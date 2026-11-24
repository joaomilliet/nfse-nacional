"""NFS-e Nacional tools: check the setup, preview a note, issue it (only a confirmed preview), look one up, download
its DANFSe PDF, cancel it, and list the notes this add-on issued.
"""
from __future__ import annotations

import base64
import datetime as _dt
import gzip
import json
import os
import ssl
import time
import urllib.error
import urllib.request
import uuid

from . import config  # noqa: F401  (declares the settings)
from . import crypto, dps
from .config import need
from .toolkit import ToolError, VALUES, bundle_manifest, data_dir, prop, tool

MODULE = "nfse"

HOSTS = {
    "producao_restrita": {"sefin": "https://sefin.producaorestrita.nfse.gov.br/API/SefinNacional",
                          "adn": "https://adn.producaorestrita.nfse.gov.br", "tpAmb": "2"},
    "producao": {"sefin": "https://sefin.nfse.gov.br/SefinNacional", "adn": "https://adn.nfse.gov.br", "tpAmb": "1"},
}
OP_SIMP = {"nao_optante": "1", "mei": "2", "me_epp": "3"}
BRT = _dt.timezone(_dt.timedelta(hours=-3))


# ---- local files ------------------------------------------------------------------------------------------------
def _dir(*parts) -> str:
    d = os.path.join(data_dir(), *parts)
    os.makedirs(d, exist_ok=True)
    return d


def _read_json(path: str, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write_json(path: str, value) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def _state_file() -> str:
    return os.path.join(_dir(), "state.json")


def _state() -> dict:
    return _read_json(_state_file(), {"next": {}, "notes": []})


# ---- settings and certificate -------------------------------------------------------------------------------------
def _env() -> dict:
    amb = VALUES.get("ambiente") or "producao_restrita"
    if amb not in HOSTS:
        raise ToolError("Ambiente must be producao_restrita or producao (AiAudioHub, Add-ons > NFS-e Nacional)",
                        "not_configured", "ambiente")
    return dict(HOSTS[amb], name=amb)


def _digits(v) -> str:
    return "".join(ch for ch in str(v or "") if ch.isdigit())


def _percent_setting(key: str):
    raw = str(VALUES.get(key) or "").strip().replace("%", "").replace(",", ".")
    if not raw:
        return None
    try:
        v = float(raw)
    except ValueError:
        raise ToolError("%s must be a number in percent, e.g. 8.6 (Add-ons > NFS-e Nacional)" % key,
                        "not_configured", key)
    if not 0 <= v <= 100:
        raise ToolError("%s must be between 0 and 100" % key, "not_configured", key)
    return v


_CERT_CACHE: dict = {}


def _cert():
    path = os.path.expanduser(str(need("certPath")).strip())
    password = str(VALUES.get("certPassword") or "")
    try:
        st = os.stat(path)
    except PermissionError:
        raise ToolError("the certificate file cannot be read from here: keep the .pfx in Documents, Desktop or "
                        "Downloads and set its path in Add-ons > NFS-e Nacional", "permission_denied", "certPath")
    except OSError:
        raise ToolError("no certificate file at the path set in Add-ons > NFS-e Nacional", "not_found", "certPath")
    key = (path, st.st_mtime, len(password))
    if _CERT_CACHE.get("key") == key:
        return _CERT_CACHE["value"]
    try:
        with open(path, "rb") as f:
            data = f.read()
    except PermissionError:
        raise ToolError("the certificate file cannot be read from here: keep the .pfx in Documents, Desktop or "
                        "Downloads and set its path in Add-ons > NFS-e Nacional", "permission_denied", "certPath")
    try:
        value = crypto.load_pfx(data, password)
    except crypto.CryptoError as e:
        msg = str(e)
        if "padding" in msg:
            msg = "the certificate password does not open the file (Add-ons > NFS-e Nacional, Senha do certificado)"
        raise ToolError("certificate: " + msg, "certificate_error", "certPath")
    _CERT_CACHE.update(key=key, value=value)
    return value


def _ca_items(path: str):
    """Certificates from a .pem/.crt/.cer file, a folder of them, or a .zip of them (DER or PEM)."""
    import zipfile
    out = []
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for n in files:
                if n.lower().endswith((".crt", ".cer", ".pem", ".der", ".zip")):
                    out += _ca_items(os.path.join(root, n))
        return out
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.lower().endswith((".crt", ".cer", ".pem", ".der")):
                    out.append(z.read(n))
        return out
    with open(path, "rb") as f:
        out.append(f.read())
    return out


AIA_HOSTS = ("secure.globalsign.com",)


def _fetch_issuer(host: str) -> bool:
    """Downloads the intermediate certificate a server leaves out of its handshake (its Authority Information Access
    address) into the add-on's ca folder. The file is only used as a link of a chain that must still end in a root this
    Mac trusts, so it adds no trust of its own."""
    import socket
    raw = ssl.create_default_context()
    raw.check_hostname = False
    raw.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=20) as s:
        with raw.wrap_socket(s, server_hostname=host) as t:
            leaf = crypto.Certificate(t.getpeercert(binary_form=True))
    current, fetched = leaf, False
    for _ in range(4):
        url = current.aia
        if not url.startswith("http://") or url.split("//", 1)[1].split("/", 1)[0] not in AIA_HOSTS:
            break
        name = "".join(ch for ch in url.rsplit("/", 1)[-1] if ch.isalnum() or ch in ".-_")
        path = os.path.join(_dir("ca"), name)
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = f.read()
        else:
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read(200000)
            fetched = True
        der_b = data if not data.startswith(b"-----") else base64.b64decode(
            b"".join(l for l in data.splitlines() if not l.startswith(b"-----")))
        nxt = crypto.Certificate(der_b)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(data)
        if nxt.subject == nxt.issuer:
            break
        current = nxt
    return fetched


def _trust_context():
    ctx = ssl.create_default_context()
    sources = ["/etc/ssl/cert.pem", "/private/etc/ssl/cert.pem", _dir("ca")]
    extra = str(VALUES.get("caBundle") or "").strip()
    if extra:
        sources.append(os.path.expanduser(extra))
    for src in sources:
        try:
            items = _ca_items(src) if os.path.exists(src) else []
        except (OSError, ValueError):
            continue
        for data in items:
            try:
                if b"-----BEGIN CERTIFICATE-----" in data:
                    ctx.load_verify_locations(cadata=data.decode("ascii", "ignore"))
                else:
                    ctx.load_verify_locations(cadata=data)
            except (ssl.SSLError, ValueError):
                continue
    return ctx


def _ssl_context():
    keyobj, leaf, chain = _cert()
    ctx = _trust_context()
    tmp = os.path.join(_dir("tmp"), "c%s.pem" % uuid.uuid4().hex)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(keyobj.pem() + leaf.pem() + "".join(c.pem() for c in chain))
        ctx.load_cert_chain(tmp)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    return ctx


def _http(method: str, url: str, body=None, accept: str = "application/json", _retry: bool = True):
    try:
        return _http_once(method, url, body, accept)
    except ToolError as e:
        if _retry and e.code == "tls_error" and "CERTIFICATE_VERIFY_FAILED" in str(e):
            host = url.split("//", 1)[1].split("/", 1)[0]
            try:
                fetched = _fetch_issuer(host)
            except Exception:  # noqa: BLE001
                fetched = False
            if fetched:
                return _http_once(method, url, body, accept)
        raise


def _http_once(method: str, url: str, body=None, accept: str = "application/json"):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "Accept": accept})
    try:
        with urllib.request.urlopen(req, context=_ssl_context(), timeout=60) as r:
            return r.status, r.read(), r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers.get("Content-Type", "") if e.headers else ""
    except ssl.SSLError as e:
        raise ToolError("secure connection to the NFS-e API failed (%s). If it says the server certificate could not "
                        "be verified, this Mac's Python lacks the root certificates" % e, "tls_error")
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(reason):
            raise ToolError("the NFS-e server's certificate could not be verified (%s): set the server's root "
                            "certificate file in Add-ons > NFS-e Nacional (Certificados raiz do servidor)" % reason,
                            "tls_error", "caBundle")
        if isinstance(reason, PermissionError) or "not permitted" in str(reason):
            raise ToolError("the internet is off for this add-on: switch on its internet permission on its card in "
                            "AiAudioHub's Add-ons", "network_off")
        raise ToolError("the NFS-e API could not be reached: %s" % reason, "network_error")


def _json(raw: bytes) -> dict:
    try:
        v = json.loads(raw.decode("utf-8") or "{}")
        return v if isinstance(v, dict) else {"resposta": v}
    except ValueError:
        return {"texto": raw.decode("utf-8", "replace")[:2000]}


def _errors(resp: dict) -> list:
    out = []
    for k in ("erros", "erro", "Erros", "errors"):
        v = resp.get(k)
        if isinstance(v, list):
            out += v
        elif isinstance(v, dict):
            out.append(v)
    return out


def _gz64(xml: str) -> str:
    return base64.b64encode(gzip.compress(xml.encode("utf-8"))).decode()


def _ungz64(s: str) -> str:
    raw = base64.b64decode(s)
    try:
        raw = gzip.decompress(raw)
    except OSError:
        pass
    return raw.decode("utf-8", "replace")


def _ver() -> str:
    return "aah-nfse-%s" % bundle_manifest().get("version", "0")


def _now() -> str:
    return _dt.datetime.now(BRT).replace(microsecond=0).isoformat()


# ---- tools ------------------------------------------------------------------------------------------------------
@tool("nfse_setup_check", "Checks the add-on's setup without sending anything: the settings filled in, the A1 "
      "certificate opened with its password (holder, CNPJ, validity) and the cipher self-test.", module=MODULE)
def nfse_setup_check(a: dict) -> dict:
    env = _env()
    st = crypto.selftest()
    out = {"ambiente": env["name"], "api": env["sefin"], "selftest": st, "settings": {}}
    for k in ("cnpj", "inscricaoMunicipal", "codigoMunicipio", "regimeSimples", "percentualTributosSN", "serie",
              "codigoServico", "codigoMunicipal"):
        out["settings"][k] = VALUES.get(k) or None
    out["settings"]["certPath"] = VALUES.get("certPath") or None
    out["settings"]["certPassword"] = "set" if VALUES.get("certPassword") else "not set"
    try:
        _, leaf, chain = _cert()
        now = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        out["certificate"] = {"holder": leaf.subject.get("CN"), "issuer": leaf.issuer.get("CN"),
                              "cnpj": leaf.cnpj or None, "validFrom": leaf.not_before, "validTo": leaf.not_after,
                              "valid": leaf.not_before <= now <= leaf.not_after, "chain": len(chain)}
        cnpj = _digits(VALUES.get("cnpj"))
        if leaf.cnpj and cnpj and leaf.cnpj != cnpj:
            out["warning"] = "the certificate's CNPJ differs from the CNPJ set in the add-on"
    except ToolError as e:
        out["certificate"] = {"error": str(e)}
    try:
        out["trustedRoots"] = _trust_context().cert_store_stats().get("x509_ca", 0)
    except Exception as e:  # noqa: BLE001
        out["trustedRoots"] = "error: %s" % e
    out["ready"] = bool(all(st.values()) and isinstance(out.get("certificate"), dict)
                        and out["certificate"].get("valid") and _digits(VALUES.get("cnpj")))
    return out


_TOMA = prop("object", "Who is invoiced: {tipo: cnpj | cpf | exterior, documento (CNPJ/CPF digits; NIF abroad, "
                       "optional), nome, email?, pais (ISO 2 letters, abroad), cidade?, estado?, cep?, logradouro?, "
                       "numero?, bairro?, cMun (IBGE, with cep, for a Brazilian address)?}")


@tool("nfse_preview", "Builds an NFS-e (a DPS) from the details given and answers what would be issued: provider, "
      "taker, service, value, taxation, environment and the DPS number. Nothing is sent; nfse_issue sends it.",
      props={"tomador": _TOMA,
             "valor": prop("number", "The service value in reais (BRL).", minimum=0.01),
             "descricao": prop("string", "The service description printed on the note.", minLength=3, maxLength=2000),
             "codigoServico": prop("string", "National service code (cTribNac, 6 digits). Default: the setting."),
             "codigoMunicipal": prop("string", "Municipal complement code (cTribMun, 3 digits). Default: the setting."),
             "nbs": prop("string", "NBS code (9 digits), when required."),
             "competencia": prop("string", "Competence date YYYY-MM-DD. Default: today."),
             "issRetido": prop("boolean", "The taker withholds the ISS. Default false."),
             "aliquota": prop("number", "ISS rate in percent, when the regime requires it.", minimum=0, maximum=5),
             "percentualTributosSN": prop("number", "Approximate total tax percent under the Simples Nacional "
                                          "(shown on the note). Default: the setting.", minimum=0, maximum=100),
             "exportacao": prop("boolean", "Export of services (taker abroad). Default: true when tomador.tipo is "
                                "exterior.")},
      required=("tomador", "valor", "descricao"), module=MODULE)
def nfse_preview(a: dict) -> dict:
    env = _env()
    cnpj = _digits(need("cnpj"))
    if len(cnpj) != 14:
        raise ToolError("CNPJ do prestador must have 14 digits (Add-ons > NFS-e Nacional)", "not_configured", "cnpj")
    c_mun = _digits(need("codigoMunicipio"))
    if len(c_mun) != 7:
        raise ToolError("Município must be the 7-digit IBGE code (Add-ons > NFS-e Nacional)", "not_configured",
                        "codigoMunicipio")
    t = a["tomador"]
    if not isinstance(t, dict):
        raise ToolError("`tomador` must be an object {tipo, documento, nome, ...}", field="tomador")
    tipo = str(t.get("tipo", "")).lower()
    if tipo not in ("cnpj", "cpf", "exterior"):
        raise ToolError("tomador.tipo must be cnpj, cpf or exterior", field="tomador", candidates=["cnpj", "cpf",
                                                                                                    "exterior"])
    doc = _digits(t.get("documento")) if tipo != "exterior" else str(t.get("documento") or "").strip()
    if tipo == "cnpj" and len(doc) != 14 or tipo == "cpf" and len(doc) != 11:
        raise ToolError("tomador.documento must have %d digits for a %s" % (14 if tipo == "cnpj" else 11,
                                                                              tipo.upper()), field="tomador")
    nome = str(t.get("nome") or "").strip()
    if not nome:
        raise ToolError("tomador.nome is required", field="tomador")
    pais = str(t.get("pais") or "").upper().strip()
    if tipo == "exterior" and len(pais) != 2:
        raise ToolError("tomador.pais must be the 2-letter ISO country code for a taker abroad (US, PT, ...)",
                        field="tomador")
    export = a.get("exportacao", tipo == "exterior")
    c_trib = _digits(a.get("codigoServico") or VALUES.get("codigoServico"))
    if len(c_trib) != 6:
        raise ToolError("codigoServico (cTribNac) must have 6 digits", field="codigoServico")
    c_trib_mun = _digits(a.get("codigoMunicipal") or VALUES.get("codigoMunicipal")) or None
    if c_trib_mun and len(c_trib_mun) != 3:
        raise ToolError("codigoMunicipal (cTribMun) must have 3 digits", field="codigoMunicipal")
    compet = a.get("competencia") or _dt.datetime.now(BRT).date().isoformat()
    try:
        _dt.date.fromisoformat(compet)
    except ValueError:
        raise ToolError("competencia must be YYYY-MM-DD", field="competencia")
    serie = _digits(VALUES.get("serie") or "1") or "1"
    st = _state()
    n_dps = int(st["next"].get("%s:%s" % (env["name"], serie), 1))
    op = OP_SIMP.get(VALUES.get("regimeSimples") or "me_epp", "3")
    p_sn = a.get("percentualTributosSN")
    if p_sn is None:
        p_sn = _percent_setting("percentualTributosSN")
    if op == "1":
        p_sn = None
    elif op == "3" and p_sn is None:
        raise ToolError("for ME/EPP the note needs the approximate Simples tax percent: set Percentual aproximado de "
                        "tributos in Add-ons > NFS-e Nacional, or pass percentualTributosSN", "not_configured",
                        "percentualTributosSN")
    d = {"tpAmb": env["tpAmb"], "verAplic": _ver(), "serie": serie, "nDPS": n_dps, "dCompet": compet,
         "cLocEmi": c_mun, "cnpj": cnpj, "im": _digits(VALUES.get("inscricaoMunicipal")) or None, "opSimpNac": op,
         "toma": {"tipo": tipo, "doc": doc, "nome": nome, "email": t.get("email"), "pais": pais,
                  "cidade": t.get("cidade"), "estado": t.get("estado"), "cep": _digits(t.get("cep")) or t.get("cep"),
                  "logradouro": t.get("logradouro"), "numero": t.get("numero"), "bairro": t.get("bairro"),
                  "complemento": t.get("complemento"), "cMun": _digits(t.get("cMun"))},
         "cLocPrestacao": c_mun, "cTribNac": c_trib, "cTribMun": c_trib_mun,
         "cNBS": _digits(a.get("nbs")) or None, "descricao": a["descricao"].strip(), "valor": float(a["valor"]),
         "tribISSQN": "3" if export else "1", "cPaisResult": pais if export else None,
         "tpRetISSQN": "2" if a.get("issRetido") else "1", "pAliq": a.get("aliquota"),
         "pTotTribSN": p_sn}
    pid = uuid.uuid4().hex[:12]
    _write_json(os.path.join(_dir("previews"), pid + ".json"), {"created": time.time(), "dps": d})
    return {"preview": pid, "ambiente": env["name"],
            "aviso": "ambiente de testes, sem valor fiscal" if env["tpAmb"] == "2" else "PRODUCAO: nota com valor fiscal",
            "prestador": {"cnpj": cnpj, "im": d["im"], "municipio": c_mun, "simplesNacional": VALUES.get("regimeSimples")},
            "tomador": {"tipo": tipo, "documento": doc or None, "nome": nome, "pais": pais or "BR",
                         "email": t.get("email")},
            "servico": {"cTribNac": c_trib, "cTribMun": c_trib_mun, "descricao": d["descricao"],
                        "competencia": compet},
            "valor": dps.money(d["valor"]),
            "tributacao": {"issqn": "exportacao" if export else "tributavel",
                           "issRetido": bool(a.get("issRetido")), "aliquota": a.get("aliquota"),
                           "percentualTributosSN": p_sn},
            "dps": {"serie": serie, "numero": n_dps}, "next": "nfse_issue {preview, confirm: true} sends it"}


@tool("nfse_issue", "Signs and sends a previewed NFS-e to the Emissor Nacional and answers the access key (chave) "
      "or the API's errors. Only a preview from nfse_preview, and only with confirm true.",
      props={"preview": prop("string", "The preview id nfse_preview answered."),
             "confirm": prop("boolean", "Must be true: the preview was read and approved.")},
      required=("preview", "confirm"), writes=True, timeout_ms=120000, module=MODULE)
def nfse_issue(a: dict) -> dict:
    if a["confirm"] is not True:
        raise ToolError("confirm must be true once the preview was approved", "not_confirmed", "confirm")
    path = os.path.join(_dir("previews"), "%s.json" % "".join(ch for ch in a["preview"] if ch.isalnum()))
    p = _read_json(path, None)
    if not p:
        raise ToolError("no preview %s: make one with nfse_preview" % a["preview"], "not_found", "preview")
    if time.time() - p.get("created", 0) > 6 * 3600:
        raise ToolError("the preview is older than 6 hours: make a new one with nfse_preview", "expired", "preview")
    env = _env()
    d = p["dps"]
    if d["tpAmb"] != env["tpAmb"]:
        raise ToolError("the environment changed since the preview: make a new one", "expired", "preview")
    st = _state()
    counter = "%s:%s" % (env["name"], d["serie"])
    d["nDPS"] = int(st["next"].get(counter, d["nDPS"]))
    d["dhEmi"] = _now()
    key, leaf, _ = _cert()
    alg = VALUES.get("assinatura") or "rsa-sha256"
    ident, xml = dps.signed_dps(d, key, leaf.der, alg)
    xml_path = os.path.join(_dir("dps"), ident + ".xml")
    with open(xml_path, "w", encoding="utf-8") as f:
        f.write(xml)
    status, raw, _ = _http("POST", env["sefin"] + "/nfse", {"dpsXmlGZipB64": _gz64(xml)})
    resp = _json(raw)
    chave = resp.get("chaveAcesso")
    if status in (200, 201) and chave:
        st["next"][counter] = d["nDPS"] + 1
        nfse_xml = _ungz64(resp["nfseXmlGZipB64"]) if resp.get("nfseXmlGZipB64") else ""
        nfse_path = ""
        if nfse_xml:
            nfse_path = os.path.join(_dir("notas"), chave + ".xml")
            with open(nfse_path, "w", encoding="utf-8") as f:
                f.write(nfse_xml)
        st["notes"].append({"chave": chave, "dps": ident, "ambiente": env["name"], "emitida": d["dhEmi"],
                            "tomador": d["toma"]["nome"], "valor": dps.money(d["valor"]), "status": "emitida"})
        _write_json(_state_file(), st)
        try:
            os.remove(path)
        except OSError:
            pass
        return {"issued": True, "ambiente": env["name"], "chave": chave, "dps": ident,
                "dataHoraProcessamento": resp.get("dataHoraProcessamento"), "alertas": resp.get("alertas"),
                "xml": nfse_path or None, "next": "nfse_pdf {chave} downloads the DANFSe"}
    errs = _errors(resp)
    if any("E0014" in json.dumps(e) or "duplic" in json.dumps(e, ensure_ascii=False).lower() for e in errs):
        st["next"][counter] = d["nDPS"] + 1
        _write_json(_state_file(), st)
    return {"issued": False, "ambiente": env["name"], "httpStatus": status, "dps": ident, "erros": errs or resp,
            "dpsXml": xml_path}


def _chave(a: dict) -> str:
    c = _digits(a.get("chave"))
    if len(c) != 50:
        raise ToolError("chave must be the 50-digit access key of the NFS-e", field="chave")
    return c


@tool("nfse_get", "Looks up an NFS-e by its 50-digit access key at the Emissor Nacional and keeps its XML.",
      props={"chave": prop("string", "The 50-digit access key.")}, required=("chave",), timeout_ms=90000,
      module=MODULE)
def nfse_get(a: dict) -> dict:
    env = _env()
    chave = _chave(a)
    status, raw, _ = _http("GET", "%s/nfse/%s" % (env["sefin"], chave))
    resp = _json(raw)
    if status == 200 and resp.get("nfseXmlGZipB64"):
        xml = _ungz64(resp["nfseXmlGZipB64"])
        path = os.path.join(_dir("notas"), chave + ".xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(xml)
        return {"found": True, "chave": chave, "xml": path, "xmlText": xml[:4000]}
    return {"found": False, "httpStatus": status, "erros": _errors(resp) or resp}


@tool("nfse_pdf", "Downloads the DANFSe (the NFS-e's PDF) by its access key into the add-on's folder and answers the "
      "file's path.", props={"chave": prop("string", "The 50-digit access key.")}, required=("chave",),
      timeout_ms=90000, module=MODULE)
def nfse_pdf(a: dict) -> dict:
    env = _env()
    chave = _chave(a)
    status, raw, ctype = _http("GET", "%s/danfse/%s" % (env["adn"], chave), accept="application/pdf")
    if status == 200 and raw[:4] == b"%PDF":
        path = os.path.join(_dir("notas"), chave + ".pdf")
        with open(path, "wb") as f:
            f.write(raw)
        return {"pdf": path, "bytes": len(raw)}
    return {"pdf": None, "httpStatus": status, "erros": _errors(_json(raw)) or _json(raw)}


@tool("nfse_cancel", "Cancels an issued NFS-e (event 101101) with a reason, signed with the certificate. Only with "
      "confirm true.",
      props={"chave": prop("string", "The 50-digit access key."),
             "motivo": prop("string", "Why it is cancelled (15 to 255 characters).", minLength=15, maxLength=255),
             "codigoMotivo": prop("string", "1 = erro na emissão, 2 = serviço não prestado, 9 = outros. Default 1.",
                                  enum=["1", "2", "9"]),
             "confirm": prop("boolean", "Must be true: the cancellation was approved.")},
      required=("chave", "motivo", "confirm"), writes=True, timeout_ms=120000, module=MODULE)
def nfse_cancel(a: dict) -> dict:
    if a["confirm"] is not True:
        raise ToolError("confirm must be true once the cancellation was approved", "not_confirmed", "confirm")
    env = _env()
    chave = _chave(a)
    motivo = a["motivo"].strip()
    if len(motivo) < 15:
        raise ToolError("motivo must have at least 15 characters", field="motivo")
    key, leaf, _ = _cert()
    cnpj = _digits(need("cnpj"))
    ident, xml = dps.signed_cancel(chave, env["tpAmb"], _ver(), _now(), cnpj, a.get("codigoMotivo", "1"), motivo,
                                   key, leaf.der, VALUES.get("assinatura") or "rsa-sha256")
    status, raw, _ = _http("POST", "%s/nfse/%s/eventos" % (env["sefin"], chave),
                           {"pedidoRegistroEventoXmlGZipB64": _gz64(xml)})
    resp = _json(raw)
    ok = status in (200, 201) and not _errors(resp)
    if ok:
        st = _state()
        for n in st["notes"]:
            if n.get("chave") == chave:
                n["status"] = "cancelada"
        _write_json(_state_file(), st)
        ev = resp.get("eventoXmlGZipB64")
        if ev:
            with open(os.path.join(_dir("notas"), chave + "-cancelamento.xml"), "w", encoding="utf-8") as f:
                f.write(_ungz64(ev))
    return {"cancelled": ok, "chave": chave, "httpStatus": status, "resposta": resp if not ok else None,
            "evento": ident}


@tool("nfse_tls_diagnose", "Reads the certificate chain the NFS-e API server presents (without trusting it and without "
      "sending any document): each certificate's subject, issuer and issuer download address, and whether this Mac's "
      "trust store verifies it.", props={"servidor": prop("string", "sefin or adn. Default sefin.",
                                                            enum=["sefin", "adn"])}, timeout_ms=60000, module=MODULE)
def nfse_tls_diagnose(a: dict) -> dict:
    import socket
    env = _env()
    url = env[a.get("servidor", "sefin")]
    host = url.split("//", 1)[1].split("/", 1)[0]
    out = {"host": host}
    raw = ssl.create_default_context()
    raw.check_hostname = False
    raw.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=20) as s:
        with raw.wrap_socket(s, server_hostname=host) as t:
            leaf = t.getpeercert(binary_form=True)
            chain = []
            try:
                chain = [c.public_bytes() if hasattr(c, "public_bytes") else c for c in t.get_verified_chain()]
            except Exception:  # noqa: BLE001
                pass
            try:
                unv = t.get_unverified_chain()
                chain = [c.public_bytes(ssl._ssl.ENCODING_DER) if hasattr(c, "public_bytes") else c for c in unv]
            except Exception:  # noqa: BLE001
                pass
    certs = chain or [leaf]
    out["sent"] = []
    for der_b in certs:
        try:
            c = crypto.Certificate(der_b)
            out["sent"].append({"subject": c.subject.get("CN"), "issuer": c.issuer.get("CN"),
                                "issuerO": c.issuer.get("O"), "validTo": c.not_after,
                                "issuerUrl": c.aia or None})
        except Exception as e:  # noqa: BLE001
            out["sent"].append({"error": str(e)})
    try:
        with socket.create_connection((host, 443), timeout=20) as s:
            with _trust_context().wrap_socket(s, server_hostname=host):
                out["verified"] = True
    except ssl.SSLError as e:
        out["verified"] = False
        out["error"] = str(e)
    return out


@tool("nfse_list", "The NFS-e this add-on issued, newest first, with their keys, takers, values and status.",
      module=MODULE)
def nfse_list(a: dict) -> dict:
    notes = list(reversed(_state().get("notes", [])))
    return {"notes": notes, "count": len(notes), "folder": _dir("notas")}
