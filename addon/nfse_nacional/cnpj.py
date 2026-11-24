"""CNPJ lookup through public APIs (BrasilAPI, then publica.cnpj.ws): the company's legal name and address, given
back as a `tomador` ready for nfse_preview."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

from .toolkit import ToolError, prop, tool


def _digits(v) -> str:
    return "".join(ch for ch in str(v or "") if ch.isdigit())


def _ctx():
    try:
        from .tools import _trust_context
        return _trust_context()
    except Exception:  # noqa: BLE001
        return ssl.create_default_context()


def _get(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "aah-nfse"})
    try:
        with urllib.request.urlopen(req, context=_ctx(), timeout=30) as r:
            return r.status, json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8") or "{}")
        except ValueError:
            body = {}
        return e.code, body
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, PermissionError) or "not permitted" in str(reason):
            raise ToolError("the internet is off for this add-on (or the CNPJ hosts are not allowed yet): allow its "
                            "network permission on its card in AiAudioHub's Add-ons", "network_off")
        return None, {"erro": str(reason)}


def _phone(ddd_tel: str) -> str:
    d = _digits(ddd_tel)
    return d or ""


def _from_brasilapi(b: dict) -> dict:
    lgr = " ".join(x for x in (b.get("descricao_tipo_de_logradouro"), b.get("logradouro")) if x).strip()
    return {"fonte": "brasilapi.com.br", "razaoSocial": b.get("razao_social"), "nomeFantasia": b.get("nome_fantasia"),
            "situacao": b.get("descricao_situacao_cadastral"), "logradouro": lgr.title() if lgr.isupper() else lgr,
            "numero": b.get("numero"), "complemento": b.get("complemento"), "bairro": b.get("bairro"),
            "cidade": b.get("municipio"), "estado": b.get("uf"), "cep": _digits(b.get("cep")),
            "cMun": _digits(b.get("codigo_municipio_ibge")), "email": b.get("email"),
            "telefone": _phone(b.get("ddd_telefone_1")), "simples": b.get("opcao_pelo_simples"),
            "atividade": b.get("cnae_fiscal_descricao")}


def _from_cnpjws(b: dict) -> dict:
    e = b.get("estabelecimento") or {}
    cid = e.get("cidade") or {}
    est = e.get("estado") or {}
    lgr = " ".join(x for x in (e.get("tipo_logradouro"), e.get("logradouro")) if x).strip()
    simples = (b.get("simples") or {}).get("simples")
    return {"fonte": "publica.cnpj.ws", "razaoSocial": b.get("razao_social"), "nomeFantasia": e.get("nome_fantasia"),
            "situacao": e.get("situacao_cadastral"), "logradouro": lgr, "numero": e.get("numero"),
            "complemento": e.get("complemento"), "bairro": e.get("bairro"), "cidade": cid.get("nome"),
            "estado": est.get("sigla"), "cep": _digits(e.get("cep")), "cMun": _digits(cid.get("ibge_id")),
            "email": e.get("email"), "telefone": _digits((e.get("ddd1") or "") + (e.get("telefone1") or "")),
            "simples": simples, "atividade": (e.get("atividade_principal") or {}).get("descricao")}


@tool("nfse_cnpj", "Looks a CNPJ up in public registries (BrasilAPI, else CNPJ.ws): legal name, trade name, status and "
      "address, and answers a `tomador` ready for nfse_preview. Sends only the CNPJ.",
      props={"cnpj": prop("string", "The CNPJ, with or without punctuation.")}, required=("cnpj",),
      timeout_ms=60000, module="nfse")
def nfse_cnpj(a: dict) -> dict:
    cnpj = _digits(a.get("cnpj"))
    if len(cnpj) != 14:
        raise ToolError("cnpj must have 14 digits", field="cnpj")
    tried = []
    st, body = _get("https://brasilapi.com.br/api/cnpj/v1/%s" % cnpj)
    info = None
    if st == 200 and body.get("razao_social"):
        info = _from_brasilapi(body)
    else:
        tried.append({"fonte": "brasilapi.com.br", "status": st, "erro": body.get("message") or body.get("erro")})
        st, body = _get("https://publica.cnpj.ws/cnpj/%s" % cnpj)
        if st == 200 and body.get("razao_social"):
            info = _from_cnpjws(body)
        else:
            tried.append({"fonte": "publica.cnpj.ws", "status": st, "erro": body.get("detalhes") or body.get("erro")})
    if not info:
        return {"found": False, "cnpj": cnpj, "tentativas": tried}
    tomador = {"tipo": "cnpj", "documento": cnpj, "nome": info["razaoSocial"], "logradouro": info["logradouro"],
               "numero": info["numero"] or "S/N", "bairro": info["bairro"], "cidade": info["cidade"],
               "estado": info["estado"], "cep": info["cep"], "cMun": info["cMun"]}
    if info.get("complemento"):
        tomador["complemento"] = info["complemento"]
    if info.get("email"):
        tomador["email"] = info["email"]
    out = {"found": True, "cnpj": cnpj, "dados": info, "tomador": tomador}
    sit = str(info.get("situacao") or "").upper()
    if sit and sit not in ("ATIVA", "2"):
        out["aviso"] = "situacao cadastral: %s" % info.get("situacao")
    if tried:
        out["tentativas"] = tried
    return out
