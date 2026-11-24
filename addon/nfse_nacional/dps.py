"""The NFS-e national documents: the DPS (Declaração de Prestação de Serviço) and the cancellation event, written
directly in canonical XML (C14N 1.0) so the bytes signed are the bytes sent, and the XMLDSig enveloped signature.
"""
from __future__ import annotations

import base64
import hashlib
from typing import List, Optional, Tuple

NS = "http://www.sped.fazenda.gov.br/nfse"
DSIG = "http://www.w3.org/2000/09/xmldsig#"
C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
ALGS = {
    "rsa-sha256": ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmlenc#sha256",
                   "sha256"),
    "rsa-sha1": ("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2000/09/xmldsig#sha1", "sha1"),
}
VERSAO = "1.01"
# finNFSe (the RTC layout) is required by the test environment (produção restrita) and refused by production's
# schema as of 2026-11-22 (E1235: after tpEmit it expects cMotivoEmisTI, chNFSeRej or cLocEmi).
FIN_NFSE_ENVS = ("2",)


def text(s) -> str:
    s = str(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#xD;")


def attr(s) -> str:
    s = str(s)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;").replace("\t", "&#x9;")
            .replace("\n", "&#xA;").replace("\r", "&#xD;"))


def el(name: str, *content, **attrs) -> str:
    """An element in canonical form: attributes sorted, no self-closing tags, empty parts left out."""
    body = "".join(c for c in content if c)
    a = "".join(' %s="%s"' % (k, attr(v)) for k, v in sorted(attrs.items()))
    return "<%s%s>%s</%s>" % (name, a, body, name)


def leaf(name: str, value) -> str:
    if value is None or value == "":
        return ""
    return "<%s>%s</%s>" % (name, text(value), name)


def money(v: float) -> str:
    return "%.2f" % round(float(v) + 1e-9, 2)


def dps_id(c_mun: str, tp_insc: str, insc: str, serie: str, n_dps: int) -> str:
    return "DPS%s%s%s%s%s" % (c_mun.zfill(7), tp_insc, insc.zfill(14), str(serie).zfill(5), str(n_dps).zfill(15))


def build_inf_dps(d: dict) -> Tuple[str, str]:
    """(Id, infDPS) - the infDPS element carrying the default namespace, exactly as C14N renders it as a subset."""
    ident = dps_id(d["cLocEmi"], "2", d["cnpj"], d["serie"], d["nDPS"])
    reg = leaf("opSimpNac", d["opSimpNac"])
    if d["opSimpNac"] == "3":
        reg += leaf("regApTribSN", d.get("regApTribSN", "1"))
    reg += leaf("regEspTrib", d.get("regEspTrib", "0"))
    prest = el("prest", leaf("CNPJ", d["cnpj"]), leaf("IM", d.get("im")), leaf("fone", d.get("prestFone")),
               leaf("email", d.get("prestEmail")), el("regTrib", reg))
    t = d["toma"]
    if t["tipo"] == "cnpj":
        tid = leaf("CNPJ", t["doc"])
    elif t["tipo"] == "cpf":
        tid = leaf("CPF", t["doc"])
    else:
        tid = leaf("NIF", t["doc"]) if t.get("doc") else leaf("cNaoNIF", "0")
    end = ""
    if t["tipo"] == "exterior" and t.get("pais"):
        end = el("end", el("endExt", leaf("cPais", t["pais"]), leaf("cEndPost", t.get("cep") or "00000"),
                           leaf("xCidade", t.get("cidade") or "-"), leaf("xEstProvReg", t.get("estado") or "-")),
                 leaf("xLgr", t.get("logradouro") or "-"), leaf("nro", t.get("numero") or "S/N"),
                 leaf("xCpl", t.get("complemento")), leaf("xBairro", t.get("bairro") or "-"))
    elif t.get("cep") and t.get("cMun"):
        end = el("end", el("endNac", leaf("cMun", t["cMun"]), leaf("CEP", t["cep"])),
                 leaf("xLgr", t.get("logradouro") or "-"), leaf("nro", t.get("numero") or "S/N"),
                 leaf("xCpl", t.get("complemento")), leaf("xBairro", t.get("bairro") or "-"))
    toma = el("toma", tid, leaf("xNome", t["nome"]), end, leaf("email", t.get("email")))
    serv = el("serv", el("locPrest", leaf("cLocPrestacao", d["cLocPrestacao"])),
              el("cServ", leaf("cTribNac", d["cTribNac"]), leaf("cTribMun", d.get("cTribMun")),
                 leaf("xDescServ", d["descricao"]), leaf("cNBS", d.get("cNBS"))))
    trib_mun = leaf("tribISSQN", d["tribISSQN"])
    if d["tribISSQN"] == "3":
        trib_mun += leaf("cPaisResult", d.get("cPaisResult") or t.get("pais"))
    trib_mun += leaf("tpRetISSQN", d["tpRetISSQN"])
    if d.get("pAliq") not in (None, ""):
        trib_mun += leaf("pAliq", "%.2f" % float(d["pAliq"]))
    tot = leaf("pTotTribSN", "%.2f" % float(d["pTotTribSN"])) if d.get("pTotTribSN") not in (None, "") \
        else leaf("indTotTrib", "0")
    valores = el("valores", el("vServPrest", leaf("vServ", money(d["valor"]))),
                 el("trib", el("tribMun", trib_mun), el("totTrib", tot)))
    fin = leaf("finNFSe", d.get("finNFSe", "0")) if d["tpAmb"] in FIN_NFSE_ENVS else ""
    body = (leaf("tpAmb", d["tpAmb"]) + leaf("dhEmi", d["dhEmi"]) + leaf("verAplic", d["verAplic"]) +
            leaf("serie", d["serie"]) + leaf("nDPS", d["nDPS"]) + leaf("dCompet", d["dCompet"]) +
            leaf("tpEmit", "1") + fin + leaf("cLocEmi", d["cLocEmi"]) + prest + toma + serv + valores)
    return ident, '<infDPS xmlns="%s" Id="%s">%s</infDPS>' % (NS, attr(ident), body)


def signature(signed_c14n: str, ident: str, key, cert_der: bytes, alg: str = "rsa-sha256") -> str:
    """The enveloped XMLDSig Signature element over the element whose canonical form is `signed_c14n`."""
    sig_m, dig_m, hname = ALGS[alg]
    digest = base64.b64encode(hashlib.new(hname, signed_c14n.encode("utf-8")).digest()).decode()
    inner = (el("CanonicalizationMethod", Algorithm=C14N) + el("SignatureMethod", Algorithm=sig_m) +
             el("Reference", el("Transforms",
                                el("Transform", Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"),
                                el("Transform", Algorithm=C14N)),
                el("DigestMethod", Algorithm=dig_m), leaf("DigestValue", digest), URI="#" + ident))
    signed_info_c14n = '<SignedInfo xmlns="%s">%s</SignedInfo>' % (DSIG, inner)
    value = base64.b64encode(key.sign(signed_info_c14n.encode("utf-8"), hname)).decode()
    cert = base64.b64encode(cert_der).decode()
    return ('<Signature xmlns="%s"><SignedInfo>%s</SignedInfo><SignatureValue>%s</SignatureValue>'
            '<KeyInfo><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></Signature>'
            % (DSIG, inner, value, cert))


def signed_dps(d: dict, key, cert_der: bytes, alg: str) -> Tuple[str, str]:
    ident, inf = build_inf_dps(d)
    sig = signature(inf, ident, key, cert_der, alg)
    inf_in_doc = inf.replace(' xmlns="%s"' % NS, "", 1)
    xml = '<?xml version="1.0" encoding="UTF-8"?><DPS xmlns="%s" versao="%s">%s%s</DPS>' % (NS, VERSAO, inf_in_doc, sig)
    return ident, xml


def signed_cancel(chave: str, tp_amb: str, ver_aplic: str, dh: str, cnpj: str, c_motivo: str, x_motivo: str,
                  key, cert_der: bytes, alg: str, n_ped: int = 1) -> Tuple[str, str]:
    ident = "PRE%s%s%s" % (chave, "101101", str(n_ped).zfill(3))
    body = (leaf("tpAmb", tp_amb) + leaf("verAplic", ver_aplic) + leaf("dhEvento", dh) + leaf("CNPJAutor", cnpj) +
            leaf("chNFSe", chave) + leaf("nPedRegEvento", n_ped) +
            el("e101101", leaf("xDesc", "Cancelamento de NFS-e"), leaf("cMotivo", c_motivo), leaf("xMotivo", x_motivo)))
    inf = '<infPedReg xmlns="%s" Id="%s">%s</infPedReg>' % (NS, attr(ident), body)
    sig = signature(inf, ident, key, cert_der, alg)
    inf_in_doc = inf.replace(' xmlns="%s"' % NS, "", 1)
    xml = ('<?xml version="1.0" encoding="UTF-8"?><pedRegEvento xmlns="%s" versao="%s">%s%s</pedRegEvento>'
           % (NS, VERSAO, inf_in_doc, sig))
    return ident, xml
