"""NFS-e Nacional: its settings, what the user fills in, in AiAudioHub (Add-ons > NFS-e Nacional).

A `secret` (an API key, a token) is a password field only the user fills in. The hub never shows it to an
assistant. Read it here with need("key"), never from a file or an environment variable, and never put it
in an answer, a log line or an error.
"""
from __future__ import annotations

from .toolkit import SETTINGS, ToolError, VALUES, setting

TITLE = "NFS-e Nacional"

setting("ambiente", "select", "Ambiente", "producao_restrita", "Produção restrita é o ambiente de testes da Receita (sem valor fiscal).", options=["producao_restrita", "producao"])
setting("certPath", "text", "Certificado A1 (.pfx) - caminho do arquivo", "", "O caminho completo do arquivo .pfx/.p12 do certificado ICP-Brasil da empresa neste Mac.")
setting("certPassword", "secret", "Senha do certificado", "", "A senha do arquivo .pfx.")
setting("cnpj", "text", "CNPJ do prestador", "", "Só os números.")
setting("inscricaoMunicipal", "text", "Inscrição municipal", "", "Opcional; só os números. Deixe vazio se a Receita recusar com E0120.")
setting("codigoMunicipio", "text", "Município (código IBGE)", "3550308", "7 dígitos. São Paulo = 3550308.")
setting("regimeSimples", "select", "Simples Nacional", "me_epp", "", options=["nao_optante", "mei", "me_epp"])
setting("percentualTributosSN", "text", "Percentual aproximado de tributos (Simples)", "", "A alíquota efetiva do Simples, em %, impressa na nota (ex.: 8.6). Obrigatória para ME/EPP.")
setting("serie", "text", "Série da DPS", "1", "")
setting("codigoServico", "text", "Código de tributação nacional padrão (cTribNac)", "130201", "6 dígitos da lista nacional de serviços. 130201 = fonografia, gravação, mixagem.")
setting("codigoMunicipal", "text", "Código complementar municipal padrão (cTribMun)", "001", "3 dígitos que o município pede junto do código nacional (São Paulo: 001).")
setting("caBundle", "text", "Certificados raiz do servidor (opcional)", "", "Caminho de um arquivo .pem com as raízes que assinam o certificado dos servidores nfse.gov.br, se este Mac não as tiver.")
setting("assinatura", "select", "Algoritmo da assinatura", "rsa-sha256", "O padrão nacional usa RSA-SHA256.", options=["rsa-sha256", "rsa-sha1"])


def need(key: str):
    """The value of a setting, or a refusal saying where the user fills it in."""
    value = VALUES.get(key)
    if value is None or value == "":
        label = next((s["label"] for s in SETTINGS if s["key"] == key), key)
        raise ToolError("%s is not set: the user fills it in AiAudioHub, Add-ons > %s" % (label, TITLE),
                        "not_configured", key)
    return value
