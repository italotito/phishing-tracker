"""
Configurações centrais, listas de referência e pesos da Calculadora de Risco.
"""

import os
from pathlib import Path


def _load_env_file() -> None:
    """Carrega variáveis do arquivo .env (usa python-dotenv se disponível ou parser nativo)."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return

    try:
        from dotenv import load_dotenv  # type: ignore
        load_dotenv(dotenv_path=env_path)
    except ImportError:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


_load_env_file()

# Credenciais e parâmetros de execução
VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
REQUEST_TIMEOUT_SECONDS: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
ENABLE_DNS_WHOIS_LOOKUP: bool = os.getenv("ENABLE_DNS_WHOIS_LOOKUP", "false").lower() == "true"

# Marcas frequentemente alvo de Typosquatting e Brand Impersonation
PROTECTED_BRANDS: tuple[str, ...] = (
    "google",
    "microsoft",
    "apple",
    "paypal",
    "amazon",
    "netflix",
    "itau",
    "bradesco",
    "nubank",
    "santander",
    "bancodobrasil",
    "caixa",
    "mercadolivre",
    "mercadopago",
    "instagram",
    "facebook",
    "whatsapp",
    "linkedin",
    "github",
    "gov",
)

# TLDs frequentemente abusados em campanhas de phishing de baixo custo
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "club", "online", "site", "icu", "vip", "work",
    "click", "link", "tk", "ml", "ga", "cf", "gq", "buzz", "rest", "zip",
})

# Encurtadores de URL que ocultam o destino real
URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
})

# Extensões de anexos de alto risco em e-mails
DANGEROUS_ATTACHMENT_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".msi", ".hta", ".iso", ".img", ".lnk", ".xlsm", ".docm",
})

# Pesos de pontuação da Calculadora de Risco (0 a 100)
RISK_WEIGHTS: dict[str, int] = {
    # Heurística de Domínio e URL
    "RAW_IP_IN_URL": 30,
    "PUNYCODE_HOMOGRAPH": 35,
    "TYPOSQUATTING_DETECTED": 35,
    "BRAND_IN_SUBDOMAIN": 25,
    "EXCESSIVE_SUBDOMAINS": 15,
    "AT_SYMBOL_IN_URL": 25,
    "SUSPICIOUS_TLD": 15,
    "URL_SHORTENER_USED": 15,
    "LONG_OBFUSCATED_URL": 10,
    "RECENTLY_REGISTERED_DOMAIN": 25,
    # Cabeçalhos de E-mail e Autenticação
    "SPF_FAIL": 30,
    "DKIM_FAIL": 25,
    "DMARC_FAIL": 30,
    "REPLY_TO_MISMATCH": 25,
    "RETURN_PATH_MISMATCH": 20,
    "DISPLAY_NAME_SPOOFING": 25,
    # Engenharia Social e Conteúdo
    "URGENCY_LANGUAGE": 15,
    "THREAT_OR_ACCOUNT_SUSPENSION": 20,
    "FINANCIAL_OR_CREDENTIAL_BAIT": 15,
    "DECEPTIVE_ANCHOR_LINK": 35,
    "EMBEDDED_HTML_FORM": 20,
    "DANGEROUS_ATTACHMENT": 35,
    # Threat Intelligence Externa (VirusTotal)
    "VT_MALICIOUS_HIGH": 50,
    "VT_MALICIOUS_LOW": 30,
    "VT_SUSPICIOUS_ONLY": 15,
}
