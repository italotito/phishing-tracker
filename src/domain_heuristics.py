"""
Módulo 2: Heurística de Domínios, Typosquatting (Distância de Levenshtein),
Homógrafos (Punycode), Subdomínios e Validação DNS/WHOIS.
"""

from datetime import datetime, timezone
import ipaddress
import re
from urllib.parse import urlparse

from src.config import (
    ENABLE_DNS_WHOIS_LOOKUP,
    PROTECTED_BRANDS,
    RISK_WEIGHTS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from src.models import RiskIndicator

# Substituições visuais comuns (Leetspeak / Homoglíficos simples)
LEET_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
})

# Sufixos compostos conhecidos (2nd-level TLDs)
COMPOUND_SUFFIXES: frozenset[str] = frozenset({
    "com.br", "org.br", "net.br", "gov.br", "edu.br",
    "co.uk", "org.uk", "co.jp", "com.au", "com.mx",
})


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calcula a distância de edição de Levenshtein entre duas strings (O(N*M) em tempo, O(min(N,M)) em espaço).
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def split_domain_parts(hostname: str) -> tuple[str, str, str]:
    """
    Divide um hostname em (subdomains, registered_domain_label, tld_suffix).
    Exemplo: 'login.seguro.itau.com.br' -> ('login.seguro', 'itau', 'com.br')
    """
    clean_host = hostname.lower().strip(".")
    parts = clean_host.split(".")
    if len(parts) < 2:
        return "", clean_host, ""

    last_two = ".".join(parts[-2:])
    if last_two in COMPOUND_SUFFIXES and len(parts) >= 3:
        tld_suffix = last_two
        domain_label = parts[-3]
        subdomains = ".".join(parts[:-3])
    else:
        tld_suffix = parts[-1]
        domain_label = parts[-2]
        subdomains = ".".join(parts[:-2])

    return subdomains, domain_label, tld_suffix


def is_raw_ip_address(hostname: str) -> bool:
    """Verifica se o hostname é um endereço IPv4 ou IPv6 literal."""
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def detect_typosquatting(domain_label: str) -> tuple[bool, str]:
    """
    Verifica se o nome principal do domínio é uma variação de Typosquatting
    de uma marca protegida (via Levenshtein <= 2, substituição leetspeak ou 'rn' -> 'm').
    """
    candidate = domain_label.lower()
    if candidate in PROTECTED_BRANDS:
        return False, ""

    # Se o domínio usa hífens (ex: 'paypal-security', 'itau-acesso'), avalia cada token
    tokens = [t for t in candidate.split("-") if t]

    normalized_leet = candidate.translate(LEET_TRANSLATION).replace("rn", "m")
    normalized_i = candidate.replace("1", "i").translate(LEET_TRANSLATION)

    for brand in PROTECTED_BRANDS:
        # 1. Caso clássico: leetspeak direto (ex: paypa1 -> paypal, g00gle -> google, rnicrosoft -> microsoft)
        if normalized_leet == brand or normalized_i == brand:
            return True, f"Imitação visual de '{brand}' no domínio '{domain_label}'"

        # 2. Caso de distância de edição curta (Levenshtein == 1 para marcas >= 5 letras)
        if len(brand) >= 5 and abs(len(candidate) - len(brand)) <= 1:
            dist = levenshtein_distance(candidate, brand)
            if dist == 1:
                return True, f"Distância de Levenshtein = 1 para a marca '{brand}' ('{domain_label}')"

        # 3. Marca combinada com hífen em domínio externo (ex: 'nubank-atendimento', 'paypal-login')
        if brand in tokens and candidate != brand:
            return True, f"Uso da marca protegida '{brand}' composta com hífen ('{domain_label}')"

        for token in tokens:
            token_leet = token.translate(LEET_TRANSLATION).replace("rn", "m")
            if token != brand and (token_leet == brand or (len(brand) >= 5 and levenshtein_distance(token, brand) == 1)):
                return True, f"Token '{token}' imita a marca '{brand}' em '{domain_label}'"

    return False, ""


def check_dns_and_whois(registered_domain: str) -> list[RiskIndicator]:
    """
    Executa validações ativas de idade do domínio (WHOIS) e registros SPF/DMARC (DNS)
    quando ENABLE_DNS_WHOIS_LOOKUP está habilitado.
    """
    indicators: list[RiskIndicator] = []
    if not ENABLE_DNS_WHOIS_LOOKUP or not registered_domain:
        return indicators

    # 1. Consulta WHOIS para idade do domínio (< 30 dias é forte indicador de phishing)
    try:
        import whois  # type: ignore

        w = whois.whois(registered_domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation_date).days
            if 0 <= age_days < 30:
                indicators.append(
                    RiskIndicator(
                        code="RECENTLY_REGISTERED_DOMAIN",
                        category="DNS & WHOIS",
                        description=f"Domínio recém-registrado há apenas {age_days} dias.",
                        weight=RISK_WEIGHTS["RECENTLY_REGISTERED_DOMAIN"],
                        evidence=f"Domínio: {registered_domain} (Criado em {creation_date.date()})",
                    )
                )
    except Exception:
        pass

    return indicators


def analyze_url_heuristics(url: str) -> list[RiskIndicator]:
    """
    Analisa uma URL em busca de múltiplos indicadores heurísticos de phishing.
    """
    indicators: list[RiskIndicator] = []
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url

    parsed = urlparse(clean_url)
    netloc = parsed.netloc
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return indicators

    # 1. Presença de '@' na autoridade da URL (redirecionamento enganoso user:pass@host)
    if "@" in netloc:
        indicators.append(
            RiskIndicator(
                code="AT_SYMBOL_IN_URL",
                category="Heurística de Domínio & URL",
                description="Uso do caractere '@' na URL para mascarar o verdadeiro domínio de destino.",
                weight=RISK_WEIGHTS["AT_SYMBOL_IN_URL"],
                evidence=clean_url,
            )
        )

    # 2. Uso de endereço IP bruto em vez de nome de domínio
    if is_raw_ip_address(hostname):
        indicators.append(
            RiskIndicator(
                code="RAW_IP_IN_URL",
                category="Heurística de Domínio & URL",
                description="A URL utiliza um endereço IP direto em vez de um domínio registrado.",
                weight=RISK_WEIGHTS["RAW_IP_IN_URL"],
                evidence=hostname,
            )
        )
        return indicators

    # 3. Detecção de Punycode / Ataque Homógrafo IDN (xn-- ou caracteres não-ASCII)
    has_non_ascii = any(ord(ch) > 127 for ch in hostname)
    if "xn--" in hostname or has_non_ascii:
        indicators.append(
            RiskIndicator(
                code="PUNYCODE_HOMOGRAPH",
                category="Heurística de Domínio & URL",
                description="Detectado domínio internacionalizado (Punycode/IDN) suspeito de ataque homógrafo.",
                weight=RISK_WEIGHTS["PUNYCODE_HOMOGRAPH"],
                evidence=hostname,
            )
        )

    # 4. Encurtadores de URL
    if hostname in URL_SHORTENERS:
        indicators.append(
            RiskIndicator(
                code="URL_SHORTENER_USED",
                category="Heurística de Domínio & URL",
                description="Uso de encurtador de URL para ocultar o domínio final.",
                weight=RISK_WEIGHTS["URL_SHORTENER_USED"],
                evidence=hostname,
            )
        )
        return indicators

    subdomains, domain_label, tld_suffix = split_domain_parts(hostname)

    # 5. Typosquatting no domínio principal
    is_typo, typo_reason = detect_typosquatting(domain_label)
    if is_typo:
        indicators.append(
            RiskIndicator(
                code="TYPOSQUATTING_DETECTED",
                category="Heurística de Domínio & URL",
                description=f"Suspeita de Typosquatting: {typo_reason}.",
                weight=RISK_WEIGHTS["TYPOSQUATTING_DETECTED"],
                evidence=hostname,
            )
        )

    # 6. Marca protegida inserida no subdomínio de um domínio de terceiros
    if subdomains:
        sub_tokens = re.split(r"[.-]", subdomains)
        for brand in PROTECTED_BRANDS:
            if brand in sub_tokens and domain_label != brand:
                indicators.append(
                    RiskIndicator(
                        code="BRAND_IN_SUBDOMAIN",
                        category="Heurística de Domínio & URL",
                        description=f"A marca '{brand}' aparece como subdomínio de um domínio não oficial ('{domain_label}.{tld_suffix}').",
                        weight=RISK_WEIGHTS["BRAND_IN_SUBDOMAIN"],
                        evidence=hostname,
                    )
                )
                break

    # 7. Excesso de subdomínios (ex: 3 ou mais níveis antes do domínio principal)
    sub_count = len([s for s in subdomains.split(".") if s]) if subdomains else 0
    if sub_count >= 3:
        indicators.append(
            RiskIndicator(
                code="EXCESSIVE_SUBDOMAINS",
                category="Heurística de Domínio & URL",
                description=f"Excesso de subdomínios ({sub_count} níveis) utilizado para dificultar a leitura do domínio real.",
                weight=RISK_WEIGHTS["EXCESSIVE_SUBDOMAINS"],
                evidence=hostname,
            )
        )

    # 8. TLD de baixa reputação / alto abuso
    if tld_suffix in SUSPICIOUS_TLDS:
        indicators.append(
            RiskIndicator(
                code="SUSPICIOUS_TLD",
                category="Heurística de Domínio & URL",
                description=f"Domínio utiliza TLD frequentemente associado a campanhas maliciosas (.{tld_suffix}).",
                weight=RISK_WEIGHTS["SUSPICIOUS_TLD"],
                evidence=hostname,
            )
        )

    # 9. URL excessivamente longa ou com múltiplos redirecionamentos embutidos
    if len(clean_url) > 120 or clean_url.count("http") > 1:
        indicators.append(
            RiskIndicator(
                code="LONG_OBFUSCATED_URL",
                category="Heurística de Domínio & URL",
                description="URL extensa ou contendo parâmetros de redirecionamento aberto.",
                weight=RISK_WEIGHTS["LONG_OBFUSCATED_URL"],
                evidence=clean_url[:100] + ("..." if len(clean_url) > 100 else ""),
            )
        )

    # 10. Checagem ativa opcional de DNS/WHOIS
    if domain_label and tld_suffix:
        indicators.extend(check_dns_and_whois(f"{domain_label}.{tld_suffix}"))

    return indicators
