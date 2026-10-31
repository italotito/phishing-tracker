"""
Módulo 3: Análise de Linguagem, Gatilhos de Engenharia Social e Padrões HTML Maliciosos.
"""

import re
from urllib.parse import urlparse

from src.config import RISK_WEIGHTS
from src.models import AnchorLink, RiskIndicator

# Padrões Regex de Senso de Urgência (Português e Inglês)
URGENCY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(urgente|imediatamente|a[cç][aã]o imediata|[uú]ltimo aviso|prazo final)\b", re.IGNORECASE),
    re.compile(r"\b(em at[eé] 24\s*h(oras)?|expira hoje|aten[cç][aã]o imediata)\b", re.IGNORECASE),
    re.compile(r"\b(urgent action required|immediate action|act now|expires in 24 hours)\b", re.IGNORECASE),
)

# Padrões Regex de Ameaça de Bloqueio / Suspensão de Conta
THREAT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(conta (ser[aá] )?(suspensa|bloqueada|cancelada)|bloqueio preventivo|acesso (suspenso|bloqueado|restrito))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(evitar o bloqueio|atividade incomum|tentativa de acesso n[aã]o autorizada|regularize seu acesso)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(account (has been )?(suspended|locked|restricted)|unauthorized login attempt)\b",
        re.IGNORECASE,
    ),
)

# Padrões Regex de Isca Financeira / Coleta de Credenciais
CREDENTIAL_BAIT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(atualize (seu|o) (token|cadastro|dados)|confirme sua (senha|identidade|chave de seguran[cç]a))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(recadastramento obrigat[oó]rio|fatura vencida|comprovante pix|validar dispositivo)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(verify your (account|identity|password)|update your billing information)\b",
        re.IGNORECASE,
    ),
)

# Detecção de formulários HTML embutidos no corpo do e-mail
HTML_FORM_REGEX = re.compile(r"<form\b[^>]*>", re.IGNORECASE)

# Verifica se o texto visível de um link parece uma URL ou domínio explícito
VISIBLE_URL_LIKE_REGEX = re.compile(
    r"^(?:https?://)?(?P<host>[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)(?:/.*)?$",
    re.IGNORECASE,
)


def analyze_text_language(subject: str, body_text: str) -> list[RiskIndicator]:
    """
    Vasculha o assunto e o corpo da mensagem em busca de linguagem urgente,
    ameaças de bloqueio e iscas de engenharia social.
    """
    indicators: list[RiskIndicator] = []
    combined_text = f"{subject}\n{body_text}".strip()
    if not combined_text:
        return indicators

    # 1. Senso de Urgência
    urgency_matches: list[str] = []
    for pattern in URGENCY_PATTERNS:
        for match in pattern.finditer(combined_text):
            term = match.group(0)
            if term.lower() not in [m.lower() for m in urgency_matches]:
                urgency_matches.append(term)

    if urgency_matches:
        indicators.append(
            RiskIndicator(
                code="URGENCY_LANGUAGE",
                category="Engenharia Social & Linguagem",
                description="Detectada linguagem de senso de urgência para induzir decisão precipitada.",
                weight=RISK_WEIGHTS["URGENCY_LANGUAGE"],
                evidence=", ".join(f"'{m}'" for m in urgency_matches[:4]),
            )
        )

    # 2. Ameaça de Bloqueio / Suspensão
    threat_matches: list[str] = []
    for pattern in THREAT_PATTERNS:
        for match in pattern.finditer(combined_text):
            term = match.group(0)
            if term.lower() not in [m.lower() for m in threat_matches]:
                threat_matches.append(term)

    if threat_matches:
        indicators.append(
            RiskIndicator(
                code="THREAT_OR_ACCOUNT_SUSPENSION",
                category="Engenharia Social & Linguagem",
                description="Gatilho de medo/ameaça (bloqueio ou suspensão de conta) identificado.",
                weight=RISK_WEIGHTS["THREAT_OR_ACCOUNT_SUSPENSION"],
                evidence=", ".join(f"'{m}'" for m in threat_matches[:4]),
            )
        )

    # 3. Isca de Credenciais / Token / Financeiro
    bait_matches: list[str] = []
    for pattern in CREDENTIAL_BAIT_PATTERNS:
        for match in pattern.finditer(combined_text):
            term = match.group(0)
            if term.lower() not in [m.lower() for m in bait_matches]:
                bait_matches.append(term)

    if bait_matches:
        indicators.append(
            RiskIndicator(
                code="FINANCIAL_OR_CREDENTIAL_BAIT",
                category="Engenharia Social & Linguagem",
                description="Solicitação direta de atualização cadastral, token, senha ou cobrança.",
                weight=RISK_WEIGHTS["FINANCIAL_OR_CREDENTIAL_BAIT"],
                evidence=", ".join(f"'{m}'" for m in bait_matches[:4]),
            )
        )

    return indicators


def analyze_html_patterns(html_body: str, anchor_links: list[AnchorLink]) -> list[RiskIndicator]:
    """
    Detecta links camuflados (onde o texto visível exibe um domínio legítimo mas o href
    aponta para outro domínio) e formulários HTML dentro do e-mail.
    """
    indicators: list[RiskIndicator] = []

    # 1. Links Âncora Camuflados (<a href="http://atacante.xyz">https://banco.com.br</a>)
    for anchor in anchor_links:
        visible = anchor.visible_text.strip()
        href = anchor.href.strip()
        if not visible or not href.startswith(("http://", "https://")):
            continue

        visible_match = VISIBLE_URL_LIKE_REGEX.match(visible)
        if visible_match:
            visible_host = visible_match.group("host").lower().removeprefix("www.")
            actual_host = (urlparse(href).hostname or "").lower().removeprefix("www.")
            if visible_host and actual_host and visible_host != actual_host:
                indicators.append(
                    RiskIndicator(
                        code="DECEPTIVE_ANCHOR_LINK",
                        category="Engenharia Social & Linguagem",
                        description="Link HTML camuflado: o texto visível mostra um domínio diferente do destino real (href).",
                        weight=RISK_WEIGHTS["DECEPTIVE_ANCHOR_LINK"],
                        evidence=f"Texto exibido: '{visible}' -> Destino real: '{href}'",
                    )
                )

    # 2. Formulários HTML embutidos no corpo do e-mail
    if html_body and HTML_FORM_REGEX.search(html_body):
        indicators.append(
            RiskIndicator(
                code="EMBEDDED_HTML_FORM",
                category="Engenharia Social & Linguagem",
                description="E-mail contém tag <form> HTML embutida para coleta direta de dados.",
                weight=RISK_WEIGHTS["EMBEDDED_HTML_FORM"],
                evidence="<form> detectado no corpo HTML",
            )
        )

    return indicators
