"""
Módulo 1: Ingestão e Parsing de E-mails (.eml) e Extração de Artefatos via Regex.
"""

import email
import hashlib
import re
from email import policy
from email.utils import parseaddr
from pathlib import Path

from src.config import DANGEROUS_ATTACHMENT_EXTENSIONS, RISK_WEIGHTS
from src.models import AnchorLink, AttachmentInfo, ParsedEmail, RiskIndicator

# Expressão regular para extração de URLs (HTTP/HTTPS) no corpo de mensagens
URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9$-_@.&+!*\\(\\),]|%[0-9a-fA-F]{2})+[^\s\"'<>)\]]*",
    re.IGNORECASE,
)

# Expressão regular para extrair tags HTML <a href="...">texto</a>
ANCHOR_TAG_REGEX = re.compile(
    r"<a\s+[^>]*?href=[\"'](?P<href>[^\"']+)[\"'][^>]*>(?P<text>.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)

# Remoção de tags HTML internas ao texto âncora
HTML_TAG_STRIP_REGEX = re.compile(r"<[^>]+>")


def extract_urls_from_text(text: str) -> list[str]:
    """Extrai URLs únicas (http/https) de um bloco de texto ou HTML usando Regex."""
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw_url in matches:
        url = raw_url.rstrip(".,;:!?)>\"'")
        if url not in seen:
            seen.add(url)
            cleaned.append(url)
    return cleaned


def extract_anchor_links(html_content: str) -> list[AnchorLink]:
    """Extrai pares (href, texto_visível) de tags HTML <a>."""
    if not html_content:
        return []
    anchors: list[AnchorLink] = []
    for match in ANCHOR_TAG_REGEX.finditer(html_content):
        href = match.group("href").strip()
        raw_text = match.group("text")
        clean_text = HTML_TAG_STRIP_REGEX.sub("", raw_text).strip()
        anchors.append(AnchorLink(href=href, visible_text=clean_text))
    return anchors


def parse_eml_content(raw_eml: str | bytes) -> ParsedEmail:
    """Realiza o parsing completo de um arquivo de e-mail (.eml) em formato texto ou bytes."""
    if isinstance(raw_eml, bytes):
        msg = email.message_from_bytes(raw_eml, policy=policy.default)
    else:
        msg = email.message_from_string(raw_eml, policy=policy.default)

    from_header = str(msg.get("From", "")).strip()
    display_name, from_address = parseaddr(from_header)
    _, reply_to_addr = parseaddr(str(msg.get("Reply-To", "")).strip())
    _, return_path_addr = parseaddr(str(msg.get("Return-Path", "")).strip())

    received_hops = [str(h).strip() for h in msg.get_all("Received", [])]
    auth_results = " ; ".join(str(h).strip() for h in msg.get_all("Authentication-Results", []))

    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get_content_disposition() or "")
            content_type = part.get_content_type()
            filename = part.get_filename()

            if filename or content_disposition == "attachment":
                payload = part.get_payload(decode=True) or b""
                sha256_hash = hashlib.sha256(payload).hexdigest()
                attachments.append(
                    AttachmentInfo(
                        filename=filename or "unnamed_attachment",
                        content_type=content_type,
                        size_bytes=len(payload),
                        sha256=sha256_hash,
                    )
                )
            elif content_type == "text/plain":
                payload_bytes = part.get_payload(decode=True)
                if payload_bytes is not None:
                    charset = part.get_content_charset() or "utf-8"
                    plain_parts.append(payload_bytes.decode(charset, errors="replace"))
            elif content_type == "text/html":
                payload_bytes = part.get_payload(decode=True)
                if payload_bytes is not None:
                    charset = part.get_content_charset() or "utf-8"
                    html_parts.append(payload_bytes.decode(charset, errors="replace"))
    else:
        content_type = msg.get_content_type()
        payload_bytes = msg.get_payload(decode=True)
        if payload_bytes is not None:
            charset = msg.get_content_charset() or "utf-8"
            decoded_text = payload_bytes.decode(charset, errors="replace")
            if content_type == "text/html":
                html_parts.append(decoded_text)
            else:
                plain_parts.append(decoded_text)

    plain_body = "\n".join(plain_parts)
    html_body = "\n".join(html_parts)
    anchor_links = extract_anchor_links(html_body)

    all_urls = extract_urls_from_text(plain_body)
    for url in extract_urls_from_text(html_body):
        if url not in all_urls:
            all_urls.append(url)
    for anchor in anchor_links:
        if anchor.href.startswith(("http://", "https://")) and anchor.href not in all_urls:
            all_urls.append(anchor.href)

    return ParsedEmail(
        subject=str(msg.get("Subject", "")).strip(),
        from_header=from_header,
        from_display_name=display_name.strip(),
        from_address=from_address.lower().strip(),
        reply_to=reply_to_addr.lower().strip(),
        return_path=return_path_addr.lower().strip(),
        received_hops=received_hops,
        authentication_results=auth_results,
        plain_body=plain_body,
        html_body=html_body,
        extracted_urls=all_urls,
        anchor_links=anchor_links,
        attachments=attachments,
    )


def parse_eml_file(file_path: str | Path) -> ParsedEmail:
    """Lê e faz o parsing de um arquivo .eml do disco."""
    path = Path(file_path)
    return parse_eml_content(path.read_bytes())


def analyze_email_headers_and_attachments(parsed_email: ParsedEmail) -> list[RiskIndicator]:
    """
    Avalia cabeçalhos técnicos (SPF, DKIM, DMARC, Return-Path, Reply-To)
    e anexos suspeitos no e-mail.
    """
    indicators: list[RiskIndicator] = []
    auth_lower = parsed_email.authentication_results.lower()

    # 1. Verificação de SPF / DKIM / DMARC no cabeçalho Authentication-Results
    if re.search(r"spf=(fail|softfail|permerror)", auth_lower):
        indicators.append(
            RiskIndicator(
                code="SPF_FAIL",
                category="Cabeçalhos & Autenticação",
                description="Falha na validação de SPF (remetente não autorizado pelo domínio).",
                weight=RISK_WEIGHTS["SPF_FAIL"],
                evidence=parsed_email.authentication_results,
            )
        )

    if re.search(r"dkim=(fail|permerror)", auth_lower):
        indicators.append(
            RiskIndicator(
                code="DKIM_FAIL",
                category="Cabeçalhos & Autenticação",
                description="Assinatura criptográfica DKIM inválida ou adulterada.",
                weight=RISK_WEIGHTS["DKIM_FAIL"],
                evidence=parsed_email.authentication_results,
            )
        )

    if re.search(r"dmarc=(fail| reject|quarantine)", auth_lower):
        indicators.append(
            RiskIndicator(
                code="DMARC_FAIL",
                category="Cabeçalhos & Autenticação",
                description="Falha na política DMARC do domínio do remetente.",
                weight=RISK_WEIGHTS["DMARC_FAIL"],
                evidence=parsed_email.authentication_results,
            )
        )

    # 2. Divergência de domínios entre From, Reply-To e Return-Path
    from_domain = parsed_email.from_address.split("@")[-1] if "@" in parsed_email.from_address else ""
    reply_domain = parsed_email.reply_to.split("@")[-1] if "@" in parsed_email.reply_to else ""
    return_domain = parsed_email.return_path.split("@")[-1] if "@" in parsed_email.return_path else ""

    if from_domain and reply_domain and from_domain != reply_domain:
        indicators.append(
            RiskIndicator(
                code="REPLY_TO_MISMATCH",
                category="Cabeçalhos & Autenticação",
                description="O endereço de resposta (Reply-To) pertence a um domínio diferente do remetente (From).",
                weight=RISK_WEIGHTS["REPLY_TO_MISMATCH"],
                evidence=f"From: {parsed_email.from_address} | Reply-To: {parsed_email.reply_to}",
            )
        )

    if from_domain and return_domain and from_domain != return_domain:
        indicators.append(
            RiskIndicator(
                code="RETURN_PATH_MISMATCH",
                category="Cabeçalhos & Autenticação",
                description="O envelope Return-Path diverge do domínio exibido no cabeçalho From.",
                weight=RISK_WEIGHTS["RETURN_PATH_MISMATCH"],
                evidence=f"From: {parsed_email.from_address} | Return-Path: {parsed_email.return_path}",
            )
        )

    # 3. Spoofing de Nome de Exibição contendo outro endereço de e-mail
    if "@" in parsed_email.from_display_name and parsed_email.from_address not in parsed_email.from_display_name.lower():
        indicators.append(
            RiskIndicator(
                code="DISPLAY_NAME_SPOOFING",
                category="Cabeçalhos & Autenticação",
                description="O nome de exibição (Display Name) tenta simular um e-mail diferente do remetente real.",
                weight=RISK_WEIGHTS["DISPLAY_NAME_SPOOFING"],
                evidence=parsed_email.from_header,
            )
        )

    # 4. Anexos com extensão executável ou script perigoso
    for attachment in parsed_email.attachments:
        filename_lower = attachment.filename.lower()
        if any(filename_lower.endswith(ext) for ext in DANGEROUS_ATTACHMENT_EXTENSIONS):
            indicators.append(
                RiskIndicator(
                    code="DANGEROUS_ATTACHMENT",
                    category="Anexos Maliciosos",
                    description=f"Anexo com extensão potencialmente maliciosa detectado: {attachment.filename}",
                    weight=RISK_WEIGHTS["DANGEROUS_ATTACHMENT"],
                    evidence=f"{attachment.filename} (SHA-256: {attachment.sha256})",
                )
            )

    return indicators
