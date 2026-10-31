"""
Módulo 5: Calculadora de Risco (0 a 100) e Orquestrador de Análise.
Consolida os indicadores dos módulos de Parsing, Heurística de Domínio,
Análise Semântica e Threat Intelligence (VirusTotal).
"""

from pathlib import Path

from src.config import VIRUSTOTAL_API_KEY
from src.domain_heuristics import analyze_url_heuristics
from src.language_analyzer import analyze_html_patterns, analyze_text_language
from src.models import AnalysisReport, ParsedEmail, RiskIndicator
from src.parser import (
    analyze_email_headers_and_attachments,
    parse_eml_content,
    parse_eml_file,
)
from src.threat_intel import check_file_hash_reputation_vt, check_url_reputation_vt


def classify_risk_score(score: int) -> str:
    """Retorna a classificação textual de severidade com base no placar de 0 a 100."""
    if score <= 20:
        return "SEGURO (Baixo Risco)"
    if score <= 50:
        return "SUSPEITO (Atenção Moderada)"
    if score <= 75:
        return "ALTO RISCO (Provável Phishing)"
    return "CRÍTICO (Phishing Confirmado)"


def calculate_total_score(indicators: list[RiskIndicator]) -> int:
    """
    Calcula o placar final somando os pesos dos indicadores detectados,
    limitado ao teto máximo de 100 pontos.
    """
    raw_total = sum(ind.weight for ind in indicators)
    return min(100, max(0, raw_total))


def analyze_single_url(url: str, use_virustotal: bool = True) -> AnalysisReport:
    """Executa a triagem completa de uma URL individual."""
    indicators: list[RiskIndicator] = []
    indicators.extend(analyze_url_heuristics(url))

    vt_enabled = bool(
        use_virustotal
        and VIRUSTOTAL_API_KEY
        and VIRUSTOTAL_API_KEY != "sua_chave_do_virustotal_aqui"
    )
    if vt_enabled:
        indicators.extend(check_url_reputation_vt(url))

    score = calculate_total_score(indicators)
    return AnalysisReport(
        target_type="URL",
        target_identifier=url,
        risk_score=score,
        classification=classify_risk_score(score),
        indicators=indicators,
        extracted_urls=[url],
        metadata={"virustotal_checked": vt_enabled},
    )


def analyze_parsed_email(
    parsed_email: ParsedEmail,
    identifier: str = "email_message",
    use_virustotal: bool = True,
) -> AnalysisReport:
    """Executa a análise completa sobre um objeto ParsedEmail."""
    indicators: list[RiskIndicator] = []

    # 1. Cabeçalhos técnicos (SPF, DKIM, DMARC, Spoofing) e anexos perigosos
    indicators.extend(analyze_email_headers_and_attachments(parsed_email))

    # 2. Análise de linguagem e engenharia social no assunto + corpo
    body_for_language = parsed_email.plain_body or parsed_email.html_body
    indicators.extend(analyze_text_language(parsed_email.subject, body_for_language))

    # 3. Padrões maliciosos em HTML (links âncora camuflados e formulários)
    indicators.extend(analyze_html_patterns(parsed_email.html_body, parsed_email.anchor_links))

    # 4. Heurística de todas as URLs extraídas do e-mail (evitando duplicar o mesmo código+evidência)
    seen_url_indicators: set[tuple[str, str]] = set()
    vt_enabled = bool(
        use_virustotal
        and VIRUSTOTAL_API_KEY
        and VIRUSTOTAL_API_KEY != "sua_chave_do_virustotal_aqui"
    )

    for url in parsed_email.extracted_urls:
        for ind in analyze_url_heuristics(url):
            key = (ind.code, ind.evidence)
            if key not in seen_url_indicators:
                seen_url_indicators.add(key)
                indicators.append(ind)

        if vt_enabled:
            for vt_ind in check_url_reputation_vt(url):
                key = (vt_ind.code, vt_ind.evidence)
                if key not in seen_url_indicators:
                    seen_url_indicators.add(key)
                    indicators.append(vt_ind)

    # 5. Reputação dos hashes SHA-256 dos anexos no VirusTotal
    if vt_enabled:
        for attachment in parsed_email.attachments:
            indicators.extend(
                check_file_hash_reputation_vt(attachment.sha256, filename=attachment.filename)
            )

    score = calculate_total_score(indicators)
    return AnalysisReport(
        target_type="EMAIL",
        target_identifier=identifier,
        risk_score=score,
        classification=classify_risk_score(score),
        indicators=indicators,
        extracted_urls=parsed_email.extracted_urls,
        metadata={
            "subject": parsed_email.subject,
            "from": parsed_email.from_header,
            "reply_to": parsed_email.reply_to,
            "return_path": parsed_email.return_path,
            "attachments_count": len(parsed_email.attachments),
            "virustotal_checked": vt_enabled,
        },
    )


def analyze_email_file(file_path: str | Path, use_virustotal: bool = True) -> AnalysisReport:
    """Lê um arquivo .eml do disco e retorna seu relatório completo de risco."""
    path = Path(file_path)
    parsed = parse_eml_file(path)
    return analyze_parsed_email(parsed, identifier=path.name, use_virustotal=use_virustotal)


def analyze_email_raw(raw_eml: str | bytes, identifier: str = "raw_email", use_virustotal: bool = True) -> AnalysisReport:
    """Analisa o conteúdo bruto (string ou bytes) de um e-mail .eml."""
    parsed = parse_eml_content(raw_eml)
    return analyze_parsed_email(parsed, identifier=identifier, use_virustotal=use_virustotal)
