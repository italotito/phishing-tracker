"""
Modelos de dados estruturados para o motor de análise de phishing.
"""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class RiskIndicator:
    """Representa uma evidência individual de phishing detectada."""
    code: str
    category: str
    description: str
    weight: int
    evidence: str = ""


@dataclass(frozen=True)
class AnchorLink:
    """Representa um hiperlink HTML (<a href='...'>texto</a>) extraído de um e-mail."""
    href: str
    visible_text: str


@dataclass(frozen=True)
class AttachmentInfo:
    """Metadados e hash SHA-256 de um anexo de e-mail."""
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class ParsedEmail:
    """Estrutura consolidada de um arquivo de e-mail (.eml) após ingestão e parsing."""
    subject: str = ""
    from_header: str = ""
    from_display_name: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    received_hops: list[str] = field(default_factory=list)
    authentication_results: str = ""
    plain_body: str = ""
    html_body: str = ""
    extracted_urls: list[str] = field(default_factory=list)
    anchor_links: list[AnchorLink] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)


@dataclass
class AnalysisReport:
    """Relatório final consolidado pela Calculadora de Risco."""
    target_type: str  # "URL" ou "EMAIL"
    target_identifier: str
    risk_score: int
    classification: str
    indicators: list[RiskIndicator] = field(default_factory=list)
    extracted_urls: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Converte o relatório para dicionário serializável em JSON."""
        return asdict(self)
