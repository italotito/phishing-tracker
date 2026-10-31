"""
Camada de Backend REST API construída com FastAPI.
Expõe endpoints assíncronos para triagem de URLs, análise de e-mails (.eml),
consulta de histórico e métricas de risco com documentação Swagger automática (/docs).
"""

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src import __version__
from src.config import VIRUSTOTAL_API_KEY
from src.database import (
    clear_scan_history,
    get_recent_scans,
    get_scan_stats,
    init_db,
    save_scan_report,
)
from src.risk_calculator import analyze_email_raw, analyze_single_url


# ==============================================================================
# Schemas Pydantic ( Validação de Entrada e Contrato OpenAPI / Swagger )
# ==============================================================================


class URLAnalyzeRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        description="URL completa ou domínio a ser analisado.",
        examples=["http://login-paypa1-verificacao.xyz/auth/confirm"],
    )
    use_virustotal: bool = Field(
        default=True,
        description="Define se deve consultar a reputação externa no VirusTotal (caso a chave esteja configurada).",
    )
    save_history: bool = Field(
        default=True,
        description="Salva o resultado no histórico SQLite.",
    )


class RawEmailAnalyzeRequest(BaseModel):
    raw_eml: str = Field(
        ...,
        min_length=10,
        description="Conteúdo bruto do e-mail em formato RFC 5322 (.eml) ou texto da mensagem.",
    )
    identifier: str = Field(
        default="email_submetido.eml",
        description="Nome ou identificador amigável do e-mail analisado.",
    )
    use_virustotal: bool = Field(
        default=True,
        description="Define se deve consultar URLs e hashes no VirusTotal.",
    )
    save_history: bool = Field(
        default=True,
        description="Salva o resultado no histórico SQLite.",
    )


class IndicatorResponse(BaseModel):
    code: str
    category: str
    description: str
    weight: int
    evidence: str = ""


class AnalysisResponse(BaseModel):
    scan_id: int | None = None
    target_type: str
    target_identifier: str
    risk_score: int
    classification: str
    indicators: list[IndicatorResponse]
    extracted_urls: list[str]
    metadata: dict[str, Any]


class StatsResponse(BaseModel):
    total_scans: int
    avg_risk_score: float
    safe_count: int
    suspicious_count: int
    high_risk_count: int
    critical_count: int


# ==============================================================================
# Inicialização da Aplicação FastAPI
# ==============================================================================


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Garante que o banco de dados SQLite esteja inicializado na subida do servidor."""
    init_db()
    yield


app = FastAPI(
    title="Fishing Tracker API",
    description=(
        "API RESTful para detecção de phishing em URLs e arquivos de e-mail (.eml) "
        "combinando heurística de domínios, análise de linguagem e VirusTotal API v3."
    ),
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# Rotas da API
# ==============================================================================


@app.get("/health", tags=["Sistema"])
async def health_check() -> dict[str, Any]:
    """Verifica a disponibilidade da API e o status da integração VirusTotal."""
    vt_configured = bool(
        VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "sua_chave_do_virustotal_aqui"
    )
    return {
        "status": "ok",
        "service": "fishing-tracker-api",
        "version": __version__,
        "virustotal_configured": vt_configured,
    }


@app.post("/api/v1/analyze/url", response_model=AnalysisResponse, tags=["Análise"])
async def analyze_url_endpoint(payload: URLAnalyzeRequest) -> dict[str, Any]:
    """Analisa uma URL em busca de indicadores de phishing e calcula o score de risco (0-100)."""
    clean_url = payload.url.strip()
    if not clean_url:
        raise HTTPException(status_code=400, detail="A URL informada não pode estar vazia.")

    report = analyze_single_url(clean_url, use_virustotal=payload.use_virustotal)
    scan_id = save_scan_report(report) if payload.save_history else None

    result = report.to_dict()
    result["scan_id"] = scan_id
    return result


@app.post("/api/v1/analyze/email/raw", response_model=AnalysisResponse, tags=["Análise"])
async def analyze_raw_email_endpoint(payload: RawEmailAnalyzeRequest) -> dict[str, Any]:
    """Analisa o conteúdo bruto de um e-mail (.eml) enviado via JSON."""
    if not payload.raw_eml.strip():
        raise HTTPException(status_code=400, detail="O conteúdo do e-mail não pode estar vazio.")

    report = analyze_email_raw(
        payload.raw_eml,
        identifier=payload.identifier,
        use_virustotal=payload.use_virustotal,
    )
    scan_id = save_scan_report(report) if payload.save_history else None

    result = report.to_dict()
    result["scan_id"] = scan_id
    return result


@app.post("/api/v1/analyze/email/upload", response_model=AnalysisResponse, tags=["Análise"])
async def analyze_uploaded_email_endpoint(
    file: UploadFile = File(..., description="Arquivo de e-mail (.eml) para análise."),
    use_virustotal: bool = Query(default=True, description="Consultar reputação no VirusTotal."),
    save_history: bool = Query(default=True, description="Salvar análise no histórico SQLite."),
) -> dict[str, Any]:
    """Recebe o upload de um arquivo `.eml`, extrai cabeçalhos/corpo/links e calcula o risco."""
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="O arquivo enviado está vazio.")

    filename = file.filename or "uploaded_email.eml"
    report = analyze_email_raw(
        raw_bytes,
        identifier=filename,
        use_virustotal=use_virustotal,
    )
    scan_id = save_scan_report(report) if save_history else None

    result = report.to_dict()
    result["scan_id"] = scan_id
    return result


@app.get("/api/v1/history", tags=["Histórico & Métricas"])
async def list_scan_history(
    limit: int = Query(default=50, ge=1, le=500, description="Quantidade máxima de registros.")
) -> list[dict[str, Any]]:
    """Retorna o histórico recente de URLs e e-mails analisados."""
    return get_recent_scans(limit=limit)


@app.get("/api/v1/stats", response_model=StatsResponse, tags=["Histórico & Métricas"])
async def get_dashboard_stats() -> dict[str, Any]:
    """Retorna contadores consolidados e média de risco para exibição no painel."""
    return get_scan_stats()


@app.delete("/api/v1/history", tags=["Histórico & Métricas"])
async def delete_scan_history() -> dict[str, str]:
    """Limpa todos os registros do histórico local SQLite."""
    clear_scan_history()
    return {"status": "cleared", "message": "Histórico de análises removido com sucesso."}
