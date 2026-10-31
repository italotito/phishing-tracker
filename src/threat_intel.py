"""
Módulo 4: Integração com Threat Intelligence Externa (VirusTotal API v3).
Consulta reputação de URLs e hashes SHA-256 de anexos em tempo real.
"""

import base64
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from src.config import REQUEST_TIMEOUT_SECONDS, RISK_WEIGHTS, VIRUSTOTAL_API_KEY
from src.models import RiskIndicator

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _vt_api_get(endpoint: str, api_key: str) -> dict[str, Any] | None:
    """
    Executa uma requisição GET autenticada na API v3 do VirusTotal.
    Usa `requests` se instalado ou `urllib.request` da biblioteca padrão como fallback.
    """
    if not api_key or api_key == "sua_chave_do_virustotal_aqui":
        return None

    full_url = f"{VT_BASE_URL}/{endpoint.lstrip('/')}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "FishingTracker-SecurityEngine/1.0",
    }

    try:
        import requests  # type: ignore

        response = requests.get(full_url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        if response.status_code == 200:
            return response.json()
        return None
    except ImportError:
        req = Request(full_url, headers=headers, method="GET")
        try:
            with urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError):
            return None
    except Exception:
        return None

    return None


def encode_vt_url_id(url: str) -> str:
    """
    Gera o identificador de URL exigido pelo VirusTotal API v3:
    Base64 URL-safe sem caracteres de padding ('=').
    """
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")


def parse_vt_stats_to_indicators(stats: dict[str, int], artifact_label: str) -> list[RiskIndicator]:
    """
    Converte o dicionário `last_analysis_stats` do VirusTotal em indicadores de risco ponderados.
    """
    indicators: list[RiskIndicator] = []
    malicious_count = int(stats.get("malicious", 0))
    suspicious_count = int(stats.get("suspicious", 0))
    total_engines = sum(int(v) for v in stats.values()) if stats else 0

    if malicious_count >= 3:
        indicators.append(
            RiskIndicator(
                code="VT_MALICIOUS_HIGH",
                category="Threat Intelligence (VirusTotal)",
                description=f"VirusTotal: {malicious_count}/{total_engines} motores classificaram o artefato como MALICIOSO.",
                weight=RISK_WEIGHTS["VT_MALICIOUS_HIGH"],
                evidence=f"{artifact_label} (malicious={malicious_count}, suspicious={suspicious_count})",
            )
        )
    elif 1 <= malicious_count <= 2:
        indicators.append(
            RiskIndicator(
                code="VT_MALICIOUS_LOW",
                category="Threat Intelligence (VirusTotal)",
                description=f"VirusTotal: {malicious_count}/{total_engines} motor(es) marcaram o artefato como malicioso.",
                weight=RISK_WEIGHTS["VT_MALICIOUS_LOW"],
                evidence=f"{artifact_label} (malicious={malicious_count}, suspicious={suspicious_count})",
            )
        )
    elif suspicious_count >= 1:
        indicators.append(
            RiskIndicator(
                code="VT_SUSPICIOUS_ONLY",
                category="Threat Intelligence (VirusTotal)",
                description=f"VirusTotal: {suspicious_count}/{total_engines} motor(es) marcaram o artefato como suspeito.",
                weight=RISK_WEIGHTS["VT_SUSPICIOUS_ONLY"],
                evidence=f"{artifact_label} (suspicious={suspicious_count})",
            )
        )

    return indicators


def check_url_reputation_vt(url: str, api_key: str = VIRUSTOTAL_API_KEY) -> list[RiskIndicator]:
    """Consulta a reputação de uma URL na API v3 do VirusTotal (`/urls/{id}`)."""
    url_id = encode_vt_url_id(url)
    payload = _vt_api_get(f"urls/{url_id}", api_key=api_key)
    if not payload:
        return []

    stats = (
        payload.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    return parse_vt_stats_to_indicators(stats, artifact_label=url)


def check_file_hash_reputation_vt(sha256_hash: str, filename: str = "", api_key: str = VIRUSTOTAL_API_KEY) -> list[RiskIndicator]:
    """Consulta a reputação do hash SHA-256 de um anexo na API v3 do VirusTotal (`/files/{hash}`)."""
    payload = _vt_api_get(f"files/{sha256_hash}", api_key=api_key)
    if not payload:
        return []

    stats = (
        payload.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    label = f"{filename} ({sha256_hash[:12]}...)" if filename else sha256_hash
    return parse_vt_stats_to_indicators(stats, artifact_label=label)
