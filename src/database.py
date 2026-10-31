"""
Módulo de Persistência Relacional (SQLite).
Armazena o histórico de análises de URLs e e-mails e fornece estatísticas agregadas
para a API (FastAPI) e para o Dashboard (Streamlit).
"""

from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from src.models import AnalysisReport

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "fishing_tracker.db"


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Cria uma conexão SQLite configurada com Row factory por nome de coluna."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    """Inicializa a tabela de histórico de análises caso ainda não exista."""
    with closing(get_connection(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_identifier TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                indicators_count INTEGER NOT NULL,
                indicators_json TEXT NOT NULL,
                extracted_urls_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_scan_report(report: AnalysisReport, db_path: Path = DEFAULT_DB_PATH) -> int:
    """Salva um relatório de análise no banco SQLite e retorna o ID do registro."""
    init_db(db_path)
    report_dict = report.to_dict()
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    with closing(get_connection(db_path)) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_history (
                created_at,
                target_type,
                target_identifier,
                risk_score,
                classification,
                indicators_count,
                indicators_json,
                extracted_urls_json,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_iso,
                report.target_type,
                report.target_identifier,
                report.risk_score,
                report.classification,
                len(report.indicators),
                json.dumps(report_dict["indicators"], ensure_ascii=False),
                json.dumps(report.extracted_urls, ensure_ascii=False),
                json.dumps(report.metadata, ensure_ascii=False),
            ),
        )
        conn.commit()
        return int(cursor.lastrowid or 0)


def get_recent_scans(limit: int = 50, db_path: Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """Retorna os registros mais recentes do histórico de análises."""
    init_db(db_path)
    with closing(get_connection(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT
                id,
                created_at,
                target_type,
                target_identifier,
                risk_score,
                classification,
                indicators_count,
                indicators_json,
                extracted_urls_json,
                metadata_json
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 500)),),
        ).fetchall()

    results: list[dict[str, Any]] = []
    for row in rows:
        results.append(
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "target_type": row["target_type"],
                "target_identifier": row["target_identifier"],
                "risk_score": row["risk_score"],
                "classification": row["classification"],
                "indicators_count": row["indicators_count"],
                "indicators": json.loads(row["indicators_json"]),
                "extracted_urls": json.loads(row["extracted_urls_json"]),
                "metadata": json.loads(row["metadata_json"]),
            }
        )
    return results


def get_scan_stats(db_path: Path = DEFAULT_DB_PATH) -> dict[str, Any]:
    """Calcula métricas consolidadas sobre o histórico de análises armazenado."""
    init_db(db_path)
    with closing(get_connection(db_path)) as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(ROUND(AVG(risk_score), 1), 0.0) AS avg_risk_score,
                SUM(CASE WHEN risk_score <= 20 THEN 1 ELSE 0 END) AS safe_count,
                SUM(CASE WHEN risk_score BETWEEN 21 AND 50 THEN 1 ELSE 0 END) AS suspicious_count,
                SUM(CASE WHEN risk_score BETWEEN 51 AND 75 THEN 1 ELSE 0 END) AS high_risk_count,
                SUM(CASE WHEN risk_score >= 76 THEN 1 ELSE 0 END) AS critical_count
            FROM scan_history
            """
        ).fetchone()

    return {
        "total_scans": int(row["total_scans"] or 0),
        "avg_risk_score": float(row["avg_risk_score"] or 0.0),
        "safe_count": int(row["safe_count"] or 0),
        "suspicious_count": int(row["suspicious_count"] or 0),
        "high_risk_count": int(row["high_risk_count"] or 0),
        "critical_count": int(row["critical_count"] or 0),
    }


def clear_scan_history(db_path: Path = DEFAULT_DB_PATH) -> None:
    """Remove todos os registros do histórico de análises."""
    init_db(db_path)
    with closing(get_connection(db_path)) as conn:
        conn.execute("DELETE FROM scan_history")
        conn.commit()
