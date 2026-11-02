"""
Dashboard Interativo de Detecção de Phishing (Streamlit).
Permite submeter URLs, arquivos de e-mail (.eml), visualizar gráficos de risco
e auditar o histórico de análises via Motor Local ou via API FastAPI.
"""

import json
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

import streamlit as st

from src.config import VIRUSTOTAL_API_KEY
from src.database import (
    clear_scan_history,
    get_recent_scans,
    get_scan_stats,
    init_db,
    save_scan_report,
)
from src.risk_calculator import analyze_email_raw, analyze_single_url

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"


# ==============================================================================
# Funções Auxiliares de Comunicação (Motor Local vs. FastAPI)
# ==============================================================================


def _badge_color(score: int) -> str:
    """Retorna a cor hexadecimal correspondente à faixa de risco."""
    if score <= 20:
        return "#16a34a"  # Verde (Seguro)
    if score <= 50:
        return "#ca8a04"  # Amarelo/Âmbar (Suspeito)
    if score <= 75:
        return "#ea580c"  # Laranja (Alto Risco)
    return "#dc2626"      # Vermelho (Crítico)


def run_url_analysis(
    url: str,
    use_vt: bool,
    use_api_mode: bool,
    api_base_url: str,
) -> dict[str, Any]:
    """Executa a análise de URL via FastAPI (se selecionado) ou diretamente pelo motor local."""
    if use_api_mode:
        endpoint = f"{api_base_url.rstrip('/')}/api/v1/analyze/url"
        payload = json.dumps(
            {"url": url, "use_virustotal": use_vt, "save_history": True}
        ).encode("utf-8")
        req = Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except URLError as exc:
            st.warning(
                f"API FastAPI indisponível em `{api_base_url}` ({exc}). "
                "Executando fallback automático no motor local."
            )

    report = analyze_single_url(url, use_virustotal=use_vt)
    scan_id = save_scan_report(report)
    data = report.to_dict()
    data["scan_id"] = scan_id
    return data


def run_email_analysis(
    raw_eml: str | bytes,
    identifier: str,
    use_vt: bool,
    use_api_mode: bool,
    api_base_url: str,
) -> dict[str, Any]:
    """Executa a análise de e-mail (.eml) via FastAPI ou diretamente pelo motor local."""
    if use_api_mode:
        endpoint = f"{api_base_url.rstrip('/')}/api/v1/analyze/email/raw"
        raw_text = (
            raw_eml.decode("utf-8", errors="replace")
            if isinstance(raw_eml, bytes)
            else raw_eml
        )
        payload = json.dumps(
            {
                "raw_eml": raw_text,
                "identifier": identifier,
                "use_virustotal": use_vt,
                "save_history": True,
            }
        ).encode("utf-8")
        req = Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except URLError as exc:
            st.warning(
                f"API FastAPI indisponível em `{api_base_url}` ({exc}). "
                "Executando fallback automático no motor local."
            )

    report = analyze_email_raw(raw_eml, identifier=identifier, use_virustotal=use_vt)
    scan_id = save_scan_report(report)
    data = report.to_dict()
    data["scan_id"] = scan_id
    return data


def render_analysis_result(result: dict[str, Any]) -> None:
    """Renderiza os cartões visuais de score, metadados, gráficos e tabela de indicadores."""
    score = int(result.get("risk_score", 0))
    classification = result.get("classification", "")
    color = _badge_color(score)
    indicators = result.get("indicators", [])

    st.markdown(
        f"""
        <div style="padding: 1.25rem; border-radius: 0.75rem; border-left: 8px solid {color};
                    background-color: rgba(128, 128, 128, 0.08); margin-bottom: 1rem;">
            <h3 style="margin: 0; color: {color};">Placar de Risco: {score}/100 — {classification}</h3>
            <p style="margin: 0.35rem 0 0 0; font-size: 0.95rem;">
                <strong>Alvo ({result.get('target_type')}):</strong> <code>{result.get('target_identifier')}</code>
                &nbsp;|&nbsp; <strong>Indicadores acionados:</strong> {len(indicators)}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.progress(score / 100.0)

    # Metadados de E-mail (quando aplicável)
    metadata = result.get("metadata") or {}
    if result.get("target_type") == "EMAIL":
        with st.expander("📨 Cabeçalhos e Metadados do E-mail", expanded=True):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Assunto:** {metadata.get('subject') or '(vazio)'}")
                st.write(f"**De (From):** `{metadata.get('from') or '(vazio)'}`")
                st.write(f"**Anexos:** {metadata.get('attachments_count', 0)}")
            with col2:
                st.write(f"**Reply-To:** `{metadata.get('reply_to') or '(não definido)'}`")
                st.write(f"**Return-Path:** `{metadata.get('return_path') or '(não definido)'}`")
                st.write(f"**URLs Extraídas:** {len(result.get('extracted_urls', []))}")

    if not indicators:
        st.success("✅ Nenhum indicador malicioso ou suspeito foi detectado neste artefato.")
    else:
        st.subheader("🚨 Evidências e Indicadores Detectados")

        # Gráfico de soma de pontos por categoria
        category_weights: dict[str, int] = {}
        for ind in indicators:
            cat = ind.get("category", "Outros")
            category_weights[cat] = category_weights.get(cat, 0) + int(ind.get("weight", 0))

        col_chart, col_list = st.columns([1, 2])
        with col_chart:
            st.caption("Pontuação acumulada por categoria")
            st.bar_chart(category_weights)

        with col_list:
            for ind in indicators:
                with st.container(border=True):
                    st.markdown(
                        f"**`{ind['code']}`** — _{ind['category']}_ "
                        f"(:red[**+{ind['weight']} pts**])"
                    )
                    st.write(ind["description"])
                    if ind.get("evidence"):
                        st.code(ind["evidence"], language="text")

    extracted_urls = result.get("extracted_urls", [])
    if extracted_urls:
        with st.expander(f"🔗 URLs Extraídas ({len(extracted_urls)})"):
            for u in extracted_urls:
                st.code(u, language="text")

    with st.expander("📄 Exportar Relatório Técnico (JSON)"):
        st.json(result)
        st.download_button(
            label="⬇️ Baixar Relatório JSON",
            data=json.dumps(result, indent=2, ensure_ascii=False),
            file_name=f"relatorio_phishing_{result.get('scan_id', 'local')}.json",
            mime="application/json",
        )


# ==============================================================================
# Layout Principal da Aplicação Streamlit
# ==============================================================================


def main() -> None:
    st.set_page_config(
        page_title="Phishing Tracker | Detecção de Phishing",
        page_icon="🛡️",
        layout="wide",
    )
    init_db()

    st.title("🛡️ Phishing Tracker — Painel de Detecção de Phishing")
    st.caption(
        "Triagem heurística de URLs e arquivos de e-mail (`.eml`), análise de engenharia social e reputação VirusTotal."
    )

    # --- Barra Lateral (Configurações) ---
    with st.sidebar:
        st.header("⚙️ Configurações de Execução")
        exec_mode = st.radio(
            "Modo de Processamento:",
            options=[
                "Motor Local Direto (SQLite)",
                "Cliente REST API (FastAPI)",
            ],
            help="No modo local, o Streamlit chama os módulos Python diretamente. No modo API, consome o servidor FastAPI.",
        )
        use_api_mode = exec_mode == "Cliente REST API (FastAPI)"
        api_base_url = "http://127.0.0.1:8000"
        if use_api_mode:
            api_base_url = st.text_input("URL da API FastAPI:", value="http://127.0.0.1:8000")

        vt_configured = bool(
            VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "sua_chave_do_virustotal_aqui"
        )
        use_vt = st.toggle(
            "Consultar VirusTotal API v3",
            value=vt_configured,
            help="Requer VIRUSTOTAL_API_KEY configurada no arquivo .env.",
        )
        if vt_configured:
            st.success("🔑 Chave VirusTotal detectada no `.env`")
        else:
            st.info("ℹ️ Chave VirusTotal ausente — operando 100% com Heurística Local")

        st.divider()
        st.markdown("### 📌 Escala de Risco")
        st.markdown(
            "- 🟢 **0 – 20**: Seguro (Baixo Risco)\n"
            "- 🟡 **21 – 50**: Suspeito (Atenção)\n"
            "- 🟠 **51 – 75**: Alto Risco\n"
            "- 🔴 **76 – 100**: Crítico (Phishing)"
        )

    tab_url, tab_email, tab_history = st.tabs(
        ["🔗 Analisar URL", "📧 Analisar E-mail (.eml)", "📊 Histórico & Métricas"]
    )

    # ==========================================================================
    # ABA 1: ANÁLISE DE URL
    # ==========================================================================
    with tab_url:
        st.subheader("Triagem de URL Suspeita")
        st.write("Insira uma URL abaixo ou selecione um dos exemplos rápidos para testar a heurística:")

        preset_col1, preset_col2, preset_col3, preset_col4 = st.columns(4)
        if "url_input_value" not in st.session_state:
            st.session_state.url_input_value = "http://login-paypa1-verificacao.xyz/auth/confirm"

        with preset_col1:
            if st.button("🧪 Exemplo Typosquatting", use_container_width=True):
                st.session_state.url_input_value = "http://login-paypa1-verificacao.xyz/auth/confirm"
        with preset_col2:
            if st.button("🧪 Exemplo Punycode (IDN)", use_container_width=True):
                st.session_state.url_input_value = "https://xn--pple-43d.com/id/login"
        with preset_col3:
            if st.button("🧪 Exemplo IP Bruto + @", use_container_width=True):
                st.session_state.url_input_value = "http://google.com@185.220.101.45/login/auth.php"
        with preset_col4:
            if st.button("✅ Exemplo URL Segura", use_container_width=True):
                st.session_state.url_input_value = "https://www.itau.com.br/seguranca"

        target_url = st.text_input("URL para análise:", key="url_input_value")

        if st.button("🔍 Executar Análise de URL", type="primary"):
            if not target_url.strip():
                st.error("Por favor, informe uma URL válida.")
            else:
                with st.spinner("Analisando estrutura do domínio, heurísticas e reputação..."):
                    result = run_url_analysis(
                        target_url.strip(),
                        use_vt=use_vt,
                        use_api_mode=use_api_mode,
                        api_base_url=api_base_url,
                    )
                render_analysis_result(result)

    # ==========================================================================
    # ABA 2: ANÁLISE DE E-MAIL (.EML)
    # ==========================================================================
    with tab_email:
        st.subheader("Triagem de Mensagem de E-mail (`.eml`)")
        input_method = st.radio(
            "Fonte do E-mail:",
            options=[
                "Carregar exemplo de teste (Pasta samples/)",
                "Fazer upload de arquivo .eml",
                "Colar conteúdo bruto (.eml / cabeçalhos + corpo)",
            ],
            horizontal=True,
        )

        raw_email_data: str | bytes | None = None
        email_identifier = "email.eml"

        if input_method == "Carregar exemplo de teste (Pasta samples/)":
            sample_choice = st.selectbox(
                "Escolha o arquivo de demonstração:",
                options=[
                    "phishing_urgente.eml (Simulação de Phishing Bancário com Spoofing + Urgência)",
                    "legitim_notification.eml (E-mail Legítimo do GitHub com SPF/DKIM/DMARC Pass)",
                ],
            )
            sample_filename = sample_choice.split(" ")[0]
            sample_path = SAMPLES_DIR / sample_filename
            if sample_path.exists():
                raw_email_data = sample_path.read_bytes()
                email_identifier = sample_filename
                with st.expander("👁️ Visualizar código-fonte bruto do arquivo `.eml`"):
                    st.code(sample_path.read_text(encoding="utf-8", errors="replace"), language="http")

        elif input_method == "Fazer upload de arquivo .eml":
            uploaded = st.file_uploader("Selecione um arquivo `.eml`", type=["eml", "txt"])
            if uploaded is not None:
                raw_email_data = uploaded.getvalue()
                email_identifier = uploaded.name

        else:
            pasted_text = st.text_area(
                "Cole os cabeçalhos e o corpo do e-mail:",
                height=220,
                placeholder="From: suporte@banco.com\nSubject: URGENTE: Conta bloqueada...\n\nClique aqui...",
            )
            if pasted_text.strip():
                raw_email_data = pasted_text
                email_identifier = "email_colado_manualmente.eml"

        if st.button("🔍 Executar Análise de E-mail", type="primary"):
            if not raw_email_data:
                st.error("Selecione ou forneça um e-mail para analisar.")
            else:
                with st.spinner("Extraindo cabeçalhos SPF/DKIM/DMARC, links HTML e avaliando linguagem..."):
                    result = run_email_analysis(
                        raw_email_data,
                        identifier=email_identifier,
                        use_vt=use_vt,
                        use_api_mode=use_api_mode,
                        api_base_url=api_base_url,
                    )
                render_analysis_result(result)

    # ==========================================================================
    # ABA 3: HISTÓRICO & MÉTRICAS (SQLITE)
    # ==========================================================================
    with tab_history:
        st.subheader("Indicadores Consolidados e Histórico de Auditoria (SQLite)")
        stats = get_scan_stats()

        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Total Analisado", stats["total_scans"])
        k2.metric("Risco Médio", f"{stats['avg_risk_score']}/100")
        k3.metric("🔴 Crítico / 🟠 Alto Risco", stats["critical_count"] + stats["high_risk_count"])
        k4.metric("🟡 Suspeitos", stats["suspicious_count"])
        k5.metric("🟢 Seguros", stats["safe_count"])

        if stats["total_scans"] > 0:
            dist_data = {
                "1. Seguro (0–20)": stats["safe_count"],
                "2. Suspeito (21–50)": stats["suspicious_count"],
                "3. Alto Risco (51–75)": stats["high_risk_count"],
                "4. Crítico (76–100)": stats["critical_count"],
            }
            st.caption("Distribuição de Análises por Severidade")
            st.bar_chart(dist_data)

            recent_scans = get_recent_scans(limit=30)
            table_rows = [
                {
                    "ID": row["id"],
                    "Data/Hora": row["created_at"],
                    "Tipo": row["target_type"],
                    "Alvo": row["target_identifier"],
                    "Score (0–100)": row["risk_score"],
                    "Classificação": row["classification"],
                    "Qtd. Indicadores": row["indicators_count"],
                }
                for row in recent_scans
            ]
            st.dataframe(table_rows, use_container_width=True, hide_index=True)

            if st.button("🗑️ Limpar Histórico de Análises"):
                clear_scan_history()
                st.rerun()
        else:
            st.info("Nenhuma análise registrada ainda no banco SQLite. Execute um teste nas abas acima!")


if __name__ == "__main__":
    main()
