"""
CLI Principal da Ferramenta de Detecção de Phishing (Phishing Tracker).
Permite analisar URLs individuais, arquivos de e-mail (.eml) ou rodar a suíte de demonstração.
"""

import argparse
import json
import sys
from pathlib import Path

from src.models import AnalysisReport
from src.risk_calculator import analyze_email_file, analyze_single_url


def print_formatted_report(report: AnalysisReport) -> None:
    """Exibe um relatório visualmente organizado no terminal."""
    divider = "=" * 78
    print(divider)
    print(f"ALVO ANALISADO : [{report.target_type}] {report.target_identifier}")
    print(f"PLACAR DE RISCO: {report.risk_score}/100 -> {report.classification}")
    print(divider)

    if report.target_type == "EMAIL" and report.metadata:
        print("METADADOS DO E-MAIL:")
        print(f"  • Assunto       : {report.metadata.get('subject') or '(vazio)'}")
        print(f"  • De (From)     : {report.metadata.get('from') or '(vazio)'}")
        if report.metadata.get("reply_to"):
            print(f"  • Reply-To      : {report.metadata.get('reply_to')}")
        if report.metadata.get("return_path"):
            print(f"  • Return-Path   : {report.metadata.get('return_path')}")
        print(f"  • URLs extraídas: {len(report.extracted_urls)}")
        print("-" * 78)

    if not report.indicators:
        print("Nenhum indicador malicioso ou suspeito foi detectado.")
    else:
        print(f"INDICADORES DETECTADOS ({len(report.indicators)}):")
        for idx, ind in enumerate(report.indicators, start=1):
            print(f"  {idx}. [{ind.category}] (+{ind.weight} pts) {ind.code}")
            print(f"     Descrição: {ind.description}")
            if ind.evidence:
                print(f"     Evidência: {ind.evidence}")
    print(divider + "\n")


def run_demo_suite(as_json: bool = False) -> None:
    """Executa casos práticos de demonstração (URLs e arquivos .eml da pasta samples/)."""
    base_dir = Path(__file__).resolve().parent
    samples_dir = base_dir / "samples"

    demo_urls = [
        "https://www.itau.com.br/seguranca",
        "http://login-paypa1-verificacao.xyz/auth/confirm",
        "https://xn--pple-43d.com/id/login",
    ]

    reports: list[AnalysisReport] = []
    for url in demo_urls:
        reports.append(analyze_single_url(url))

    for eml_name in ("phishing_urgente.eml", "legitim_notification.eml"):
        eml_path = samples_dir / eml_name
        if eml_path.exists():
            reports.append(analyze_email_file(eml_path))

    if as_json:
        print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
    else:
        for report in reports:
            print_formatted_report(report)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phishing Tracker — Motor de Detecção de Phishing em URLs e E-mails (.eml)"
    )
    parser.add_argument("-u", "--url", type=str, help="Analisa uma URL suspeita.")
    parser.add_argument("-e", "--email", type=str, help="Caminho para um arquivo de e-mail (.eml).")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Executa a bateria de demonstração com URLs e e-mails da pasta samples/.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Exibe o relatório final em formato JSON estruturado.",
    )
    parser.add_argument(
        "--no-vt",
        action="store_true",
        help="Desativa consultas externas à API do VirusTotal (apenas análise local/heurística).",
    )

    args = parser.parse_args()
    use_vt = not args.no_vt

    if args.demo:
        run_demo_suite(as_json=args.json)
        return 0

    if not args.url and not args.email:
        parser.print_help()
        return 1

    reports: list[AnalysisReport] = []
    if args.url:
        reports.append(analyze_single_url(args.url, use_virustotal=use_vt))

    if args.email:
        email_path = Path(args.email)
        if not email_path.exists():
            print(f"Erro: Arquivo '{email_path}' não encontrado.", file=sys.stderr)
            return 2
        reports.append(analyze_email_file(email_path, use_virustotal=use_vt))

    if args.json:
        output = reports[0].to_dict() if len(reports) == 1 else [r.to_dict() for r in reports]
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        for report in reports:
            print_formatted_report(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
