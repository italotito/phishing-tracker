"""
Suíte de Testes Unitários e de Integração para o Motor de Detecção de Phishing.
Compatível tanto com `pytest` quanto com `python -m unittest`.
"""

from pathlib import Path
import tempfile
import unittest

from src.database import (
    clear_scan_history,
    get_recent_scans,
    get_scan_stats,
    init_db,
    save_scan_report,
)
from src.domain_heuristics import analyze_url_heuristics, detect_typosquatting, levenshtein_distance
from src.language_analyzer import analyze_html_patterns, analyze_text_language
from src.models import AnchorLink
from src.risk_calculator import analyze_email_file, analyze_single_url
from src.threat_intel import encode_vt_url_id, parse_vt_stats_to_indicators

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class TestFishingTrackerEngine(unittest.TestCase):
    """Valida os 5 módulos principais do motor de análise."""

    def test_levenshtein_distance(self) -> None:
        self.assertEqual(levenshtein_distance("paypal", "paypal"), 0)
        self.assertEqual(levenshtein_distance("paypal", "paypa1"), 1)
        self.assertEqual(levenshtein_distance("google", "g00gle"), 2)

    def test_typosquatting_detection(self) -> None:
        is_typo, _ = detect_typosquatting("paypa1")
        self.assertTrue(is_typo)

        is_typo_rn, _ = detect_typosquatting("rnicrosoft")
        self.assertTrue(is_typo_rn)

        is_legit, _ = detect_typosquatting("itau")
        self.assertFalse(is_legit)

    def test_url_heuristics_malicious_vs_safe(self) -> None:
        safe_report = analyze_single_url("https://www.itau.com.br/seguranca", use_virustotal=False)
        self.assertEqual(safe_report.risk_score, 0)
        self.assertIn("SEGURO", safe_report.classification)

        phish_report = analyze_single_url(
            "http://login-paypa1-verificacao.xyz/auth/confirm",
            use_virustotal=False,
        )
        codes = {ind.code for ind in phish_report.indicators}
        self.assertIn("TYPOSQUATTING_DETECTED", codes)
        self.assertIn("SUSPICIOUS_TLD", codes)
        self.assertGreaterEqual(phish_report.risk_score, 50)

    def test_punycode_and_raw_ip_url(self) -> None:
        puny_inds = analyze_url_heuristics("https://xn--pple-43d.com/login")
        self.assertTrue(any(i.code == "PUNYCODE_HOMOGRAPH" for i in puny_inds))

        ip_inds = analyze_url_heuristics("http://google.com@185.220.101.45/login")
        codes = {i.code for i in ip_inds}
        self.assertIn("AT_SYMBOL_IN_URL", codes)
        self.assertIn("RAW_IP_IN_URL", codes)

    def test_language_and_deceptive_html_links(self) -> None:
        lang_inds = analyze_text_language(
            subject="URGENTE: Sua conta sera suspensa em ate 24 horas",
            body_text="Realize uma acao imediata e atualize seu token para evitar o bloqueio preventivo.",
        )
        codes = {i.code for i in lang_inds}
        self.assertIn("URGENCY_LANGUAGE", codes)
        self.assertIn("THREAT_OR_ACCOUNT_SUSPENSION", codes)
        self.assertIn("FINANCIAL_OR_CREDENTIAL_BAIT", codes)

        anchors = [
            AnchorLink(
                href="http://itau-login-token.xyz/auth",
                visible_text="https://www.itau.com.br/seguranca",
            )
        ]
        html_inds = analyze_html_patterns("<form action='http://evil.xyz'></form>", anchors)
        html_codes = {i.code for i in html_inds}
        self.assertIn("DECEPTIVE_ANCHOR_LINK", html_codes)
        self.assertIn("EMBEDDED_HTML_FORM", html_codes)

    def test_sample_emails_end_to_end(self) -> None:
        phish_eml = SAMPLES_DIR / "phishing_urgente.eml"
        legit_eml = SAMPLES_DIR / "legitim_notification.eml"

        phish_report = analyze_email_file(phish_eml, use_virustotal=False)
        self.assertEqual(phish_report.risk_score, 100)
        self.assertIn("CRÍTICO", phish_report.classification)

        legit_report = analyze_email_file(legit_eml, use_virustotal=False)
        self.assertEqual(legit_report.risk_score, 0)
        self.assertIn("SEGURO", legit_report.classification)

    def test_virustotal_helpers(self) -> None:
        url_id = encode_vt_url_id("https://example.com/login")
        self.assertNotIn("=", url_id)

        vt_inds = parse_vt_stats_to_indicators(
            {"malicious": 5, "suspicious": 2, "harmless": 60, "undetected": 10},
            artifact_label="https://evil-phish.xyz",
        )
        self.assertEqual(len(vt_inds), 1)
        self.assertEqual(vt_inds[0].code, "VT_MALICIOUS_HIGH")

    def test_sqlite_persistence_and_stats(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_db = Path(tmpdir) / "test_history.db"
            init_db(temp_db)

            safe_report = analyze_single_url("https://github.com", use_virustotal=False)
            phish_report = analyze_email_file(SAMPLES_DIR / "phishing_urgente.eml", use_virustotal=False)

            id1 = save_scan_report(safe_report, db_path=temp_db)
            id2 = save_scan_report(phish_report, db_path=temp_db)
            self.assertGreater(id2, id1)

            recent = get_recent_scans(limit=10, db_path=temp_db)
            self.assertEqual(len(recent), 2)

            stats = get_scan_stats(db_path=temp_db)
            self.assertEqual(stats["total_scans"], 2)
            self.assertEqual(stats["safe_count"], 1)
            self.assertEqual(stats["critical_count"], 1)

            clear_scan_history(db_path=temp_db)
            self.assertEqual(get_scan_stats(db_path=temp_db)["total_scans"], 0)


if __name__ == "__main__":
    unittest.main()
