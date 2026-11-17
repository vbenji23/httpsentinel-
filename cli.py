"""Point d'entrée en ligne de commande."""

import argparse
import sys
from urllib.parse import urlparse

from httpsentinel import __version__
from httpsentinel.scanner import scan
from httpsentinel.report import to_terminal, to_json, to_html
from httpsentinel.findings import Severity


def _normalize_url(raw: str) -> str:
    if not urlparse(raw).scheme:
        return "https://" + raw
    return raw


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="httpsentinel",
        description="Scanner de sécurité web (reconnaissance passive).",
    )
    p.add_argument("url", help="URL de la cible (ex. https://exemple.fr)")
    p.add_argument("--json", metavar="FICHIER", help="exporter le rapport en JSON")
    p.add_argument("--html", metavar="FICHIER", help="exporter le rapport en HTML")
    p.add_argument("--insecure", action="store_true", help="ne pas vérifier le certificat TLS")
    p.add_argument("--timeout", type=float, default=10.0, help="délai par requête (s)")
    p.add_argument("--no-color", action="store_true", help="désactiver la couleur")
    p.add_argument("--version", action="version", version=f"httpsentinel {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    url = _normalize_url(args.url)

    print(f"Scan de {url} en cours...", file=sys.stderr)
    findings = scan(url, insecure=args.insecure, timeout=args.timeout)

    print(to_terminal(url, findings, color=not args.no_color))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(to_json(url, findings))
        print(f"\nRapport JSON écrit dans {args.json}", file=sys.stderr)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(url, findings))
        print(f"Rapport HTML écrit dans {args.html}", file=sys.stderr)

    # Code de sortie non nul si au moins un constat HIGH (utile en CI)
    has_high = any(f.severity == Severity.HIGH for f in findings)
    return 1 if has_high else 0


if __name__ == "__main__":
    sys.exit(main())
