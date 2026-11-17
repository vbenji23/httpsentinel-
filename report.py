"""Mise en forme des rapports : terminal, JSON, HTML."""

import html
import json

from httpsentinel.findings import Severity

# Codes couleur ANSI par sévérité
_COLORS = {
    Severity.HIGH: "\033[91m",    # rouge
    Severity.MEDIUM: "\033[93m",  # jaune
    Severity.LOW: "\033[96m",     # cyan
    Severity.INFO: "\033[90m",    # gris
    Severity.OK: "\033[92m",      # vert
}
_RESET = "\033[0m"


def _sorted(findings):
    return sorted(findings, key=lambda f: f.severity.rank)


def to_terminal(url: str, findings: list, color: bool = True) -> str:
    lines = [f"\nhttpsentinel — rapport pour {url}", "=" * 60]
    for f in _sorted(findings):
        tag = f"[{f.severity.value:^6}]"
        if color:
            tag = f"{_COLORS[f.severity]}{tag}{_RESET}"
        lines.append(f"{tag} {f.title}")
        if f.detail:
            lines.append(f"         ↳ {f.detail}")
        if f.recommendation:
            lines.append(f"         → {f.recommendation}")
    lines.append("=" * 60)
    lines.append(_summary_line(findings))
    return "\n".join(lines)


def _summary_line(findings) -> str:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    return (
        f"Bilan : {counts[Severity.HIGH]} HIGH · {counts[Severity.MEDIUM]} MEDIUM · "
        f"{counts[Severity.LOW]} LOW · {counts[Severity.INFO]} INFO · {counts[Severity.OK]} OK"
    )


def to_json(url: str, findings: list) -> str:
    payload = {
        "target": url,
        "findings": [f.to_dict() for f in _sorted(findings)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_html(url: str, findings: list) -> str:
    rows = []
    for f in _sorted(findings):
        rows.append(
            "<tr class='{sev}'><td>{sev}</td><td>{title}</td>"
            "<td>{detail}</td><td>{reco}</td></tr>".format(
                sev=f.severity.value,
                title=html.escape(f.title),
                detail=html.escape(f.detail),
                reco=html.escape(f.recommendation),
            )
        )
    return _HTML_TEMPLATE.format(
        url=html.escape(url),
        summary=html.escape(_summary_line(findings)),
        rows="\n".join(rows),
    )


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>httpsentinel — {url}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
  h1 {{ font-size: 1.4rem; }}
  .summary {{ margin: 1rem 0; font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #ddd; vertical-align: top; }}
  th {{ background: #f4f4f4; }}
  tr.HIGH td:first-child {{ color: #c0392b; font-weight: 700; }}
  tr.MEDIUM td:first-child {{ color: #d68910; font-weight: 700; }}
  tr.LOW td:first-child {{ color: #148f77; }}
  tr.INFO td:first-child {{ color: #7f8c8d; }}
  tr.OK td:first-child {{ color: #27ae60; }}
</style>
</head>
<body>
<h1>🛡️ httpsentinel — {url}</h1>
<div class="summary">{summary}</div>
<table>
<thead><tr><th>Sévérité</th><th>Constat</th><th>Détail</th><th>Recommandation</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""
