"""Identification du serveur et des technologies via les en-têtes de réponse."""

import requests

from httpsentinel.findings import Finding, Severity, ScanContext

# Indices de cookies -> technologie probable
COOKIE_HINTS = {
    "phpsessid": "PHP",
    "wordpress_": "WordPress",
    "wp-settings": "WordPress",
    "laravel_session": "Laravel",
    "csrftoken": "Django",
    "jsessionid": "Java (serveur d'applications)",
    "asp.net": "ASP.NET",
}


def run(ctx: ScanContext) -> list:
    try:
        resp = requests.get(ctx.url, timeout=ctx.timeout, verify=not ctx.insecure)
    except requests.RequestException as exc:
        return [
            Finding(
                check="fingerprint",
                title="Fingerprinting impossible",
                severity=Severity.INFO,
                detail=str(exc),
            )
        ]

    findings = []
    headers = {k.lower(): v for k, v in resp.headers.items()}

    server = headers.get("server")
    if server:
        findings.append(
            Finding(
                check="fingerprint",
                title=f"Serveur : {server}",
                severity=Severity.INFO,
                recommendation="Masquer la bannière détaillée pour limiter la fuite d'information.",
            )
        )

    powered = headers.get("x-powered-by")
    if powered:
        findings.append(
            Finding(
                check="fingerprint",
                title=f"X-Powered-By : {powered}",
                severity=Severity.LOW,
                recommendation="Supprimer l'en-tête X-Powered-By.",
            )
        )

    # Technologies devinées via les cookies
    cookie_blob = resp.headers.get("set-cookie", "").lower()
    detected = {tech for hint, tech in COOKIE_HINTS.items() if hint in cookie_blob}
    for tech in sorted(detected):
        findings.append(
            Finding(
                check="fingerprint",
                title=f"Technologie probable : {tech}",
                severity=Severity.INFO,
            )
        )

    if not findings:
        findings.append(
            Finding(
                check="fingerprint",
                title="Aucune techno identifiée via les en-têtes",
                severity=Severity.OK,
            )
        )
    return findings
