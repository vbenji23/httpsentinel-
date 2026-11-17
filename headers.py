"""Analyse des en-têtes HTTP de sécurité."""

import requests

from httpsentinel.findings import Finding, Severity, ScanContext

# En-têtes attendus : nom -> (sévérité si absent, recommandation)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "Définir une CSP pour limiter les sources de scripts et réduire le risque XSS.",
    ),
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "Ajouter HSTS pour forcer le HTTPS (ex. max-age=31536000; includeSubDomains).",
    ),
    "X-Frame-Options": (
        Severity.LOW,
        "Positionner X-Frame-Options: DENY ou SAMEORIGIN contre le clickjacking.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Ajouter X-Content-Type-Options: nosniff pour bloquer le MIME-sniffing.",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Définir une Referrer-Policy (ex. strict-origin-when-cross-origin).",
    ),
    "Permissions-Policy": (
        Severity.INFO,
        "Restreindre les API navigateur via Permissions-Policy.",
    ),
}


def run(ctx: ScanContext) -> list:
    findings = []
    try:
        resp = requests.get(
            ctx.url,
            timeout=ctx.timeout,
            verify=not ctx.insecure,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return [
            Finding(
                check="headers",
                title="Requête HTTP échouée",
                severity=Severity.HIGH,
                detail=str(exc),
                recommendation="Vérifier que l'URL est accessible.",
            )
        ]

    headers = {k.lower(): v for k, v in resp.headers.items()}

    for name, (severity, reco) in SECURITY_HEADERS.items():
        if name.lower() in headers:
            findings.append(
                Finding(
                    check="headers",
                    title=f"{name} présent",
                    severity=Severity.OK,
                    detail=headers[name.lower()],
                )
            )
        else:
            findings.append(
                Finding(
                    check="headers",
                    title=f"{name} absent",
                    severity=severity,
                    recommendation=reco,
                )
            )
    return findings
