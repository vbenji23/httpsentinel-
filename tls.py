"""Inspection du certificat TLS et de la version négociée."""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from httpsentinel.findings import Finding, Severity, ScanContext

EXPIRY_WARNING_DAYS = 30


def run(ctx: ScanContext) -> list:
    parsed = urlparse(ctx.url)
    if parsed.scheme != "https":
        return [
            Finding(
                check="tls",
                title="Pas de HTTPS",
                severity=Severity.HIGH,
                detail=f"Schéma détecté : {parsed.scheme}",
                recommendation="Servir le site en HTTPS avec un certificat valide.",
            )
        ]

    host = parsed.hostname
    port = parsed.port or 443
    findings = []

    context = ssl.create_default_context()
    if ctx.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=ctx.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cert = ssock.getpeercert()
    except (ssl.SSLError, socket.error) as exc:
        return [
            Finding(
                check="tls",
                title="Connexion TLS échouée",
                severity=Severity.HIGH,
                detail=str(exc),
                recommendation="Vérifier le certificat et la configuration TLS du serveur.",
            )
        ]

    # Version TLS
    old = version in ("TLSv1", "TLSv1.1", "SSLv3")
    findings.append(
        Finding(
            check="tls",
            title=f"Version TLS : {version}",
            severity=Severity.MEDIUM if old else Severity.OK,
            recommendation="Désactiver les versions < TLS 1.2." if old else "",
        )
    )

    # Expiration du certificat
    if cert and "notAfter" in cert:
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_left = (expires - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "inconnu")

        if days_left < 0:
            sev, reco = Severity.HIGH, "Certificat expiré : le renouveler immédiatement."
        elif days_left < EXPIRY_WARNING_DAYS:
            sev, reco = Severity.MEDIUM, "Renouveler le certificat prochainement."
        else:
            sev, reco = Severity.OK, ""

        findings.append(
            Finding(
                check="tls",
                title=f"Certificat valable {days_left} jour(s)",
                severity=sev,
                detail=f"Émetteur : {issuer} — expire le {expires:%Y-%m-%d}",
                recommendation=reco,
            )
        )
    elif ctx.insecure:
        findings.append(
            Finding(
                check="tls",
                title="Certificat non vérifié (--insecure)",
                severity=Severity.INFO,
            )
        )

    return findings
