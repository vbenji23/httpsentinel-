"""Orchestrateur : exécute tous les checks et agrège les résultats."""

from httpsentinel.findings import ScanContext
from httpsentinel.checks import headers, tls, fingerprint, exposed_files

CHECKS = [headers, tls, fingerprint, exposed_files]


def scan(url: str, insecure: bool = False, timeout: float = 10.0) -> list:
    """Lance tous les checks sur `url` et renvoie la liste complète des findings."""
    ctx = ScanContext(url=url, insecure=insecure, timeout=timeout)
    results = []
    for check in CHECKS:
        results.extend(check.run(ctx))
    return results
