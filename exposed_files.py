"""Test de chemins sensibles potentiellement exposés.

Uniquement des requêtes GET sur des chemins connus : aucune exploitation,
aucun contournement. C'est de la reconnaissance passive.
"""

from urllib.parse import urljoin

import requests

from httpsentinel.findings import Finding, Severity, ScanContext

# chemin -> (sévérité si trouvé, description)
SENSITIVE_PATHS = {
    ".git/HEAD": (Severity.HIGH, "Dépôt Git exposé : le code source peut être reconstitué."),
    ".env": (Severity.HIGH, "Fichier d'environnement exposé : secrets potentiels."),
    ".svn/entries": (Severity.HIGH, "Métadonnées SVN exposées."),
    "backup.zip": (Severity.HIGH, "Archive de sauvegarde accessible."),
    "config.php.bak": (Severity.HIGH, "Sauvegarde de configuration accessible."),
    "phpinfo.php": (Severity.MEDIUM, "phpinfo() expose la configuration du serveur."),
    ".htaccess": (Severity.MEDIUM, "Fichier .htaccess potentiellement lisible."),
    "robots.txt": (Severity.INFO, "robots.txt accessible (peut révéler des chemins)."),
    ".DS_Store": (Severity.LOW, ".DS_Store expose l'arborescence des fichiers."),
}

# Signatures de pages d'erreur déguisées en 200
_SOFT_404 = ("not found", "404", "introuvable", "page n'existe pas")


def _looks_present(resp) -> bool:
    if resp.status_code != 200:
        return False
    body = resp.text[:2048].lower()
    return not any(sig in body for sig in _SOFT_404)


def run(ctx: ScanContext) -> list:
    base = ctx.url if ctx.url.endswith("/") else ctx.url + "/"
    findings = []

    for path, (severity, desc) in SENSITIVE_PATHS.items():
        target = urljoin(base, path)
        try:
            resp = requests.get(
                target,
                timeout=ctx.timeout,
                verify=not ctx.insecure,
                allow_redirects=False,
            )
        except requests.RequestException:
            continue

        if _looks_present(resp):
            findings.append(
                Finding(
                    check="exposed_files",
                    title=f"Exposé : /{path}",
                    severity=severity,
                    detail=f"HTTP {resp.status_code} sur {target}",
                    recommendation=desc,
                )
            )

    if not findings:
        findings.append(
            Finding(
                check="exposed_files",
                title="Aucun fichier sensible trouvé",
                severity=Severity.OK,
                detail=f"{len(SENSITIVE_PATHS)} chemins testés.",
            )
        )
    return findings
