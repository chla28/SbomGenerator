# Politique de sécurité / Security policy

🇫🇷 [Français](#français) · 🇬🇧 [English](#english)

## Français

### Versions prises en charge

Seule la dernière version publiée (tag `vX.Y.Z` le plus récent) reçoit des correctifs de sécurité.

### Signaler une vulnérabilité

**Ne créez pas d'issue publique** pour un problème de sécurité. Utilisez le signalement privé de GitHub : onglet *Security* → *Report a vulnerability* du dépôt (`chla28/SbomGenerator`).

Merci d'indiquer : la version concernée (`sbom-generator --version`), le système, les étapes pour reproduire, et l'impact estimé. Un accusé de réception est visé sous 7 jours ; un correctif ou un plan de correction sous 90 jours, selon la gravité. Le signalement est ensuite divulgué de façon coordonnée, avec mention du rapporteur s'il le souhaite.

### Périmètre

Dans le périmètre : l'analyse de fichiers non fiables (archives tar/zip/jar/wheel/rpm/deb, lockfiles, images OCI, binaires) — extraction hors du dossier prévu, écrasement de fichiers, exécution de commandes, consommation de ressources non bornée — ainsi que le lancement des outils externes (`rpm`, `python3`, `syft`, `grype`, `trivy`, `osv-scanner`, `sbomqs`, `asciidoctor-pdf`) par le CLI et la GUI.

Hors périmètre : les vulnérabilités des outils externes eux-mêmes (à signaler à leurs projets) et le contenu des bases de vulnérabilités qu'ils interrogent.

## English

### Supported versions

Only the latest published release (most recent `vX.Y.Z` tag) receives security fixes.

### Reporting a vulnerability

**Do not open a public issue** for a security problem. Use GitHub private reporting: *Security* tab → *Report a vulnerability* of the repository (`chla28/SbomGenerator`).

Please include: the affected version (`sbom-generator --version`), the system, steps to reproduce, and the estimated impact. We aim to acknowledge within 7 days and to provide a fix or a remediation plan within 90 days, depending on severity. The report is then disclosed in a coordinated way, crediting the reporter if desired.

### Scope

In scope: analysis of untrusted inputs (tar/zip/jar/wheel/rpm/deb archives, lockfiles, OCI images, binaries) — extraction outside the intended folder, file overwrite, command execution, unbounded resource consumption — and the launching of external tools (`rpm`, `python3`, `syft`, `grype`, `trivy`, `osv-scanner`, `sbomqs`, `asciidoctor-pdf`) by the CLI and the GUI.

Out of scope: vulnerabilities of the external tools themselves (report them to their projects) and the content of the vulnerability databases they query.
