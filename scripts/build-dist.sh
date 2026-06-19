#!/usr/bin/env bash
# build-dist.sh — Compile et package SBOM Generator pour Linux
# Produit : dist/sbom_generator-VERSION-linux-ARCH.tar.gz
#
# Usage : ./scripts/build-dist.sh [VERSION]
#   VERSION : numéro de version (défaut: 1.0.0)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="${1:-1.0.0}"
ARCH="$(uname -m)"
DIST_NAME="sbom_generator-${VERSION}-linux-${ARCH}"
DIST_DIR="${PROJECT_DIR}/dist/${DIST_NAME}"
ARCHIVE="${PROJECT_DIR}/dist/${DIST_NAME}.tar.gz"

cd "$PROJECT_DIR"

# ── Vérification des outils ──────────────────────────────────────────────────
echo "╔══════════════════════════════════════════╗"
echo "║  SBOM Generator — Build distribution    ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Version : ${VERSION}"
echo "Arch    : ${ARCH}"
echo "Sortie  : dist/${DIST_NAME}.tar.gz"
echo ""

for tool in dart flutter tar; do
  if ! command -v "$tool" &>/dev/null; then
    echo "Erreur : '$tool' introuvable dans PATH." >&2
    exit 1
  fi
done

echo "Outils : dart $(dart --version 2>&1 | head -1 | awk '{print $4}') • $(flutter --version 2>&1 | head -1)"
echo ""

# ── Nettoyage ────────────────────────────────────────────────────────────────
rm -rf "$DIST_DIR"
mkdir -p "${DIST_DIR}/bin" "${DIST_DIR}/gui"

# ── CLI : dart compile exe ───────────────────────────────────────────────────
echo "▶ Compilation du CLI (dart compile exe)…"
dart compile exe bin/sbom_generator.dart -o "${DIST_DIR}/bin/sbom-generator" 2>&1 \
  | grep -v "^$" | sed 's/^/  /'
chmod +x "${DIST_DIR}/bin/sbom-generator"
CLI_SIZE=$(du -sh "${DIST_DIR}/bin/sbom-generator" | cut -f1)
echo "  ✓ sbom-generator (${CLI_SIZE})"
echo ""

# ── GUI : flutter build linux --release ─────────────────────────────────────
echo "▶ Build du GUI Flutter (release)…"
cd gui
flutter build linux --release 2>&1 \
  | grep -E "^\s*(✓|Building|error|warning|▶)" | sed 's/^/  /'
cp -r build/linux/x64/release/bundle/. "${DIST_DIR}/gui/"
chmod +x "${DIST_DIR}/gui/sbom_generator_gui"
cd "$PROJECT_DIR"
GUI_SIZE=$(du -sh "${DIST_DIR}/gui" | cut -f1)
echo "  ✓ sbom_generator_gui + libs (${GUI_SIZE})"
echo ""

# ── Ressources ───────────────────────────────────────────────────────────────
echo "▶ Ajout des ressources…"

# Icône SVG
if [[ -f "${PROJECT_DIR}/assets/sbom_generator.svg" ]]; then
  cp "${PROJECT_DIR}/assets/sbom_generator.svg" "${DIST_DIR}/gui/"
  echo "  ✓ sbom_generator.svg"
fi

# Fichier .desktop
cat > "${DIST_DIR}/gui/sbom_generator.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=SBOM Generator
GenericName=Générateur de SBOM
Comment=Génère des SBOM (CycloneDX, SPDX 2.3/3.0, JSON) depuis des listes de paquets RPM, Python, DEB ou archives
Exec=sbom-generator-gui
Icon=sbom_generator
Categories=System;Security;Utility;Development;
Keywords=sbom;rpm;spdx;cyclonedx;security;cve;python;deb;
Terminal=false
StartupNotify=true
DESKTOP
echo "  ✓ sbom_generator.desktop"

# Scripts install / uninstall
cp "${SCRIPT_DIR}/install.sh"   "${DIST_DIR}/"
cp "${SCRIPT_DIR}/uninstall.sh" "${DIST_DIR}/"
chmod +x "${DIST_DIR}/install.sh" "${DIST_DIR}/uninstall.sh"
echo "  ✓ install.sh / uninstall.sh"
echo ""

# ── Archive ──────────────────────────────────────────────────────────────────
echo "▶ Création de l'archive…"
tar czf "$ARCHIVE" -C "${PROJECT_DIR}/dist" "${DIST_NAME}"
TOTAL_SIZE=$(du -sh "$ARCHIVE" | cut -f1)
echo "  ✓ ${ARCHIVE} (${TOTAL_SIZE})"
echo ""

# ── Résumé ───────────────────────────────────────────────────────────────────
echo "✅ Distribution prête !"
echo ""
echo "  dist/${DIST_NAME}.tar.gz (${TOTAL_SIZE})"
echo ""
echo "Contenu :"
tar tf "$ARCHIVE" | sed 's/^/  /'
echo ""
echo "Pour installer sur la machine cible :"
echo "  tar xzf ${DIST_NAME}.tar.gz"
echo "  cd ${DIST_NAME}"
echo "  ./install.sh              # installation utilisateur (~/.local)"
echo "  sudo ./install.sh         # installation système (/usr/local)"
