#!/usr/bin/env bash
# build-dist.sh — Compile et package SBOM Generator pour Linux
# Produit : dist/sbom_generator-VERSION-linux-ARCH.tar.gz
#           dist/rpmbuild/RPMS/  (avec --rpm)
#
# Usage : ./scripts/build-dist.sh [VERSION] [--rpm]
#   VERSION : numéro de version (défaut: 1.1.0)
#   --rpm   : génère également les paquets RPM (nécessite rpm-build)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VERSION="1.1.0"
BUILD_RPM=false

for _arg in "$@"; do
  case "$_arg" in
    --rpm)     BUILD_RPM=true ;;
    --help|-h)
      echo "Usage: $0 [VERSION] [--rpm]"
      echo "  VERSION  numéro de version (défaut: 1.1.0)"
      echo "  --rpm    génère les RPMs en plus du tar.gz (nécessite rpm-build)"
      exit 0 ;;
    -*)        echo "Option inconnue : $_arg" >&2; exit 1 ;;
    *)         VERSION="$_arg" ;;
  esac
done
unset _arg

ARCH="$(uname -m)"
DIST_NAME="sbom_generator-${VERSION}-linux-${ARCH}"
DIST_DIR="${PROJECT_DIR}/dist/${DIST_NAME}"
ARCHIVE="${PROJECT_DIR}/dist/${DIST_NAME}.tar.gz"

cd "$PROJECT_DIR"

# ── Vérification des outils ──────────────────────────────────────────────────
echo "╔══════════════════════════════════════════╗"
echo "║  SBOM Generator — Build distribution     ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Version : ${VERSION}"
echo "Arch    : ${ARCH}"
echo "Sortie  : dist/${DIST_NAME}.tar.gz"
[[ "$BUILD_RPM" == true ]] && echo "RPM     : oui (dist/rpmbuild/RPMS/)"
echo ""

_required_tools=(dart flutter tar)
[[ "$BUILD_RPM" == true ]] && _required_tools+=(rpmbuild)
for tool in "${_required_tools[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    echo "Erreur : '$tool' introuvable dans PATH." >&2
    [[ "$tool" == "rpmbuild" ]] && echo "  Installez : sudo dnf install rpm-build" >&2
    exit 1
  fi
done
unset _required_tools

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

# ── RPM (optionnel) ──────────────────────────────────────────────────────────
if [[ "$BUILD_RPM" == true ]]; then
  echo "▶ Génération des RPMs…"

  RPM_TOPDIR="${PROJECT_DIR}/dist/rpmbuild"
  mkdir -p "${RPM_TOPDIR}"/{SPECS,SOURCES,BUILD,RPMS,SRPMS}

  # L'archive source doit être dans SOURCES/ avec le nom attendu par le spec
  cp "$ARCHIVE" "${RPM_TOPDIR}/SOURCES/${DIST_NAME}.tar.gz"
  cp "${SCRIPT_DIR}/sbom_generator.spec" "${RPM_TOPDIR}/SPECS/"

  rpmbuild -ba \
    --define "_topdir ${RPM_TOPDIR}" \
    --define "version ${VERSION}" \
    "${RPM_TOPDIR}/SPECS/sbom_generator.spec" 2>&1 \
    | grep -E "^(Wrote|erreur|error:|warning:|Erreurs)" | sed 's/^/  /' || true

  echo ""
  RPM_COUNT=0
  while IFS= read -r rpm_file; do
    RPM_SIZE=$(du -sh "$rpm_file" | cut -f1)
    echo "  ✓ $(realpath --relative-to="${PROJECT_DIR}" "$rpm_file") (${RPM_SIZE})"
    RPM_COUNT=$((RPM_COUNT + 1))
  done < <(find "${RPM_TOPDIR}/RPMS" -name "*.rpm" | sort)

  if [[ "$RPM_COUNT" -eq 0 ]]; then
    echo "  ⚠  Aucun RPM produit — vérifiez les logs rpmbuild ci-dessus." >&2
  fi
  echo ""
fi

# ── Résumé ───────────────────────────────────────────────────────────────────
echo "✅ Distribution prête !"
echo ""
echo "  dist/${DIST_NAME}.tar.gz (${TOTAL_SIZE})"
if [[ "$BUILD_RPM" == true ]]; then
  find "${PROJECT_DIR}/dist/rpmbuild/RPMS" -name "*.rpm" 2>/dev/null | sort \
    | while IFS= read -r r; do echo "  $(realpath --relative-to="${PROJECT_DIR}" "$r")"; done
fi
echo ""
echo "Contenu de l'archive :"
tar tf "$ARCHIVE" | sed 's/^/  /'
echo ""
echo "Pour installer sur la machine cible :"
echo "  tar xzf ${DIST_NAME}.tar.gz"
echo "  cd ${DIST_NAME}"
echo "  ./install.sh              # installation utilisateur (~/.local)"
echo "  sudo ./install.sh         # installation système (/usr/local)"
if [[ "$BUILD_RPM" == true ]]; then
  echo ""
  echo "Installation via RPM :"
  echo "  sudo dnf install dist/rpmbuild/RPMS/${ARCH}/sbom-generator-${VERSION}-1.*.rpm"
  echo "  sudo dnf install dist/rpmbuild/RPMS/${ARCH}/sbom-generator-gui-${VERSION}-1.*.rpm"
fi
