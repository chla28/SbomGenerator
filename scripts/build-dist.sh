#!/usr/bin/env bash
# build-dist.sh — Compile et package SBOM Generator pour Linux
# Produit : dist/sbom_generator-VERSION-linux-ARCH.tar.gz
#             (inclut un SBOM CycloneDX : dépendances runtime distro + arbre
#              des dépendances Dart/Flutter — sbom.cdx.json)
#           dist/sbom_generator-VERSION-linux-ARCH-scan-report.pdf
#             (rapport de synthèse CVE Grype + OSV-Scanner + Trivy du SBOM
#              ci-dessus ; à côté de l'archive — instantané daté, best-effort :
#              produit seulement si au moins un scanner est installé)
#           dist/rpmbuild/RPMS/  (avec --rpm)
#             + dist/sbom_generator-VERSION-linux-ARCH-rpms.cdx.json
#               (SBOM CycloneDX des RPM produits ; à côté, pas dans l'archive,
#               car les RPM sont construits à partir de l'archive elle-même)
#             + dist/sbom_generator-VERSION-linux-ARCH-rpms-scan-report.pdf
#
# Le SBOM est généré avec le binaire sbom-generator tout juste compilé par ce
# script (auto-hébergement : pas de dépendance à une installation préalable
# sur la machine de build, et garantit que la version décrite dans le SBOM
# est bien celle en cours de packaging).
#
# Usage : ./scripts/build-dist.sh [VERSION] [--rpm]
#   VERSION : numéro de version (défaut : champ `version:` de pubspec.yaml)
#   --rpm   : génère également les paquets RPM (nécessite rpm-build)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Version par défaut : celle du code (pubspec.yaml), pour qu'elle ne dérive
# jamais du binaire réellement packagé. Surchargée par l'argument positionnel.
VERSION="$(sed -n 's/^version:[[:space:]]*//p' "$PROJECT_DIR/pubspec.yaml" \
  | head -1 | tr -d '[:space:]')"
: "${VERSION:?impossible de lire la version depuis pubspec.yaml}"
BUILD_RPM=false

for _arg in "$@"; do
  case "$_arg" in
    --rpm)     BUILD_RPM=true ;;
    --help|-h)
      echo "Usage: $0 [VERSION] [--rpm]"
      echo "  VERSION  numéro de version (défaut : version de pubspec.yaml,"
      echo "           actuellement ${VERSION})"
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

# Scanne un SBOM avec Grype + OSV-Scanner + Trivy (best-effort : chaque
# scanner absent est simplement omis) et produit un PDF de synthèse via
# `sbom-generator scan -f pdf`. Le PDF est déposé À CÔTÉ de l'archive dans
# dist/ (instantané CVE daté, pas un livrable figé). N'échoue jamais le
# build : si aucun scanner ni asciidoctor-pdf n'est disponible, on saute.
#   $1 = chemin du SBOM      $2 = chemin du PDF de sortie
run_scan_report() {
  local sbom="$1" pdf="$2"
  if [[ ! -f "$sbom" ]]; then
    echo "  ⚠  SBOM introuvable ($sbom) — scan sauté." >&2
    return 0
  fi
  if ! command -v grype &>/dev/null \
     && ! command -v osv-scanner &>/dev/null \
     && ! command -v trivy &>/dev/null; then
    echo "  ⚠  Aucun scanner (grype / osv-scanner / trivy) — scan sauté." >&2
    return 0
  fi
  # `scan -f pdf` sort 0 dès qu'un rapport est produit (même avec des CVE) ;
  # si asciidoctor-pdf manque, le .adoc est conservé à côté. Il liste au
  # passage chaque CVE Critical (rouge) / High (orange) sur stdout : on force
  # la couleur si le terminal du build la supporte (le `sed` la préserve).
  local color=never
  [[ -t 1 && -z "${NO_COLOR:-}" ]] && color=always
  if "${DIST_DIR}/bin/sbom-generator" scan \
       --sbom "$sbom" --scanner all --format pdf --output "$pdf" \
       --color "$color" 2>&1 | sed 's/^/  /'; then
    [[ -f "$pdf" ]] && echo "  ✓ $(realpath --relative-to="${PROJECT_DIR}" "$pdf")"
  else
    echo "  ⚠  Échec du scan CVE — le packaging continue sans rapport." >&2
  fi
}

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
# `flutter clean` d'abord : le cache CMake de gui/build/ mémorise le chemin
# absolu du projet et fait échouer le build si l'arborescence a été déplacée
# ou clonée ailleurs ("CMakeCache.txt directory ... is different").
flutter clean 2>&1 | sed 's/^/  /'
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

# SBOM (CycloneDX) : dépendances runtime distro du GUI, alignées sur les
# `Requires` du sous-paquet gui dans sbom_generator.spec (branche moderne
# gtk4/libsecret — Fedora 44, RHEL 9/10, les seules cibles couvertes par
# build-rpm-mock.sh) + arbre des dépendances Dart/Flutter (tous les
# pubspec.lock du projet : CLI à la racine, GUI dans gui/). Généré avec le
# binaire tout juste compilé ci-dessus (pas un `sbom-generator` du PATH) :
# la version packagée s'auto-décrit elle-même, sans dépendre d'une
# installation préalable sur la machine de build.
SBOM_INPUT="$(mktemp)"
cat > "$SBOM_INPUT" <<'PKGS'
fontconfig
mesa-libGL
gtk4
libsecret
PKGS
find "$PROJECT_DIR" -name pubspec.lock \
  -not -path '*/build/*' -not -path '*/.dart_tool/*' | sort >> "$SBOM_INPUT"

# Les paquets `source: sdk` d'un pubspec.lock (flutter, sky_engine…) sont notés
# "0.0.0" par pub : on injecte la vraie version des SDK utilisés pour ce build.
# `--flutter-root` sert en plus à lire le LICENSE de ces paquets ; le cache pub
# (rempli par le `flutter build` ci-dessus) est auto-détecté par le CLI et
# fournit les licences de tous les autres paquets pub.
SDK_ARGS=()
_flutter_ver="$(flutter --version 2>/dev/null \
  | grep -oiE 'flutter[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
  | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
[[ -n "$_flutter_ver" ]] && SDK_ARGS+=(--sdk-version "flutter=$_flutter_ver")
_dart_ver="$(dart --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
[[ -n "$_dart_ver" ]] && SDK_ARGS+=(--sdk-version "dart=$_dart_ver")
_flutter_bin="$(command -v flutter || true)"
if [[ -n "$_flutter_bin" ]]; then
  _flutter_root="$(dirname "$(dirname "$(readlink -f "$_flutter_bin")")")"
  [[ -d "$_flutter_root/packages/flutter" ]] \
    && SDK_ARGS+=(--flutter-root "$_flutter_root")
fi
[[ ${#SDK_ARGS[@]} -gt 0 ]] && echo "  SDK : ${SDK_ARGS[*]}"

if "${DIST_DIR}/bin/sbom-generator" -i "$SBOM_INPUT" -f cyclonedx \
     -o "${DIST_DIR}/sbom.cdx.json" \
     -n "${DIST_NAME}-sbom" ${SDK_ARGS[@]+"${SDK_ARGS[@]}"} 2>&1 | sed 's/^/  /'; then
  echo "  ✓ sbom.cdx.json (SBOM CycloneDX : deps runtime + arbre pub)"
else
  echo "  ⚠  Échec de la génération du SBOM — le packaging continue sans." >&2
fi
rm -f "$SBOM_INPUT"
unset _flutter_ver _dart_ver _flutter_bin _flutter_root
echo ""

# ── Scan CVE du SBOM + PDF de synthèse ───────────────────────────────────────
echo "▶ Scan CVE du SBOM (Grype + OSV-Scanner + Trivy)…"
SCAN_PDF="${PROJECT_DIR}/dist/${DIST_NAME}-scan-report.pdf"
run_scan_report "${DIST_DIR}/sbom.cdx.json" "$SCAN_PDF"
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

  # SBOM (CycloneDX) des RPM effectivement construits — décrit précisément
  # l'artefact livré (nom, version, licence). Ne peut pas être inclus dans
  # l'archive tar.gz : les RPM sont construits à partir de cette archive,
  # donc placé à côté, dans dist/.
  if [[ "$RPM_COUNT" -gt 0 ]]; then
    echo "▶ Génération du SBOM des RPM construits…"
    RPM_SBOM="${PROJECT_DIR}/dist/${DIST_NAME}-rpms.cdx.json"
    RPM_LIST="$(mktemp)"
    find "${RPM_TOPDIR}/RPMS" -name "*.rpm" | sort > "$RPM_LIST"
    if "${DIST_DIR}/bin/sbom-generator" -i "$RPM_LIST" -f cyclonedx \
         -o "$RPM_SBOM" -n "${DIST_NAME}-rpms" 2>&1 \
         | sed 's/^/  /'; then
      echo "  ✓ $(realpath --relative-to="${PROJECT_DIR}" "$RPM_SBOM")"
    else
      echo "  ⚠  Échec de la génération du SBOM RPM — le packaging continue sans." >&2
    fi
    rm -f "$RPM_LIST"
    echo ""

    echo "▶ Scan CVE du SBOM des RPM construits…"
    run_scan_report "$RPM_SBOM" \
      "${PROJECT_DIR}/dist/${DIST_NAME}-rpms-scan-report.pdf"
    echo ""
  fi
fi

# ── Résumé ───────────────────────────────────────────────────────────────────
echo "✅ Distribution prête !"
echo ""
echo "  dist/${DIST_NAME}.tar.gz (${TOTAL_SIZE})"
if [[ -f "${DIST_DIR}/sbom.cdx.json" ]]; then
  echo "    └─ inclut sbom.cdx.json (SBOM CycloneDX : deps runtime + arbre pub)"
fi
if [[ -f "$SCAN_PDF" ]]; then
  echo "  dist/${DIST_NAME}-scan-report.pdf (synthèse CVE Grype + OSV-Scanner + Trivy)"
elif [[ -f "${SCAN_PDF%.pdf}.adoc" ]]; then
  echo "  dist/${DIST_NAME}-scan-report.adoc (synthèse CVE — PDF non généré, asciidoctor-pdf absent)"
fi
if [[ "$BUILD_RPM" == true ]]; then
  find "${PROJECT_DIR}/dist/rpmbuild/RPMS" -name "*.rpm" 2>/dev/null | sort \
    | while IFS= read -r r; do echo "  $(realpath --relative-to="${PROJECT_DIR}" "$r")"; done
  if [[ -f "${PROJECT_DIR}/dist/${DIST_NAME}-rpms.cdx.json" ]]; then
    echo "  dist/${DIST_NAME}-rpms.cdx.json (SBOM CycloneDX des RPM ci-dessus)"
  fi
  if [[ -f "${PROJECT_DIR}/dist/${DIST_NAME}-rpms-scan-report.pdf" ]]; then
    echo "  dist/${DIST_NAME}-rpms-scan-report.pdf (synthèse CVE des RPM ci-dessus)"
  fi
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
