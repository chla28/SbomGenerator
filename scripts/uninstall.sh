#!/usr/bin/env bash
# uninstall.sh — Désinstallateur de SBOM Generator
set -euo pipefail

APP_NAME="sbom_generator"

# ── Détection du mode ────────────────────────────────────────────────────────
FORCE_SYSTEM=false
CUSTOM_PREFIX=""

for arg in "$@"; do
  case "$arg" in
    --system)   FORCE_SYSTEM=true ;;
    --prefix=*) CUSTOM_PREFIX="${arg#--prefix=}" ;;
    --help|-h)
      echo "Usage: $0 [--system] [--prefix=DIR]"
      exit 0 ;;
  esac
done

if [[ -n "$CUSTOM_PREFIX" ]]; then
  PREFIX="$CUSTOM_PREFIX"
  SYSTEM_INSTALL=false
elif [[ "$FORCE_SYSTEM" == true ]] || [[ $EUID -eq 0 ]]; then
  PREFIX="/usr/local"
  SYSTEM_INSTALL=true
else
  PREFIX="${HOME}/.local"
  SYSTEM_INSTALL=false
fi

GUI_DIR="${PREFIX}/lib/${APP_NAME}"
BIN_DIR="${PREFIX}/bin"
ICON_DIR="${HOME}/.local/share/icons/hicolor"
DESKTOP_DIR="${HOME}/.local/share/applications"

if [[ "$SYSTEM_INSTALL" == true ]]; then
  ICON_DIR="/usr/share/icons/hicolor"
  DESKTOP_DIR="/usr/share/applications"
fi

echo "╔══════════════════════════════════════╗"
echo "║  SBOM Generator — Désinstallation   ║"
echo "╚══════════════════════════════════════╝"
echo ""

_remove() {
  local target="$1"
  if [[ -e "$target" || -L "$target" ]]; then
    rm -rf "$target"
    echo "  ✓ supprimé : $target"
  fi
}

_remove "${BIN_DIR}/sbom-generator"
_remove "${BIN_DIR}/sbom-generator-gui"
_remove "${GUI_DIR}"
_remove "${ICON_DIR}/scalable/apps/sbom_generator.svg"
_remove "${DESKTOP_DIR}/sbom_generator.desktop"

command -v update-desktop-database &>/dev/null \
  && update-desktop-database "${DESKTOP_DIR}" 2>/dev/null || true
command -v gtk-update-icon-cache &>/dev/null \
  && gtk-update-icon-cache -qf "${ICON_DIR}" 2>/dev/null || true

echo ""
echo "✅ SBOM Generator désinstallé."
