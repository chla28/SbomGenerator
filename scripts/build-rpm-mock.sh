#!/usr/bin/env bash
# build-rpm-mock.sh — Construit les RPM sbom-generator (CLI) et sbom-generator-gui
# pour Fedora Linux 44, RHEL 9 et RHEL 10, via mock, à partir du spec existant
# (scripts/sbom_generator.spec, non modifié).
#
# RHEL 9/10 n'ont pas de dépôts publics sans souscription Red Hat : les chroots
# utilisent CentOS Stream 9/10 comme upstream libre, binairement très proche
# (dist tag produit : .el9 / .el10, comme pour un vrai RHEL).
#
# Usage : ./scripts/build-rpm-mock.sh [VERSION] [--targets=fedora44,el9,el10] [--arch=x86_64]
#   VERSION    numéro de version (défaut : 1.1.0)
#   --targets  sous-ensemble de cibles à construire (défaut : les trois)
#   --arch     architecture cible (défaut : celle de la machine hôte)
#
# Prérequis : mock + mock-core-configs installés, utilisateur dans le groupe
# "mock" (sudo dnf install mock mock-core-configs ; sudo usermod -aG mock $USER
# ; se reconnecter). Si la configuration mock d'une cible n'existe pas encore
# (ex. Fedora très récente pas encore packagée dans mock-core-configs), voir
# le message d'erreur affiché pour la corriger.
#
# Sortie : dist/rpmbuild-<cible>/RPMS/ (un dossier par cible), en complément
# de dist/rpmbuild/ déjà utilisé par build-dist.sh --rpm (build local, non
# ciblé). Ce script ne modifie ni build-dist.sh, ni sbom_generator.spec, ni
# install.sh/uninstall.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VERSION="1.1.0"
ARCH="$(uname -m)"
TARGETS="fedora44,el9,el10"

for _arg in "$@"; do
  case "$_arg" in
    --targets=*) TARGETS="${_arg#--targets=}" ;;
    --arch=*)    ARCH="${_arg#--arch=}" ;;
    --help|-h)
      echo "Usage: $0 [VERSION] [--targets=fedora44,el9,el10] [--arch=x86_64]"
      echo "  VERSION    numéro de version (défaut: 1.1.0)"
      echo "  --targets  sous-ensemble de cibles, virgule-séparé (défaut: les trois)"
      echo "  --arch     architecture cible (défaut: $(uname -m))"
      exit 0 ;;
    -*) echo "Option inconnue : $_arg" >&2; exit 1 ;;
    *)  VERSION="$_arg" ;;
  esac
done
unset _arg

declare -A MOCK_CONFIG=(
  [fedora44]="fedora-44-${ARCH}"
  [el9]="centos-stream-9-${ARCH}"
  [el10]="centos-stream-10-${ARCH}"
)
declare -A TARGET_LABEL=(
  [fedora44]="Fedora Linux 44"
  [el9]="RHEL 9 (chroot CentOS Stream 9)"
  [el10]="RHEL 10 (chroot CentOS Stream 10)"
)

cd "$PROJECT_DIR"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  SBOM Generator — Build RPM multi-cibles (mock)           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Version : ${VERSION}"
echo "Arch    : ${ARCH}"
echo "Cibles  : ${TARGETS}"
echo ""

# ── Vérification des outils ──────────────────────────────────────────────────
if ! command -v mock &>/dev/null; then
  echo "Erreur : 'mock' introuvable dans PATH." >&2
  echo "  Installez : sudo dnf install mock mock-core-configs" >&2
  echo "  Puis      : sudo usermod -aG mock \$USER   (puis se reconnecter)" >&2
  exit 1
fi

IFS=',' read -ra TARGET_LIST <<< "$TARGETS"
for target in "${TARGET_LIST[@]}"; do
  if [[ -z "${MOCK_CONFIG[$target]:-}" ]]; then
    echo "Erreur : cible inconnue '$target' (attendu : fedora44, el9, el10)." >&2
    exit 1
  fi
  config="${MOCK_CONFIG[$target]}"
  if [[ ! -f "/etc/mock/${config}.cfg" ]]; then
    echo "Erreur : configuration mock '${config}' introuvable (/etc/mock/${config}.cfg)." >&2
    echo "  mock-core-configs ne l'inclut peut-être pas encore pour cette version." >&2
    echo "  Listez les configs disponibles : mock --list-chroots" >&2
    echo "  Ou créez /etc/mock/${config}.cfg à partir d'une config existante proche." >&2
    exit 1
  fi
done

# ── Archive source (réutilise build-dist.sh, non modifié) ────────────────────
DIST_NAME="sbom_generator-${VERSION}-linux-${ARCH}"
ARCHIVE="${PROJECT_DIR}/dist/${DIST_NAME}.tar.gz"

if [[ ! -f "$ARCHIVE" ]]; then
  echo "▶ Archive source absente, construction via build-dist.sh…"
  "${SCRIPT_DIR}/build-dist.sh" "$VERSION"
  echo ""
else
  echo "▶ Archive source déjà présente : $(realpath --relative-to="$PROJECT_DIR" "$ARCHIVE")"
  echo ""
fi

SOURCES_DIR="${PROJECT_DIR}/dist/rpm-sources"
mkdir -p "$SOURCES_DIR"
cp "$ARCHIVE" "$SOURCES_DIR/"

# ── Construction par cible ────────────────────────────────────────────────────
declare -a ALL_RPMS=()

for target in "${TARGET_LIST[@]}"; do
  config="${MOCK_CONFIG[$target]}"
  label="${TARGET_LABEL[$target]}"
  RESULT_DIR="${PROJECT_DIR}/dist/rpmbuild-${target}"

  echo "▶ ${label} (mock root: ${config})…"
  rm -rf "$RESULT_DIR"
  mkdir -p "${RESULT_DIR}/SRPMS" "${RESULT_DIR}/RPMS"

  echo "  … construction du SRPM"
  mock --root "$config" --resultdir "${RESULT_DIR}/SRPMS" \
       --buildsrpm --spec "${SCRIPT_DIR}/sbom_generator.spec" \
       --sources "$SOURCES_DIR" \
       --define "version ${VERSION}" \
       --quiet

  srpm="$(find "${RESULT_DIR}/SRPMS" -maxdepth 1 -name '*.src.rpm' | head -1)"
  if [[ -z "$srpm" ]]; then
    echo "  ✗ Échec de construction du SRPM pour ${label}." >&2
    exit 1
  fi

  echo "  … construction des RPM binaires (CLI + GUI)"
  # --define doit être répété ici : --rebuild ré-analyse en interne le texte
  # brut du spec extrait du .src.rpm (Version: %{version} n'y est jamais
  # pré-résolu), sans hériter du --define passé à l'étape --buildsrpm.
  mock --root "$config" --resultdir "${RESULT_DIR}/RPMS" \
       --rebuild "$srpm" \
       --define "version ${VERSION}" \
       --quiet

  echo "  ✓ RPM produits :"
  while IFS= read -r rpm; do
    size=$(du -sh "$rpm" | cut -f1)
    rel="$(realpath --relative-to="$PROJECT_DIR" "$rpm")"
    echo "      ${rel} (${size})"
    ALL_RPMS+=("$rel")
  done < <(find "${RESULT_DIR}/RPMS" -maxdepth 1 -name '*.rpm' ! -name '*.src.rpm' | sort)
  echo ""
done

# ── Résumé ───────────────────────────────────────────────────────────────────
echo "✅ Construction terminée pour : ${TARGETS}"
echo ""
echo "RPM produits (${#ALL_RPMS[@]}) :"
for rpm in "${ALL_RPMS[@]}"; do
  echo "  ${rpm}"
done
echo ""
echo "Installation (exemple, cible el9) :"
echo "  sudo dnf install dist/rpmbuild-el9/RPMS/sbom-generator-${VERSION}-1.*.rpm"
echo "  sudo dnf install dist/rpmbuild-el9/RPMS/sbom-generator-gui-${VERSION}-1.*.rpm"
