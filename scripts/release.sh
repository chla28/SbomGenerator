#!/usr/bin/env bash
# release.sh — Prépare une release en local (remplace les workflows GitHub).
#
# Étapes : contrôle de cohérence des versions et de l'arbre git, analyse et
# tests (CLI + GUI), construction de la distribution (build-dist.sh), somme de
# contrôle des livrables et notes de version extraites du CHANGELOG.
#
# Rien n'est envoyé par défaut : le tag et la publication sont des options
# explicites, et le script ne fait jamais de `git push`.
#
# Usage : ./scripts/release.sh [--rpm] [--skip-tests] [--check-only]
#                              [--tag] [--publish]
#   --rpm         construit aussi les RPM (nécessite rpm-build)
#   --skip-tests  saute analyse et tests (déjà faits)
#   --check-only  s'arrête après les contrôles de cohérence
#   --tag         crée le tag annoté vVERSION sur HEAD (local)
#   --publish     crée la release GitHub avec `gh` (le tag doit déjà être
#                 poussé : git push origin vVERSION)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

BUILD_RPM=false
SKIP_TESTS=false
CHECK_ONLY=false
DO_TAG=false
DO_PUBLISH=false

for arg in "$@"; do
  case "$arg" in
    --rpm)        BUILD_RPM=true ;;
    --skip-tests) SKIP_TESTS=true ;;
    --check-only) CHECK_ONLY=true ;;
    --tag)        DO_TAG=true ;;
    --publish)    DO_PUBLISH=true ;;
    --help|-h)    sed -n '2,/^set -/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
                  exit 0 ;;
    *) echo "Option inconnue : $arg" >&2; exit 1 ;;
  esac
done

fail() { echo "✗ $*" >&2; exit 1; }
step() { echo; echo "── $* ──"; }

pubspec_version() { sed -n 's/^version:[[:space:]]*//p' "$1" | head -1 | tr -d '[:space:]'; }

# ── Cohérence des versions ─────────────────────────────────────────────────
step "Contrôle des versions"
VERSION="$(pubspec_version pubspec.yaml)"
[[ -n "$VERSION" ]] || fail "version illisible dans pubspec.yaml"
GUI_VERSION="$(pubspec_version gui/pubspec.yaml)"
[[ "${GUI_VERSION%%+*}" == "$VERSION" ]] \
  || fail "gui/pubspec.yaml ($GUI_VERSION) ne correspond pas à pubspec.yaml ($VERSION)"
for changelog in CHANGELOG.md CHANGELOG.en.md; do
  .github/scripts/changelog-section.sh "$VERSION" "$changelog" > /dev/null \
    || fail "$changelog n'a pas de section pour $VERSION"
done
echo "✓ version $VERSION cohérente (pubspec, GUI, changelogs)"

# ── État git ───────────────────────────────────────────────────────────────
step "Contrôle de l'arbre git"
# Les fichiers non suivis sont tolérés ; toute modification suivie bloque.
if ! git diff --quiet || ! git diff --cached --quiet; then
  git status --short | grep -v '^??' >&2 || true
  fail "des modifications suivies ne sont pas commitées"
fi
TAG="v$VERSION"
if git rev-parse -q --verify "refs/tags/$TAG" > /dev/null; then
  TAG_COMMIT="$(git rev-list -n 1 "$TAG")"
  [[ "$TAG_COMMIT" == "$(git rev-parse HEAD)" ]] \
    || fail "le tag $TAG existe déjà sur un autre commit que HEAD"
  echo "✓ le tag $TAG existe déjà sur HEAD"
else
  echo "✓ le tag $TAG est libre"
fi
$CHECK_ONLY && { echo; echo "Contrôles terminés (--check-only)."; exit 0; }

# ── Analyse et tests ───────────────────────────────────────────────────────
if ! $SKIP_TESTS; then
  step "Analyse et tests (CLI)"
  dart analyze
  dart test
  step "Analyse et tests (GUI)"
  (cd gui && flutter analyze && flutter test)
fi

# ── Distribution ───────────────────────────────────────────────────────────
step "Construction de la distribution"
if $BUILD_RPM; then ./scripts/build-dist.sh --rpm; else ./scripts/build-dist.sh; fi

step "Sommes de contrôle et notes de version"
(
  cd dist
  shopt -s nullglob
  assets=(*"$VERSION"*.tar.gz *"$VERSION"*.cdx.json *"$VERSION"*-scan-report.pdf
          rpmbuild/RPMS/*/*.rpm)
  [[ ${#assets[@]} -gt 0 ]] || fail "aucun livrable pour la version $VERSION dans dist/"
  sha256sum "${assets[@]}" > SHA256SUMS
  echo "✓ dist/SHA256SUMS (${#assets[@]} fichier(s))"
)
.github/scripts/changelog-section.sh "$VERSION" > dist/release-notes.md
echo "✓ dist/release-notes.md"

# ── Tag et publication (explicites) ────────────────────────────────────────
if $DO_TAG; then
  step "Tag"
  if git rev-parse -q --verify "refs/tags/$TAG" > /dev/null; then
    echo "le tag $TAG existe déjà : rien à faire"
  else
    git tag -a "$TAG" -m "SBOM Generator $TAG"
    echo "✓ tag $TAG créé (non poussé : git push origin $TAG)"
  fi
fi

if $DO_PUBLISH; then
  step "Publication GitHub"
  command -v gh > /dev/null || fail "gh introuvable"
  git ls-remote --exit-code --tags origin "refs/tags/$TAG" > /dev/null \
    || fail "le tag $TAG n'est pas sur le dépôt distant (git push origin $TAG)"
  (
    cd dist
    shopt -s nullglob
    files=(*"$VERSION"*.tar.gz *"$VERSION"*.cdx.json *"$VERSION"*-scan-report.pdf
           rpmbuild/RPMS/*/*.rpm SHA256SUMS)
    gh release create "$TAG" --verify-tag --title "SBOM Generator $TAG" \
      --notes-file release-notes.md "${files[@]}"
  )
fi

echo
echo "Release $VERSION prête dans dist/."
$DO_PUBLISH || echo "Pour publier : git push origin $TAG && ./scripts/release.sh --skip-tests --publish"
