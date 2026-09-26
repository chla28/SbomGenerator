#!/usr/bin/env bash
# Prepares an AlmaLinux 9 container (run as root) to build a SBOM Generator
# release with scripts/build-dist.sh --rpm: build toolchain for the Flutter
# Linux desktop app, Flutter SDK (Dart included), rpm-build, and the tools
# used for the CVE scan report (grype, osv-scanner, trivy, asciidoctor-pdf).
#
# AlmaLinux 9 (glibc 2.34) is used so that the binaries and RPMs also run on
# RHEL 9 / 10 and recent Fedora releases.
#
# Environment:
#   FLUTTER_VERSION  Flutter release to install (required, e.g. 3.47.5)
#   FLUTTER_HOME     install directory (default: /opt/flutter)
set -euo pipefail

: "${FLUTTER_VERSION:?FLUTTER_VERSION is required}"
FLUTTER_HOME="${FLUTTER_HOME:-/opt/flutter}"

echo "::group::System packages"
dnf install -y dnf-plugins-core epel-release
dnf config-manager --set-enabled crb
dnf install -y \
  git tar xz unzip which findutils file diffutils \
  clang cmake ninja-build pkgconf-pkg-config gtk3-devel \
  rpm-build python3 ruby rubygems
# Runtime dependencies of the GUI: build-dist.sh queries them with `rpm` to
# describe them in the release SBOM (sbom.cdx.json).
dnf install -y fontconfig mesa-libGL gtk4 libsecret
echo "::endgroup::"

echo "::group::Flutter ${FLUTTER_VERSION}"
if [[ ! -x "${FLUTTER_HOME}/bin/flutter" ]]; then
  mkdir -p "$(dirname "$FLUTTER_HOME")"
  curl -fsSL "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz" \
    | tar -xJ -C "$(dirname "$FLUTTER_HOME")"
fi
# The SDK is a git checkout owned by another user than root in the container.
git config --global --add safe.directory '*'
export PATH="${FLUTTER_HOME}/bin:${PATH}"
flutter config --no-analytics >/dev/null
flutter --version
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${FLUTTER_HOME}/bin" >> "$GITHUB_PATH"
fi
echo "::endgroup::"

echo "::group::CVE scanners and asciidoctor-pdf"
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
  | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin
curl -sSfL -o /usr/local/bin/osv-scanner \
  https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
chmod +x /usr/local/bin/osv-scanner
gem install --no-document asciidoctor-pdf
grype version | head -2
trivy --version | head -1
osv-scanner --version | head -1
asciidoctor-pdf --version | head -1
echo "::endgroup::"
