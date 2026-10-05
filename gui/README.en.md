# sbom_generator_gui

🇫🇷 [Français](README.md) · 🇬🇧 **English**

Desktop graphical interface (Linux) for **SBOM Generator**. It gives access, without a command line, to the whole workflow around the software inventory (SBOM): configuring and launching a generation, following progress, exploring the results, looking up known vulnerabilities (on an already generated SBOM or directly on a container image), assessing the quality of the produced SBOM, comparing two inventories, merging several inventories, generating a license report, and freely browsing any existing SBOM file.

The application does not perform any business processing itself: it orchestrates external command-line tools (`sbom-generator`, `grype`, `osv-scanner`, `trivy`, `sbomqs`, `sbom-scorecard`, `asciidoctor-pdf`) and displays their results.

The interface is available in French and English (*Interface language* menu: System / Français / English) and forwards its language to the `sbom-generator` CLI it launches (via `SBOM_LANG`).

---

## Interface overview

A single window in two areas:
- a **Configuration** panel (left): SBOM generation form (package source or OCI container image, output formats, options), with a live preview of the equivalent command and management of named profiles;
- a **Results** area (right), organised in 13 tabs: Progress, Results, Dashboard, Grype, OSV-Scanner, Trivy, SBOM Quality, Tree, Comparison, Merge, Licenses, Viewer, Preview.

For the complete functional description of each tab, see `doc/user.en.adoc`.

---

## Prerequisites

| Component | Mandatory | Role |
|-----------|:---------:|------|
| Flutter SDK (stable channel, ≥ 3.44) | Yes | Build and execution |
| `sbom-generator` (CLI binary of this repository) | Yes | Generation of the SBOM files |
| `syft` | No | OCI image analysis (default backend) |
| `trivy` | No | OCI image analysis (alternative backend) and/or vulnerability detection (Trivy tab) |
| `skopeo` | No | OCI image analysis (alternative backend) |
| `grype` | No | Vulnerability detection (Grype tab) |
| `osv-scanner` | No | Vulnerability detection (OSV-Scanner tab) |
| `sbomqs` | No | SBOM quality score (SBOM Quality tab, or option in Configuration) |
| `sbom-scorecard` | No | SBOM quality score, complementary reference (SBOM Quality tab) |
| `asciidoctor-pdf` | No | PDF conversion of the generated AsciiDoc report (SBOM or Grype/OSV-Scanner/Trivy vulnerability export) |

All the tools marked "No" are optional: their absence only disables the corresponding feature, with an explicit message in the interface, without making the rest of the application fail.

---

## Running in development

```bash
cd gui/
flutter pub get
flutter run -d linux
```

`sbom-generator` must be reachable in the `PATH`, or compiled and placed next to the GUI binary (see `SettingsService.cliBinary` in `doc/developer.en.adoc` for the resolution order):

```bash
cd ..   # project root
dart compile exe bin/sbom_generator.dart -o build/sbom-generator
export PATH="$PWD/build:$PATH"
```

## Building a standalone binary

```bash
flutter build linux --release
# Binary produced in: build/linux/x64/release/bundle/sbom_generator_gui
```

The script `../scripts/build-dist.sh` (at the repository root) automates the build of the CLI **and** the GUI, and produces a complete distribution archive.

## Checks

```bash
flutter analyze
flutter test -j 1   # -j 1: more deterministic than the default parallelism
                     #   on machines with limited resources
```

Run automatically by `../.github/workflows/ci.yml` on every push/pull request to `main`.

---

## Documentation

- `doc/user.en.adoc` — complete user guide: each tab, each option, typical usage scenarios, troubleshooting (French: `doc/user.adoc`).
- `doc/developer.en.adoc` — technical architecture: role of each file, data flows, conventions, known pitfalls (French: `doc/developer.adoc`).
