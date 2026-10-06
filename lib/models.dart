import 'dart:math';

String _safeId(String s) => s.replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '-');

/// Identifiant SPDX 2.x : le schéma n'autorise que `[a-zA-Z0-9.-]` après
/// `SPDXRef-` (pas de `_`).
String _spdxSafe(String s) => s.replaceAll(RegExp(r'[^a-zA-Z0-9.-]'), '-');

String _normalizePyName(String name) =>
    name.toLowerCase().replaceAll(RegExp(r'[-_.]+'), '-');

// ── Empreinte cryptographique d'un artefact ────────────────────────────────

/// Empreinte cryptographique de l'artefact distribuable d'un paquet
/// (le fichier `.rpm` / `.whl` / `.jar` / l'archive du registre…).
///
/// [alg] utilise les libellés CycloneDX (`SHA-256`, `SHA-512`, `SHA-1`,
/// `MD5`, `SHA3-256`…) ; les générateurs SPDX les convertissent. [content]
/// est le condensat en hexadécimal minuscule.
///
/// N'y placer que le condensat d'un artefact réel : un hash « dérivé » (hash
/// d'en-tête RPM, dirhash Go `h1:`, checksum APK `Q1…`) n'a pas sa place ici
/// et tromperait un consommateur qui vérifie un téléchargement.
class PackageHash {
  final String alg;
  final String content;
  const PackageHash(this.alg, this.content);

  @override
  bool operator ==(Object other) =>
      other is PackageHash && other.alg == alg && other.content == content;

  @override
  int get hashCode => Object.hash(alg, content);

  @override
  String toString() => '$alg:$content';
}

// ── OS de base d'une image de conteneur ─────────────────────────────────────

/// Système d'exploitation de base d'une image de conteneur, tel que détecté
/// par le backend OCI (syft ou trivy — voir [OciParser.parseImage]).
///
/// Sert à générer un composant dédié dans les SBOM CycloneDX (`type:
/// "operating-system"`) et SPDX (`primaryPackagePurpose:
/// "OPERATING-SYSTEM"` / `software:primaryPurpose: "operatingSystem"`).
/// Sans lui, un consommateur comme Trivy en mode `trivy sbom` ignore
/// silencieusement toute la classe de vulnérabilités "os-pkgs" (paquets
/// système RPM/DEB/APK), même si chaque paquet individuel porte déjà
/// `distro=...` dans son propre purl — Trivy exige spécifiquement ce
/// composant séparé pour savoir quelle base de données CVE interroger.
class OsInfo {
  /// Identifiant court de la distribution, ex. `rhel`, `debian`, `alpine`.
  final String id;

  /// Version de la distribution, ex. `9.6`, `13.5`.
  final String version;

  /// Nom complet lisible, ex. `Red Hat Enterprise Linux 9.6 (Plow)`.
  final String? prettyName;

  /// CPE de la distribution, si connu (ex.
  /// `cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*`).
  final String? cpe;

  const OsInfo({
    required this.id,
    required this.version,
    this.prettyName,
    this.cpe,
  });
}

// ── Abstract base ────────────────────────────────────────────────────────────

abstract class Package {
  String get name;
  String get version;
  String get license;
  String get url;
  String get summary;
  String get vendor;
  String get arch;
  String get sourceRef;

  /// Empreintes cryptographiques de l'artefact du paquet (souvent vide : les
  /// paquets déjà installés dans une image n'ont pas d'artefact à hacher).
  List<PackageHash> get hashes;
  List<String> get requires;
  List<String> get provides;

  String get fullVersion;
  String get purl;
  String get bomRef;
  String get spdxId;

  /// 'rpm' or 'pypi'
  String get packageType;

  /// Copie du paquet avec les champs indiqués remplacés (les autres inchangés).
  /// Utilisé pour appliquer les overrides de licence, le repli fournisseur et
  /// la réécriture de [sourceRef] des objets imbriqués (`--depth`).
  Package copyWith({String? license, String? vendor, String? sourceRef});
}

// ── RPM package ──────────────────────────────────────────────────────────────

class RpmPackage extends Package {
  @override
  final String name;
  @override
  final String version;
  final String release;
  @override
  final String arch;
  final String epoch;
  @override
  final String license;
  @override
  final String vendor;
  @override
  final String url;
  final String buildTime;
  @override
  final String summary;
  @override
  final List<String> requires;
  @override
  final List<String> provides;
  @override
  final List<PackageHash> hashes;

  /// Condensat SHA-256 de l'*en-tête* RPM (`%{SHA256HEADER}`) — **pas** le hash
  /// du fichier `.rpm`. Émis comme propriété/annotation dédiée, jamais comme
  /// empreinte d'artefact.
  final String headerSha256;
  final String sourceRpm;
  @override
  final String sourceRef;

  RpmPackage({
    required this.name,
    required this.version,
    required this.release,
    required this.arch,
    required this.epoch,
    required this.license,
    required this.vendor,
    required this.url,
    required this.buildTime,
    required this.summary,
    required this.requires,
    required this.provides,
    this.hashes = const [],
    this.headerSha256 = '',
    this.sourceRpm = '',
    this.sourceRef = '',
  });

  @override
  String get packageType => 'rpm';

  @override
  String get fullVersion {
    if (epoch != '(none)' && epoch.isNotEmpty && epoch != '0') {
      return '$epoch:$version-$release';
    }
    return '$version-$release';
  }

  @override
  String get purl {
    final ver = Uri.encodeComponent(fullVersion);
    return 'pkg:rpm/${_safeId(name)}@$ver?arch=${_safeId(arch)}';
  }

  @override
  String get bomRef =>
      'pkg-${_safeId(name)}-${_safeId(version)}-${_safeId(release)}-${_safeId(arch)}';

  @override
  String get spdxId =>
      'SPDXRef-${_spdxSafe(name)}-${_spdxSafe(version)}-${_spdxSafe(release)}';

  @override
  RpmPackage copyWith({String? license, String? vendor, String? sourceRef}) =>
      RpmPackage(
        name: name,
        version: version,
        release: release,
        arch: arch,
        epoch: epoch,
        license: license ?? this.license,
        vendor: vendor ?? this.vendor,
        url: url,
        buildTime: buildTime,
        summary: summary,
        requires: requires,
        provides: provides,
        hashes: hashes,
        headerSha256: headerSha256,
        sourceRpm: sourceRpm,
        sourceRef: sourceRef ?? this.sourceRef,
      );

  @override
  String toString() => '$name-$fullVersion.$arch';
}

// ── Python wheel package ─────────────────────────────────────────────────────

/// Python wheel or source archive package.
///
/// [packageType] is 'pypi' for wheels and Python sdist (PKG-INFO present),
/// or 'source' for generic source archives where metadata is filename-derived.
class WheelPackage extends Package {
  @override
  final String name;
  @override
  final String version;
  @override
  final String license;
  @override
  final String url;
  @override
  final String summary;
  @override
  final String vendor;

  /// Platform tag from the wheel filename, or 'any' for source archives.
  @override
  final String arch;

  @override
  final String sourceRef;
  @override
  final List<PackageHash> hashes;
  @override
  final List<String> requires;
  @override
  final List<String> provides;

  final String _packageType;

  WheelPackage({
    required this.name,
    required this.version,
    required this.license,
    required this.url,
    required this.summary,
    required this.vendor,
    required this.arch,
    required this.sourceRef,
    this.hashes = const [],
    required this.requires,
    required this.provides,
    String packageType = 'pypi',
  }) : _packageType = packageType;

  @override
  String get packageType => _packageType;

  @override
  String get fullVersion => version;

  @override
  String get purl {
    final v = Uri.encodeComponent(version);
    if (_packageType == 'pypi') {
      final n = Uri.encodeComponent(_normalizePyName(name));
      return 'pkg:pypi/$n@$v';
    }
    if (_packageType == 'maven') {
      // name stored as "groupId:artifactId"
      final parts = name.split(':');
      if (parts.length == 2) {
        final ns = Uri.encodeComponent(parts[0]);
        final nm = Uri.encodeComponent(parts[1]);
        return version.isNotEmpty ? 'pkg:maven/$ns/$nm@$v' : 'pkg:maven/$ns/$nm';
      }
    }
    if (_packageType == 'golang') {
      // Go module paths contain '/' that must NOT be percent-encoded in PURLs
      final gn = name.toLowerCase();
      return version.isNotEmpty ? 'pkg:golang/$gn@$v' : 'pkg:golang/$gn';
    }
    final n = Uri.encodeComponent(name.toLowerCase());
    return switch (_packageType) {
      'npm' => version.isNotEmpty ? 'pkg:npm/$n@$v' : 'pkg:npm/$n',
      'pub' => version.isNotEmpty ? 'pkg:pub/$n@$v' : 'pkg:pub/$n',
      'cargo' => version.isNotEmpty ? 'pkg:cargo/$n@$v' : 'pkg:cargo/$n',
      'apk' => version.isNotEmpty ? 'pkg:apk/alpine/$n@$v' : 'pkg:apk/alpine/$n',
      _ => version.isNotEmpty ? 'pkg:generic/$n@$v' : 'pkg:generic/$n',
    };
  }

  @override
  String get bomRef {
    final prefix = switch (_packageType) {
      'pypi' => 'pkg-pypi',
      'golang' => 'pkg-golang',
      'npm' => 'pkg-npm',
      'pub' => 'pkg-pub',
      'maven' => 'pkg-maven',
      'cargo' => 'pkg-cargo',
      _ => 'pkg-src',
    };
    return '$prefix-${_safeId(name)}-${_safeId(version)}';
  }

  @override
  String get spdxId {
    final prefix = switch (_packageType) {
      'pypi' => 'SPDXRef-pypi',
      'golang' => 'SPDXRef-golang',
      'npm' => 'SPDXRef-npm',
      'pub' => 'SPDXRef-pub',
      'maven' => 'SPDXRef-maven',
      'cargo' => 'SPDXRef-cargo',
      _ => 'SPDXRef-src',
    };
    return '$prefix-${_spdxSafe(name)}-${_spdxSafe(version)}';
  }

  @override
  WheelPackage copyWith({String? license, String? vendor, String? sourceRef}) =>
      WheelPackage(
        name: name,
        version: version,
        license: license ?? this.license,
        url: url,
        summary: summary,
        vendor: vendor ?? this.vendor,
        arch: arch,
        sourceRef: sourceRef ?? this.sourceRef,
        hashes: hashes,
        requires: requires,
        provides: provides,
        packageType: _packageType,
      );

  @override
  String toString() => '$name-$version ($arch)';
}

// ── Debian package ───────────────────────────────────────────────────────────

/// Represents a Debian `.deb` package parsed via `dpkg-deb`.
class DebPackage extends Package {
  @override
  final String name;
  @override
  final String version;
  @override
  final String arch;
  @override
  final String license;
  @override
  final String vendor;
  @override
  final String url;
  @override
  final String summary;
  @override
  final String sourceRef;
  @override
  final List<PackageHash> hashes;
  @override
  final List<String> requires;
  @override
  final List<String> provides;

  DebPackage({
    required this.name,
    required this.version,
    required this.arch,
    required this.license,
    required this.vendor,
    required this.url,
    required this.summary,
    required this.sourceRef,
    this.hashes = const [],
    required this.requires,
    required this.provides,
  });

  @override
  String get packageType => 'deb';

  @override
  String get fullVersion => version;

  @override
  String get purl {
    final n = Uri.encodeComponent(name.toLowerCase());
    final v = Uri.encodeComponent(version);
    final a = Uri.encodeComponent(arch);
    return 'pkg:deb/$n@$v?arch=$a';
  }

  @override
  String get bomRef =>
      'pkg-deb-${_safeId(name)}-${_safeId(version)}-${_safeId(arch)}';

  @override
  String get spdxId => 'SPDXRef-deb-${_spdxSafe(name)}-${_spdxSafe(version)}';

  @override
  DebPackage copyWith({String? license, String? vendor, String? sourceRef}) =>
      DebPackage(
        name: name,
        version: version,
        arch: arch,
        license: license ?? this.license,
        vendor: vendor ?? this.vendor,
        url: url,
        summary: summary,
        sourceRef: sourceRef ?? this.sourceRef,
        hashes: hashes,
        requires: requires,
        provides: provides,
      );

  @override
  String toString() => '$name $version ($arch)';
}

// ── OCI container image package ──────────────────────────────────────────────

/// Represents a package found inside an OCI container image.
///
/// [packageType] reflects the ecosystem : 'rpm', 'deb', 'apk', 'pypi', 'npm',
/// 'go', 'java', 'generic', etc.
/// [purlOverride] is taken directly from the analysis tool (syft/trivy) when
/// provided; otherwise a PURL is constructed from [packageType], [name] and
/// [version].
class OciPackage extends Package {
  @override
  final String name;
  @override
  final String version;
  @override
  final String license;
  @override
  final String vendor;
  @override
  final String url;
  @override
  final String summary;
  @override
  final String arch;
  @override
  final String sourceRef;
  @override
  final List<PackageHash> hashes;
  @override
  final List<String> requires;
  @override
  final List<String> provides;

  final String _packageType;

  /// PURL as reported by the analysis tool; empty means auto-constructed.
  final String purlOverride;

  /// Original OCI image reference (registry ref, tar path, or layout dir).
  final String imageRef;

  OciPackage({
    required this.name,
    required this.version,
    required this.license,
    required this.vendor,
    required this.url,
    required this.summary,
    required this.arch,
    required this.sourceRef,
    required this.imageRef,
    this.hashes = const [],
    required this.requires,
    required this.provides,
    String packageType = 'generic',
    this.purlOverride = '',
  }) : _packageType = packageType;

  @override
  String get packageType => _packageType;

  @override
  String get fullVersion => version;

  @override
  String get purl {
    if (purlOverride.isNotEmpty) return purlOverride;
    final n = Uri.encodeComponent(name.toLowerCase());
    final v = Uri.encodeComponent(version);
    final a = arch.isNotEmpty ? '?arch=${Uri.encodeComponent(arch)}' : '';
    return switch (_packageType) {
      'rpm' => 'pkg:rpm/$n@$v$a',
      'deb' => 'pkg:deb/$n@$v$a',
      'apk' => 'pkg:apk/alpine/$n@$v$a',
      'pypi' => 'pkg:pypi/$n@$v',
      'npm' => 'pkg:npm/$n@$v',
      'go' => 'pkg:golang/$n@$v',
      'java' => 'pkg:maven/$n@$v',
      _ => version.isNotEmpty ? 'pkg:generic/$n@$v' : 'pkg:generic/$n',
    };
  }

  @override
  String get bomRef =>
      'pkg-oci-${_safeId(_packageType)}-${_safeId(name)}-${_safeId(version)}';

  @override
  String get spdxId =>
      'SPDXRef-oci-${_spdxSafe(name)}-${_spdxSafe(version)}';

  @override
  OciPackage copyWith({String? license, String? vendor, String? sourceRef}) =>
      OciPackage(
        name: name,
        version: version,
        license: license ?? this.license,
        vendor: vendor ?? this.vendor,
        url: url,
        summary: summary,
        arch: arch,
        sourceRef: sourceRef ?? this.sourceRef,
        imageRef: imageRef,
        hashes: hashes,
        requires: requires,
        provides: provides,
        packageType: _packageType,
        purlOverride: purlOverride,
      );

  @override
  String toString() => '$name $version ($arch) [$_packageType]';
}

// ── Dependency record ────────────────────────────────────────────────────────

class PackageDependency {
  final String sourceRef;
  final List<String> dependsOn;

  PackageDependency({required this.sourceRef, required this.dependsOn});
}

// ── UUID v4 ──────────────────────────────────────────────────────────────────

String generateUuidV4() {
  final rng = Random.secure();
  final bytes = List<int>.generate(16, (_) => rng.nextInt(256));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  final h = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return '${h.substring(0, 8)}-${h.substring(8, 12)}-'
      '${h.substring(12, 16)}-${h.substring(16, 20)}-'
      '${h.substring(20)}';
}
