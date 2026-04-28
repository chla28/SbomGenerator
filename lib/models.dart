import 'dart:math';

String _safeId(String s) => s.replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '-');

String _normalizePyName(String name) =>
    name.toLowerCase().replaceAll(RegExp(r'[-_.]+'), '-');

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
  String get sha256Header;
  List<String> get requires;
  List<String> get provides;

  String get fullVersion;
  String get purl;
  String get bomRef;
  String get spdxId;

  /// 'rpm' or 'pypi'
  String get packageType;
}

// ── RPM package ──────────────────────────────────────────────────────────────

class RpmPackage extends Package {
  @override final String name;
  @override final String version;
  final String release;
  @override final String arch;
  final String epoch;
  @override final String license;
  @override final String vendor;
  @override final String url;
  final String buildTime;
  @override final String summary;
  @override final List<String> requires;
  @override final List<String> provides;
  @override final String sha256Header;
  final String sourceRpm;
  @override final String sourceRef;

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
    this.sha256Header = '',
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
      'SPDXRef-${_safeId(name)}-${_safeId(version)}-${_safeId(release)}';

  @override
  String toString() => '$name-$fullVersion.$arch';
}

// ── Python wheel package ─────────────────────────────────────────────────────

/// Python wheel or source archive package.
///
/// [packageType] is 'pypi' for wheels and Python sdist (PKG-INFO present),
/// or 'source' for generic source archives where metadata is filename-derived.
class WheelPackage extends Package {
  @override final String name;
  @override final String version;
  @override final String license;
  @override final String url;
  @override final String summary;
  @override final String vendor;

  /// Platform tag from the wheel filename, or 'any' for source archives.
  @override final String arch;

  @override final String sourceRef;
  @override final String sha256Header;
  @override final List<String> requires;
  @override final List<String> provides;

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
    this.sha256Header = '',
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
    if (_packageType == 'pypi') {
      final n = Uri.encodeComponent(_normalizePyName(name));
      final v = Uri.encodeComponent(version);
      return 'pkg:pypi/$n@$v';
    }
    // Generic source archive — use pkg:generic PURL type
    final n = Uri.encodeComponent(name.toLowerCase());
    return version.isNotEmpty
        ? 'pkg:generic/$n@${Uri.encodeComponent(version)}'
        : 'pkg:generic/$n';
  }

  @override
  String get bomRef {
    final prefix = _packageType == 'pypi' ? 'pkg-pypi' : 'pkg-src';
    return '$prefix-${_safeId(name)}-${_safeId(version)}';
  }

  @override
  String get spdxId {
    final prefix = _packageType == 'pypi' ? 'SPDXRef-pypi' : 'SPDXRef-src';
    return '$prefix-${_safeId(name)}-${_safeId(version)}';
  }

  @override
  String toString() => '$name-$version ($arch)';
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
