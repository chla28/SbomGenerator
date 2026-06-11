/// Shared helpers for archive parsers (tar, zip).
///
/// Provides filename parsing, license identification, and generic package
/// construction — logic identical for both archive formats.
library;

import 'dart:io';
import 'models.dart';

// ── Data class ───────────────────────────────────────────────────────────────

class ArchiveFilenameInfo {
  final String name;
  final String version;
  final String arch;
  ArchiveFilenameInfo(
      {required this.name, required this.version, required this.arch});
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Build a generic [WheelPackage] from an archive that has no Python metadata.
///
/// Returns null when the package name cannot be determined from the filename.
WheelPackage? buildGenericArchivePackage(
  String path, {
  required String licenseFile,
  required String licenseContent,
}) {
  final info = parseArchiveFilename(path);

  if (info.name.isEmpty) {
    stderr.writeln(
        'Warning: cannot determine package name from "$path"; skipping.');
    return null;
  }

  final license =
      licenseContent.isNotEmpty ? identifyArchiveLicense(licenseContent) : '';

  if (licenseFile.isNotEmpty && license.isEmpty) {
    stderr.writeln('Info: found "$licenseFile" in "${path.split('/').last}" '
        'but could not identify a known SPDX license.');
  }

  return WheelPackage(
    name: info.name,
    version: info.version,
    license: license,
    url: '',
    summary: '',
    vendor: '',
    arch: info.arch,
    sourceRef: path,
    requires: [],
    provides: [info.name.toLowerCase()],
    packageType: 'source',
  );
}

/// Parse name, version and architecture from an archive filename.
///
/// Strategy:
///   1. Remove the archive extension.
///   2. Split on `-` and locate the first segment that starts with a
///      semantic version (`\d+\.\d+`).
///   3. Segments before the version that are known platform/OS/arch keywords
///      are stripped from the name.
///   4. Architecture is extracted from any recognised arch keyword.
ArchiveFilenameInfo parseArchiveFilename(String path) {
  final filename = path.split('/').last;

  var base = filename;
  for (final ext in ['.tar.gz', '.tgz', '.tar', '.zip']) {
    if (base.endsWith(ext)) {
      base = base.substring(0, base.length - ext.length);
      break;
    }
  }

  final segments = base.split('-');

  final versionRe = RegExp(r'^\d+\.\d+');
  int versionIdx = -1;
  for (int i = 1; i < segments.length; i++) {
    if (versionRe.hasMatch(segments[i])) {
      versionIdx = i;
      break;
    }
  }

  if (versionIdx < 0) {
    return ArchiveFilenameInfo(name: base, version: '', arch: 'any');
  }

  final nameSegs = segments
      .sublist(0, versionIdx)
      .where((s) => !_isPlatformSegment(s))
      .toList();

  final name = nameSegs.isNotEmpty
      ? nameSegs.join('-')
      : segments.sublist(0, versionIdx).join('-');

  final version = segments[versionIdx];
  final arch = _detectArch(segments) ?? 'any';

  return ArchiveFilenameInfo(name: name, version: version, arch: arch);
}

/// Heuristic identification of a license from the first ~2 KB of a license
/// file. Returns an SPDX identifier or an empty string when unknown.
///
/// Checks only the first 300 chars for LGPL/GPL to avoid false positives —
/// the GPL-2.0 body mentions "GNU Library General Public License" in passing.
String identifyArchiveLicense(String text) {
  final full = text.length > 2000 ? text.substring(0, 2000) : text;
  final title =
      (text.length > 300 ? text.substring(0, 300) : text).toLowerCase();
  final lower = full.toLowerCase();

  if (lower.contains('server side public license')) return 'SSPL-1.0';

  if (lower.contains('apache license') ||
      lower.contains('apache software license')) {
    if (lower.contains('version 2')) return 'Apache-2.0';
    if (lower.contains('version 1.1')) return 'Apache-1.1';
    return 'Apache-2.0';
  }

  if (RegExp(r'gnu\s+(lesser|library)\s+general\s+public\s+license',
          caseSensitive: false)
      .hasMatch(title)) {
    if (title.contains('version 3')) return 'LGPL-3.0-only';
    if (title.contains('version 2.1')) return 'LGPL-2.1-only';
    if (title.contains('version 2')) return 'LGPL-2.0-only';
    return 'LGPL-2.1-only';
  }

  if (RegExp(r'gnu\s+general\s+public\s+license', caseSensitive: false)
      .hasMatch(title)) {
    if (lower.contains('version 3')) return 'GPL-3.0-only';
    if (lower.contains('version 2')) return 'GPL-2.0-only';
    return 'GPL-2.0-only';
  }

  if (lower.contains('mozilla public license')) {
    if (lower.contains('2.0')) return 'MPL-2.0';
    if (lower.contains('1.1')) return 'MPL-1.1';
    return 'MPL-2.0';
  }

  if (lower.contains('mit license') ||
      (lower.contains('permission is hereby granted') &&
          lower.contains('without restriction'))) {
    return 'MIT';
  }

  if (lower.contains('isc license')) return 'ISC';

  if (lower.contains('bsd') && lower.contains('redistribution')) {
    if (lower.contains('neither the name')) return 'BSD-3-Clause';
    return 'BSD-2-Clause';
  }

  if (lower.contains('eclipse public license')) {
    if (lower.contains('2.0')) return 'EPL-2.0';
    return 'EPL-1.0';
  }

  if (lower.contains('cddl')) return 'CDDL-1.0';

  return '';
}

// ── Private helpers ───────────────────────────────────────────────────────────

bool _isPlatformSegment(String s) {
  const known = {
    'linux',
    'windows',
    'darwin',
    'macos',
    'win',
    'osx',
    'x86_64',
    'x64',
    'amd64',
    'arm64',
    'aarch64',
    'i386',
    'i686',
    'systemd',
    'community',
    'enterprise',
  };
  if (known.contains(s.toLowerCase())) return true;
  return RegExp(r'^(rhel|el|fc|centos|ubuntu|debian|amzn)\d+$',
          caseSensitive: false)
      .hasMatch(s);
}

String? _detectArch(List<String> segments) {
  for (final s in segments) {
    switch (s.toLowerCase()) {
      case 'x86_64':
      case 'amd64':
        return 'x86_64';
      case 'x64':
        return 'x86_64';
      case 'arm64':
      case 'aarch64':
        return 'aarch64';
      case 'i386':
      case 'i686':
        return 'i386';
    }
  }
  return null;
}
