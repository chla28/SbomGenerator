import 'dart:convert';
import 'dart:io';
import 'models.dart';
import 'wheel_parser.dart';

// ── Python extraction script ─────────────────────────────────────────────────
//
// Outputs a single JSON line on stdout:
//   {"type":"python","content":"<RFC822 metadata>"}        — Python sdist
//   {"type":"generic","licenseFile":"<name>","license":"<first 2KB>"}  — other
//   {"type":"error","error":"<msg>"}  (stderr + exit 1)    — unreadable
//
const _extractScript = r'''
import tarfile, sys, json

def is_license(path):
    name = path.split('/')[-1].upper()
    return (
        name in ('LICENSE','COPYING','LICENCE','LICENSE.TXT','COPYING.TXT',
                 'LICENSE.MD','COPYING.MD') or
        name.startswith('LICENSE-') or name.startswith('LICENSE.') or
        name.startswith('COPYING-') or name.startswith('COPYING.')
    )

try:
    t = tarfile.open(sys.argv[1])
    names = t.getnames()

    meta_name = (
        next((x for x in names if x.endswith('/METADATA') and '.dist-info' in x), None) or
        next((x for x in names if x.endswith('PKG-INFO')), None)
    )

    if meta_name:
        f = t.extractfile(meta_name)
        text = f.read().decode('utf-8', errors='replace')
        print(json.dumps({'type': 'python', 'content': text}))
    else:
        lic_files = sorted(
            [x for x in names if x.count('/') <= 1 and is_license(x)],
            key=lambda x: (x.count('/'), len(x))
        )
        lic_content = ''
        lic_file = ''
        if lic_files:
            f = t.extractfile(lic_files[0])
            if f:
                lic_content = f.read(2048).decode('utf-8', errors='replace')
                lic_file = lic_files[0].split('/')[-1]
        print(json.dumps({'type': 'generic',
                          'licenseFile': lic_file, 'license': lic_content}))
except Exception as e:
    import sys as _sys
    print(json.dumps({'type': 'error', 'error': str(e)}), file=_sys.stderr)
    _sys.exit(1)
''';

// ── Data class for parsed filename ───────────────────────────────────────────

class _FilenameInfo {
  final String name;
  final String version;
  final String arch;
  _FilenameInfo({required this.name, required this.version, required this.arch});
}

// ── Parser ───────────────────────────────────────────────────────────────────

/// Parses source archive files (.tar, .tar.gz, .tgz).
///
/// Three outcomes:
///   1. **Python sdist** (PKG-INFO / dist-info METADATA present) → delegates to
///      [WheelParser.parseMetadataText], PURL `pkg:pypi/…`.
///   2. **Vendor binary / generic archive** — no Python metadata → name, version
///      and arch are extracted from the filename; license is identified from a
///      LICENSE / COPYING file inside the archive when available.
///      PURL `pkg:generic/…`.
///
/// Requires `python3` (for tarfile extraction).
class TarParser {
  final _wheelParser = WheelParser();

  Future<Package?> parseTarFile(String path) async {
    final result = await Process.run('python3', ['-c', _extractScript, path]);

    if (result.exitCode != 0) {
      stderr.writeln('Warning: cannot read archive "$path"');
      final err = result.stderr.toString().trim();
      if (err.isNotEmpty) stderr.writeln('  $err');
      return null;
    }

    final Map<String, dynamic> payload;
    try {
      payload = jsonDecode(result.stdout.toString().trim()) as Map<String, dynamic>;
    } catch (_) {
      stderr.writeln('Warning: unexpected output from python3 for "$path"');
      return null;
    }

    final type = payload['type'] as String? ?? 'error';

    if (type == 'python') {
      final content = payload['content'] as String? ?? '';
      if (content.isEmpty) {
        stderr.writeln('Warning: empty metadata for "$path"');
        return null;
      }
      return _wheelParser.parseMetadataText(path, content);
    }

    if (type == 'generic') {
      return _buildGenericPackage(
        path,
        licenseFile: payload['licenseFile'] as String? ?? '',
        licenseContent: payload['license'] as String? ?? '',
      );
    }

    // type == 'error' should have caused a non-zero exit code, but guard anyway
    stderr.writeln('Warning: extraction failed for "$path"');
    return null;
  }

  // ── Generic archive (no Python metadata) ──────────────────────────────────

  WheelPackage? _buildGenericPackage(
    String path, {
    required String licenseFile,
    required String licenseContent,
  }) {
    final info = _parseFilename(path);

    if (info.name.isEmpty) {
      stderr.writeln(
          'Warning: cannot determine package name from "$path"; skipping.');
      return null;
    }

    final license = licenseContent.isNotEmpty
        ? _identifyLicense(licenseContent)
        : '';

    if (licenseFile.isNotEmpty && license.isEmpty) {
      // We found a license file but couldn't identify it — keep the filename
      // as a human-readable hint rather than leaving the field empty.
      stderr.writeln(
          'Info: found "$licenseFile" in "${path.split('/').last}" '
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

  // ── Filename parsing ───────────────────────────────────────────────────────

  /// Parse name, version and architecture from a tar archive filename.
  ///
  /// Strategy:
  ///   1. Remove the archive extension.
  ///   2. Split on `-` and locate the first segment that starts with a
  ///      semantic version (`\d+\.\d+`).
  ///   3. Segments *before* the version that are known platform / OS / arch
  ///      keywords are stripped from the name.
  ///   4. Architecture is extracted from any recognised arch keyword in the
  ///      full segment list.
  ///
  /// Examples:
  ///   apache-tomcat-10.1.44             → name=apache-tomcat  ver=10.1.44   arch=any
  ///   mariadb-11.4.8-linux-systemd-x86_64 → name=mariadb       ver=11.4.8    arch=x86_64
  ///   mongodb-linux-x86_64-rhel8-8.0.12   → name=mongodb       ver=8.0.12    arch=x86_64
  ///   mongodb-database-tools-rhel88-x86_64-100.13.0 → name=mongodb-database-tools
  ///   mongosh-2.5.6-linux-x64           → name=mongosh        ver=2.5.6     arch=x86_64
  _FilenameInfo _parseFilename(String path) {
    final filename = path.split('/').last;

    var base = filename;
    for (final ext in ['.tar.gz', '.tgz', '.tar']) {
      if (base.endsWith(ext)) {
        base = base.substring(0, base.length - ext.length);
        break;
      }
    }

    final segments = base.split('-');

    // Find first segment that starts with a version (e.g. "10.1.44", "8.0.12")
    final versionRe = RegExp(r'^\d+\.\d+');
    int versionIdx = -1;
    for (int i = 1; i < segments.length; i++) {
      if (versionRe.hasMatch(segments[i])) {
        versionIdx = i;
        break;
      }
    }

    if (versionIdx < 0) {
      // No version found — use full base as name
      return _FilenameInfo(name: base, version: '', arch: 'any');
    }

    // Name = pre-version segments minus platform keywords
    final nameSegs = segments
        .sublist(0, versionIdx)
        .where((s) => !_isPlatformSegment(s))
        .toList();

    final name = nameSegs.isNotEmpty
        ? nameSegs.join('-')
        : segments.sublist(0, versionIdx).join('-');

    final version = segments[versionIdx];
    final arch = _detectArch(segments) ?? 'any';

    return _FilenameInfo(name: name, version: version, arch: arch);
  }

  /// Returns true for OS, architecture and distribution keywords that should
  /// not be part of the package name.
  bool _isPlatformSegment(String s) {
    const known = {
      'linux', 'windows', 'darwin', 'macos', 'win', 'osx',
      'x86_64', 'x64', 'amd64', 'arm64', 'aarch64', 'i386', 'i686',
      'systemd', 'community', 'enterprise',
    };
    if (known.contains(s.toLowerCase())) return true;
    // Distribution patterns: rhel8, rhel88, el9, fc40, centos7, ubuntu22, …
    return RegExp(r'^(rhel|el|fc|centos|ubuntu|debian|amzn)\d+$',
            caseSensitive: false)
        .hasMatch(s);
  }

  /// Map known arch keywords to normalised values; returns null if none found.
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

  // ── License identification ─────────────────────────────────────────────────

  /// Heuristic identification of a license from the first ~2 KB of a license
  /// file. Returns an SPDX identifier or an empty string when unknown.
  ///
  /// Strategy: identify the license by its *title line* (first 300 chars),
  /// not by arbitrary mentions later in the text.  GPL-2.0 legitimately
  /// references "GNU Lesser General Public License" in its body; reading only
  /// the title prevents false LGPL matches.
  String _identifyLicense(String text) {
    final full = text.length > 2000 ? text.substring(0, 2000) : text;
    // Title = first ~300 chars stripped of whitespace, lower-cased
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

    // Check LGPL/GPL from the title only to avoid false positives:
    // GPL-2.0 body mentions "GNU Library General Public License" in passing.
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
}
