import 'dart:io';
import 'tool_runner.dart';
import 'hash_utils.dart' show hashLocalFile;
import 'models.dart';
import 'i18n.dart';

String _normalizePyName(String name) =>
    name.toLowerCase().replaceAll(RegExp(r'[-_.]+'), '-');

/// Reads Python wheel (.whl) archives and extracts package metadata.
///
/// Wheels are ZIP files; the METADATA file inside the .dist-info/ directory
/// follows RFC 822 header syntax (PEP 241 / PEP 566 / PEP 643).
/// Requires python3 to unzip the archive.
class WheelParser {
  static const _extractScript = r'''
import zipfile, sys
z = zipfile.ZipFile(sys.argv[1])
name = next((x for x in z.namelist() if x.endswith('/METADATA')), None)
if name is None:
    raise SystemExit("no METADATA found in " + sys.argv[1])
sys.stdout.buffer.write(z.read(name))
''';

  Future<WheelPackage?> parseWheelFile(String path) async {
    final result = await runTool('python3', ['-c', _extractScript, path]);

    if (result.exitCode != 0) {
      stderr.writeln('Warning: ' +
          tr('lecture impossible de la wheel "$path"',
              'cannot read wheel "$path"'));
      final err = result.stderr.toString().trim();
      if (err.isNotEmpty) stderr.writeln('  $err');
      return null;
    }

    final text = result.stdout.toString();
    if (text.isEmpty) {
      stderr.writeln('Warning: ' +
          tr('METADATA vide pour "$path"', 'empty METADATA for "$path"'));
      return null;
    }

    return _buildPackage(path, _parseRfc822(text), hashes: hashLocalFile(path));
  }

  /// Parse an already-extracted RFC 822 metadata text (PKG-INFO / METADATA).
  /// Used by [TarParser] to avoid duplicating the parsing logic.
  WheelPackage? parseMetadataText(String sourceRef, String text,
      {String packageType = 'pypi'}) {
    if (text.isEmpty) return null;
    return _buildPackage(sourceRef, _parseRfc822(text),
        packageType: packageType);
  }

  WheelPackage? _buildPackage(String path, Map<String, List<String>> headers,
      {String packageType = 'pypi', List<PackageHash> hashes = const []}) {
    final name = headers['name']?.first ?? '';
    if (name.isEmpty) {
      stderr.writeln('Warning: ' +
          tr('aucun Name dans METADATA pour "$path"',
              'no Name in METADATA for "$path"'));
      return null;
    }

    final version = headers['version']?.first ?? '';

    // License: prefer PEP 639 License-Expression, then License field,
    // then extract from Classifier: License :: OSI Approved :: <name>
    var license =
        headers['license-expression']?.first ?? headers['license']?.first ?? '';
    if (license.isEmpty || license == 'UNKNOWN') {
      license = _licenseFromClassifiers(headers['classifier'] ?? []);
    }
    if (license == 'UNKNOWN') license = '';

    // URL: prefer Project-URL: Homepage, then Home-page
    var url = '';
    for (final entry in (headers['project-url'] ?? [])) {
      final idx = entry.indexOf(',');
      if (idx > 0 &&
          entry.substring(0, idx).trim().toLowerCase() == 'homepage') {
        url = entry.substring(idx + 1).trim();
        break;
      }
    }
    if (url.isEmpty) url = headers['home-page']?.first ?? '';
    if (url == 'UNKNOWN') url = '';

    final summary = headers['summary']?.first ?? '';

    // Vendor: Author-email (may be "Name <addr>") || Author || Maintainer
    var vendor = headers['author-email']?.first ??
        headers['author']?.first ??
        headers['maintainer']?.first ??
        '';
    // Strip email address, keep only the display name part
    final nameEmail = RegExp(r'^"?([^"<,]+?)"?\s*<[^>]+>$');
    final m = nameEmail.firstMatch(vendor.trim());
    if (m != null) vendor = m.group(1)!.trim();
    if (vendor == 'UNKNOWN') vendor = '';

    // Arch: platform tag (last dash-segment before .whl in the filename)
    final arch = _platformFromFilename(path);

    // Requires: strip version constraints and environment markers
    final requires = (headers['requires-dist'] ?? [])
        .map(_requiresDistName)
        .where((s) => s.isNotEmpty)
        .toList();

    // Provides: normalized name so the dependency resolver can match it
    final provides = [_normalizePyName(name)];

    return WheelPackage(
      name: name,
      version: version,
      license: license,
      url: url,
      summary: summary,
      vendor: vendor,
      arch: arch,
      sourceRef: path,
      hashes: hashes,
      requires: requires,
      provides: provides,
      packageType: packageType,
    );
  }

  // ── RFC 822 parser ───────────────────────────────────────────────────────

  /// Parse RFC 822 headers into a map of lowercase field → list of values.
  /// Multi-line values (continuation lines starting with whitespace) are
  /// concatenated. Stops at the first blank line (start of the body).
  Map<String, List<String>> _parseRfc822(String text) {
    final result = <String, List<String>>{};
    String? currentKey;
    final buf = StringBuffer();

    void flush() {
      if (currentKey != null) {
        final val = buf.toString().trim();
        if (val.isNotEmpty) {
          result.putIfAbsent(currentKey!, () => []).add(val);
        }
        buf.clear();
        currentKey = null;
      }
    }

    for (final raw in text.split('\n')) {
      final line = raw.trimRight();
      if (line.isEmpty) break; // end of headers
      if (line.startsWith(' ') || line.startsWith('\t')) {
        if (buf.isNotEmpty) buf.write(' ');
        buf.write(line.trim());
      } else {
        flush();
        final colon = line.indexOf(':');
        if (colon > 0) {
          currentKey = line.substring(0, colon).toLowerCase();
          buf.write(line.substring(colon + 1).trim());
        }
      }
    }
    flush();
    return result;
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  String _licenseFromClassifiers(List<String> classifiers) {
    final names = classifiers
        .where((c) => c.startsWith('License :: '))
        .map((c) => c.split(' :: ').last.trim())
        .where((l) => l != 'OSI Approved' && l.isNotEmpty)
        .toSet()
        .toList();
    return names.join(' OR ');
  }

  /// Extract the normalized package name from a Requires-Dist entry.
  /// Strips version constraints "(...)" and environment markers "; ...".
  String _requiresDistName(String req) {
    var s = req.split(';').first.trim();
    s = s.split(RegExp(r'[\s(]')).first.trim();
    return _normalizePyName(s);
  }

  /// Derive a platform tag from the wheel filename.
  /// Wheel format: {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
  String _platformFromFilename(String path) {
    final filename = path.split('/').last;
    if (!filename.endsWith('.whl')) return 'any';
    final base = filename.substring(0, filename.length - 4);
    final parts = base.split('-');
    return parts.length >= 5 ? parts.last : 'any';
  }
}
