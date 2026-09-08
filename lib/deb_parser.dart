import 'dart:io';
import 'hash_utils.dart' show hashLocalFile;
import 'models.dart';

/// Parses Debian .deb archives using the system `dpkg-deb` binary.
///
/// Extracts metadata from the embedded control file. The `License` field is
/// not standardised in Debian control files and is often absent; the field is
/// used when present.
class DebParser {
  Future<DebPackage?> parseDebFile(String path) async {
    final result = await Process.run('dpkg-deb', ['-f', path]);

    if (result.exitCode != 0) {
      stderr.writeln('Warning: cannot read "$path"');
      final err = result.stderr.toString().trim();
      if (err.isNotEmpty) stderr.writeln('  $err');
      return null;
    }

    final fields = _parseControl(result.stdout.toString());

    final name = fields['package'] ?? '';
    if (name.isEmpty) {
      stderr.writeln('Warning: no Package field in "$path"');
      return null;
    }

    // First line of Description is the short summary
    final description = fields['description'] ?? '';
    final summary = description.split('\n').first.trim();

    final dependsStr = fields['depends'] ?? '';
    final requires = _parseDependsList(dependsStr);

    return DebPackage(
      name: name,
      version: fields['version'] ?? '',
      arch: fields['architecture'] ?? 'any',
      license: fields['license'] ?? '',
      vendor: fields['maintainer'] ?? '',
      url: fields['homepage'] ?? '',
      summary: summary,
      sourceRef: path,
      hashes: hashLocalFile(path),
      requires: requires,
      provides: [name],
    );
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  Map<String, String> _parseControl(String text) {
    final fields = <String, String>{};
    String? currentKey;
    final buf = StringBuffer();

    for (final line in text.split('\n')) {
      if ((line.startsWith(' ') || line.startsWith('\t')) &&
          currentKey != null) {
        buf.write('\n${line.trim()}');
      } else {
        if (currentKey != null) fields[currentKey] = buf.toString();
        final colonIdx = line.indexOf(':');
        if (colonIdx > 0) {
          currentKey = line.substring(0, colonIdx).trim().toLowerCase();
          buf
            ..clear()
            ..write(line.substring(colonIdx + 1).trim());
        } else {
          currentKey = null;
        }
      }
    }
    if (currentKey != null) fields[currentKey] = buf.toString();

    return fields;
  }

  List<String> _parseDependsList(String depends) {
    if (depends.isEmpty) return [];
    return depends
        .split(RegExp(r'[,|]'))
        .map((s) => s.trim().split(RegExp(r'[\s(]')).first.trim())
        .where((s) => s.isNotEmpty)
        .toList();
  }
}
