import 'dart:io';
import 'hash_utils.dart' show packageHash, packageHashFromSri;
import 'models.dart';
import 'i18n.dart';

/// Parses `yarn.lock` files (yarn v1 classic and yarn v2+ Berry formats).
class YarnParser {
  List<WheelPackage> parseYarnLock(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('yarn.lock introuvable : $path', 'yarn.lock not found: $path'));
      return [];
    }
    final content = file.readAsStringSync();
    return content.contains('__metadata:')
        ? _parseBerry(content, path)
        : _parseClassic(content, path);
  }

  // ── Yarn v1 ───────────────────────────────────────────────────────────────

  /// Yarn v1 format:
  ///   "lodash@^4.17.21":
  ///     version "4.17.21"
  ///     resolved "https://..."
  List<WheelPackage> _parseClassic(String content, String path) {
    final packages = <WheelPackage>[];
    final seen = <String>{};

    _YarnBlock? current;

    void flush() {
      if (current == null) return;
      final key = '${current!.name}@${current!.version}';
      if (current!.name.isNotEmpty &&
          current!.version.isNotEmpty &&
          seen.add(key)) {
        packages.add(_toPackage(current!, path));
      }
      current = null;
    }

    for (final raw in content.split('\n')) {
      final line = raw.trimRight();

      if (line.isEmpty || line.startsWith('#')) {
        flush();
        continue;
      }

      if (!line.startsWith(' ') &&
          !line.startsWith('\t') &&
          line.endsWith(':')) {
        flush();
        final name = _nameFromHeader(line, classic: true);
        current = _YarnBlock(name);
        continue;
      }

      if (current == null) continue;
      final trimmed = line.trim();
      if (trimmed.startsWith('version ')) {
        current!.version =
            trimmed.substring('version '.length).replaceAll('"', '').trim();
      } else if (trimmed.startsWith('resolved ')) {
        var r =
            trimmed.substring('resolved '.length).replaceAll('"', '').trim();
        final h = r.indexOf('#');
        if (h > 0) {
          // Le fragment `#<hex>` d'un `resolved` yarn v1 est le SHA-1 du tarball.
          current!.hash ??= packageHash('SHA-1', r.substring(h + 1));
          r = r.substring(0, h);
        }
        current!.resolved = r;
      } else if (trimmed.startsWith('integrity ')) {
        current!.hash = packageHashFromSri(
                trimmed.substring('integrity '.length).replaceAll('"', '')) ??
            current!.hash;
      }
    }
    flush();
    return packages;
  }

  // ── Yarn v2+ Berry ────────────────────────────────────────────────────────

  /// Yarn Berry format:
  ///   "lodash@npm:^4.17.21":
  ///     version: 4.17.21
  ///     resolution: "lodash@npm:4.17.21"
  List<WheelPackage> _parseBerry(String content, String path) {
    final packages = <WheelPackage>[];
    final seen = <String>{};
    _YarnBlock? current;
    bool skip = false;

    void flush() {
      if (current == null || skip) {
        current = null;
        skip = false;
        return;
      }
      final key = '${current!.name}@${current!.version}';
      if (current!.name.isNotEmpty &&
          current!.version.isNotEmpty &&
          seen.add(key)) {
        packages.add(_toPackage(current!, path));
      }
      current = null;
    }

    for (final raw in content.split('\n')) {
      final line = raw.trimRight();

      if (line.isEmpty) {
        flush();
        continue;
      }

      if (!line.startsWith(' ') &&
          !line.startsWith('\t') &&
          line.endsWith(':')) {
        flush();
        if (line.startsWith('__metadata:')) {
          skip = true;
          continue;
        }
        final name = _nameFromHeader(line, classic: false);
        current = _YarnBlock(name);
        continue;
      }

      if (current == null || skip) continue;
      final trimmed = line.trim();
      if (trimmed.startsWith('version:')) {
        current!.version =
            trimmed.substring('version:'.length).trim().replaceAll('"', '');
      } else if (trimmed.startsWith('resolution:')) {
        current!.resolved =
            trimmed.substring('resolution:'.length).trim().replaceAll('"', '');
      }
    }
    flush();
    return packages;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  String _nameFromHeader(String line, {required bool classic}) {
    var h = line.replaceAll('"', '').trimRight();
    if (h.endsWith(':')) h = h.substring(0, h.length - 1);
    // Take first specifier if comma-separated
    final first = h.split(',').first.trim();

    if (!classic) {
      // Berry: "lodash@npm:^4.17.21" → name is before "@npm:"
      final npmIdx = first.indexOf('@npm:');
      if (npmIdx > 0) return first.substring(0, npmIdx);
      final patchIdx = first.indexOf('@patch:');
      if (patchIdx > 0) return first.substring(0, patchIdx);
    }

    // Classic / fallback: strip version constraint after last '@'
    final atIdx = first.lastIndexOf('@');
    return atIdx > 0 ? first.substring(0, atIdx) : first;
  }

  WheelPackage _toPackage(_YarnBlock b, String path) => WheelPackage(
        name: b.name,
        version: b.version,
        license: '',
        url: b.resolved,
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: path,
        hashes: [if (b.hash != null) b.hash!],
        requires: [],
        provides: [b.name],
        packageType: 'npm',
      );
}

class _YarnBlock {
  final String name;
  String version = '';
  String resolved = '';
  PackageHash? hash;
  _YarnBlock(this.name);
}
