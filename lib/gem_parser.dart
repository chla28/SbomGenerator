import 'dart:io';
import 'hash_utils.dart' show packageHash;
import 'models.dart';
import 'i18n.dart';

/// Parses `Gemfile.lock` files (Ruby/Bundler).
///
/// Les gems sont les lignes à 4 espaces sous `specs:` (sections GEM, GIT,
/// PATH) ; la section `CHECKSUMS` (Bundler ≥ 2.5) fournit les SHA-256.
class GemParser {
  List<WheelPackage> parseGemfileLock(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('Gemfile.lock introuvable : {path}', {'path': path}));
      return [];
    }

    final gems = <(String, String)>[];
    final checksums = <String, String>{};
    var section = '';
    var inSpecs = false;

    final spec = RegExp(r'^    ([^\s(]+) \(([^)]+)\)\s*$');
    final sum = RegExp(r'^  ([^\s(]+) \(([^)]+)\) sha256=([0-9a-f]+)\s*$');
    for (final line in file.readAsLinesSync()) {
      if (line.isNotEmpty && !line.startsWith(' ')) {
        section = line.trim();
        inSpecs = false;
        continue;
      }
      if (section == 'CHECKSUMS') {
        final m = sum.firstMatch(line);
        if (m != null) checksums['${m.group(1)}@${m.group(2)}'] = m.group(3)!;
        continue;
      }
      if (line.trim() == 'specs:') {
        inSpecs = true;
        continue;
      }
      if (!inSpecs) continue;
      final m = spec.firstMatch(line);
      if (m != null &&
          (section == 'GEM' || section == 'GIT' || section == 'PATH')) {
        // PATH = gem local du projet, pas un composant tiers.
        if (section != 'PATH') gems.add((m.group(1)!, m.group(2)!));
      }
    }

    final packages = <WheelPackage>[];
    final seen = <String>{};
    for (final (name, raw) in gems) {
      // `1.15.4-x86_64-linux` : la plateforme n'appartient pas à la version.
      final dash = raw.indexOf('-');
      final version = dash > 0 ? raw.substring(0, dash) : raw;
      if (!seen.add('$name@$version')) continue;
      final hash = packageHash('SHA-256',
          checksums['$name@$raw'] ?? checksums['$name@$version'] ?? '');
      packages.add(WheelPackage(
        name: name,
        version: version,
        license: '',
        url: 'https://rubygems.org/gems/$name',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: path,
        hashes: [if (hash != null) hash],
        requires: [],
        provides: [name],
        packageType: 'gem',
      ));
    }
    return packages;
  }
}
