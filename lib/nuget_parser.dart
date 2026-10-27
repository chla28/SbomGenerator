import 'dart:convert';
import 'dart:io';
import 'hash_utils.dart' show packageHashFromSri;
import 'models.dart';
import 'i18n.dart';

/// Parses .NET dependency files : `packages.lock.json`, `*.deps.json` et les
/// projets `*.csproj` / `*.fsproj` / `*.vbproj`.
///
/// Les lockfiles donnent les versions résolues (fermeture transitive) ; un
/// projet ne donne que les versions littérales de ses `PackageReference`.
class NugetParser {
  /// `packages.lock.json` : `dependencies.<tfm>.<nom>.{type,resolved,contentHash}`.
  List<WheelPackage> parsePackagesLock(String path) {
    final data = _readJson(path, 'packages.lock.json');
    if (data is! Map) return [];
    final out = _Collector(path);
    final frameworks = data['dependencies'];
    if (frameworks is! Map) return [];
    for (final deps in frameworks.values) {
      if (deps is! Map) continue;
      deps.forEach((name, info) {
        if (info is! Map) return;
        // Project = projet de la solution, pas un composant tiers.
        if (info['type'] == 'Project') return;
        out.add(name as String, (info['resolved'] as String?) ?? '',
            sri: 'sha512-${info['contentHash'] ?? ''}');
      });
    }
    return out.packages;
  }

  /// `*.deps.json` : `libraries."<nom>/<version>".{type,sha512}`.
  List<WheelPackage> parseDepsJson(String path) {
    final data = _readJson(path, '.deps.json');
    if (data is! Map) return [];
    final out = _Collector(path);
    final libs = data['libraries'];
    if (libs is! Map) return [];
    libs.forEach((key, info) {
      if (info is! Map || info['type'] != 'package') return;
      final slash = (key as String).lastIndexOf('/');
      if (slash <= 0) return;
      out.add(key.substring(0, slash), key.substring(slash + 1),
          sri: (info['sha512'] as String?) ?? '');
    });
    return out.packages;
  }

  /// Projet MSBuild : `<PackageReference Include="X" Version="1.2.3" />`
  /// (attribut ou élément enfant). Les versions calculées (`$(Prop)`) ne sont
  /// pas résolubles sans MSBuild : le paquet est ignoré avec un avertissement.
  List<WheelPackage> parseProject(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln(
          'Warning: ' + tr('projet .NET introuvable : {path}', {'path': path}));
      return [];
    }
    final text = file.readAsStringSync();
    final out = _Collector(path);
    final ref = RegExp(
        r'<PackageReference\b([^>]*?)(?:/>|>([\s\S]*?)</PackageReference>)',
        caseSensitive: false);
    final attr = RegExp(r'\b(Include|Update|Version)\s*=\s*"([^"]*)"',
        caseSensitive: false);
    for (final m in ref.allMatches(text)) {
      final attrs = <String, String>{};
      for (final a in attr.allMatches(m.group(1)!)) {
        attrs[a.group(1)!.toLowerCase()] = a.group(2)!;
      }
      final name = attrs['include'] ?? '';
      if (name.isEmpty) continue; // `Update` modifie une référence existante
      var version = attrs['version'] ?? '';
      if (version.isEmpty && m.group(2) != null) {
        version =
            RegExp(r'<Version>\s*([^<\s]+)\s*</Version>', caseSensitive: false)
                    .firstMatch(m.group(2)!)
                    ?.group(1) ??
                '';
      }
      if (version.contains(r'$(')) {
        stderr.writeln('Warning: ' +
            tr('version calculée ignorée pour {name} dans {path}',
                {'name': name, 'path': path}));
        continue;
      }
      out.add(name, _lowerBound(version));
    }
    return out.packages;
  }

  /// `[1.0,2.0)` → `1.0` : la borne basse est la version minimale demandée.
  String _lowerBound(String v) {
    final s = v.trim();
    if (!s.startsWith('[') && !s.startsWith('(')) return s;
    return s.substring(1).split(',').first.replaceAll(RegExp(r'[\])\s]'), '');
  }

  Object? _readJson(String path, String label) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('{label} introuvable : {path}', {'label': label, 'path': path}));
      return null;
    }
    try {
      return jsonDecode(file.readAsStringSync());
    } on FormatException catch (e) {
      stderr.writeln('Warning: ' +
          tr('analyse impossible de {path} : {e}', {'path': path, 'e': e}));
      return null;
    }
  }
}

class _Collector {
  final String path;
  final packages = <WheelPackage>[];
  final _seen = <String>{};
  _Collector(this.path);

  void add(String name, String version, {String sri = ''}) {
    if (name.isEmpty || version.isEmpty) return;
    if (!_seen.add('${name.toLowerCase()}@$version')) return;
    final hash = packageHashFromSri(sri);
    packages.add(WheelPackage(
      name: name,
      version: version,
      license: '',
      url: 'https://www.nuget.org/packages/$name/$version',
      summary: '',
      vendor: '',
      arch: 'any',
      sourceRef: path,
      hashes: [if (hash != null) hash],
      requires: [],
      provides: [name],
      packageType: 'nuget',
    ));
  }
}
