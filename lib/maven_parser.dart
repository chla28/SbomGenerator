import 'dart:io';
import 'models.dart';
import 'i18n.dart';

/// Parses Maven `pom.xml` files using lightweight regex-based XML extraction.
///
/// Only compile-scope (and default-scope) `<dependency>` entries inside the
/// top-level `<dependencies>` block are included. Test/provided/system scope
/// and `<dependencyManagement>` entries are excluded.
class MavenParser {
  List<WheelPackage> parsePomXml(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      stderr.writeln('Warning: ' +
          tr('pom.xml introuvable : $path', 'pom.xml not found: $path'));
      return [];
    }

    final content = file.readAsStringSync();

    // Remove dependencyManagement and build/plugin sections to avoid
    // picking up their <dependency> entries.
    final cleaned = content
        .replaceAll(
            RegExp(r'<dependencyManagement>.*?</dependencyManagement>',
                dotAll: true),
            '')
        .replaceAll(RegExp(r'<build>.*?</build>', dotAll: true), '')
        .replaceAll(RegExp(r'<plugin>.*?</plugin>', dotAll: true), '');

    final block = _extractFirst(cleaned, 'dependencies');
    if (block == null) return [];

    return _parseDependencies(block, path);
  }

  List<WheelPackage> _parseDependencies(String block, String path) {
    final packages = <WheelPackage>[];
    final re = RegExp(r'<dependency>(.*?)</dependency>', dotAll: true);
    for (final m in re.allMatches(block)) {
      final dep = m.group(1)!;

      final groupId = _extractFirst(dep, 'groupId') ?? '';
      final artifactId = _extractFirst(dep, 'artifactId') ?? '';
      if (artifactId.isEmpty) continue;

      final scope = _extractFirst(dep, 'scope') ?? 'compile';
      if (scope == 'test' || scope == 'system') continue;

      final version = _extractFirst(dep, 'version') ?? '';

      // Store as groupId:artifactId — matches Maven coordinate convention
      // and allows proper PURL construction in WheelPackage.
      final name = groupId.isNotEmpty ? '$groupId:$artifactId' : artifactId;

      packages.add(WheelPackage(
        name: name,
        version: version,
        license: '',
        url: groupId.isNotEmpty
            ? 'https://mvnrepository.com/artifact/$groupId/$artifactId'
            : '',
        summary: '',
        vendor: groupId,
        arch: 'any',
        sourceRef: path,
        requires: [],
        provides: [name],
        packageType: 'maven',
      ));
    }
    return packages;
  }

  String? _extractFirst(String xml, String tag) {
    final m =
        RegExp('<$tag>\\s*(.*?)\\s*</$tag>', dotAll: true).firstMatch(xml);
    return m?.group(1)?.trim();
  }
}
