import 'dart:io';
import 'models.dart';

class MarkdownGenerator {
  Future<void> writeToFile(
    List<Package> packages,
    String outputPath, {
    String? documentName,
  }) async {
    final buf = StringBuffer();

    final title = documentName ?? 'Software Bill of Materials — Licences';
    buf.writeln('# $title');
    buf.writeln();
    buf.writeln('| Paquet | Version | Architecture | Licence |');
    buf.writeln('|--------|---------|--------------|---------|');

    final sorted = List<Package>.from(packages)
      ..sort((a, b) => a.name.compareTo(b.name));

    for (final pkg in sorted) {
      final name    = _escape(pkg.name);
      final version = _escape(pkg.fullVersion);
      final arch    = _escape(pkg.arch);
      final license = _escape(pkg.license.isEmpty ? '(inconnue)' : pkg.license);
      buf.writeln('| $name | $version | $arch | $license |');
    }

    buf.writeln();
    buf.writeln('_Généré par sbom_generator — ${packages.length} paquet(s)._');

    await File(outputPath).writeAsString(buf.toString());
  }

  String _escape(String s) => s.replaceAll('|', r'\|');
}
