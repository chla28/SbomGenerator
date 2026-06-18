import 'dart:io';
import 'models.dart';

class AsciidocGenerator {
  Future<void> writeToFile(
    List<Package> packages,
    String outputPath, {
    String? documentName,
  }) async {
    final buf = StringBuffer();
    final title = documentName ?? 'Software Bill of Materials — Licences';
    final sorted = List<Package>.from(packages)
      ..sort((a, b) => a.name.compareTo(b.name));

    buf.writeln('= $title');
    buf.writeln(':doctype: article');
    buf.writeln(':toc:');
    buf.writeln(':toclevels: 1');
    buf.writeln(':icons: font');
    buf.writeln();
    buf.writeln('[cols="<1,<2,<1,<2",options="header",stripes=odd]');
    buf.writeln('|===');
    buf.writeln('| Paquet | Version | Architecture | Licence');
    buf.writeln();

    for (final pkg in sorted) {
      final name = _esc(pkg.name);
      final version = _esc(pkg.fullVersion);
      final arch = _esc(pkg.arch);
      final license = _esc(pkg.license.isEmpty ? '(inconnue)' : pkg.license);
      buf.writeln('| $name | $version | $arch | $license');
    }

    buf.writeln('|===');
    buf.writeln();
    buf.writeln('_Généré par sbom_generator — ${packages.length} paquet(s)._');

    await File(outputPath).writeAsString(buf.toString());
  }

  // Dans une cellule AsciiDoc inline, "|" en début de contenu est ambigu.
  // On échappe systématiquement pour éviter tout problème de rendu.
  String _esc(String s) => s.replaceAll('|', '\\|');
}
