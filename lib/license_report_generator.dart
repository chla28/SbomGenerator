import 'dart:io';
import 'models.dart';

/// Heuristic classification of an SPDX-ish license string, used to flag
/// copyleft licenses in the report. Not a legal assessment.
enum LicenseCategory { unknown, permissive, weakCopyleft, strongCopyleft }

/// Generates an AsciiDoc license-compliance report from a list of [Package],
/// grouped by license with a summary and copyleft/unknown-license warnings.
///
/// Input packages are expected to already carry their license as read back
/// from a SBOM file (see `SbomReader`), i.e. an SPDX expression or the raw
/// string stored in the source document.
class LicenseReportGenerator {
  Future<void> writeToFile(
    List<Package> packages,
    String outputPath, {
    String? documentName,
  }) async {
    final buf = StringBuffer();
    final title = documentName ?? 'Rapport de licences';

    final byLicense = <String, List<Package>>{};
    for (final pkg in packages) {
      final key = pkg.license.trim();
      byLicense.putIfAbsent(key, () => []).add(pkg);
    }

    final unknown = byLicense.remove('') ?? [];

    // Les expressions composées (« A AND B AND … ») sont fréquentes dans les
    // paquets Debian/RPM (toutes les licences trouvées dans les sources sont
    // concaténées). On les garde telles quelles comme clé de regroupement
    // (fidèle à ce qui est déclaré), mais l'avertissement copyleft liste les
    // identifiants individuels plutôt que ces chaînes composées, illisibles.
    var strongCopyleftPackages = 0;
    var weakCopyleftPackages = 0;
    final strongCopyleftTokens = <String>{};
    final weakCopyleftTokens = <String>{};
    for (final entry in byLicense.entries) {
      switch (_classify(entry.key)) {
        case LicenseCategory.strongCopyleft:
          strongCopyleftPackages += entry.value.length;
          strongCopyleftTokens.addAll(_copyleftTokens(entry.key, LicenseCategory.strongCopyleft));
        case LicenseCategory.weakCopyleft:
          weakCopyleftPackages += entry.value.length;
          weakCopyleftTokens.addAll(_copyleftTokens(entry.key, LicenseCategory.weakCopyleft));
        case LicenseCategory.permissive:
        case LicenseCategory.unknown:
          break;
      }
    }

    final sortedLicenses = byLicense.keys.toList()..sort();

    buf.writeln('= $title');
    buf.writeln(':doctype: article');
    buf.writeln(':toc:');
    buf.writeln(':toclevels: 2');
    buf.writeln(':icons: font');
    buf.writeln();

    buf.writeln('== Résumé');
    buf.writeln();
    buf.writeln('[cols="<3,<1",options="header"]');
    buf.writeln('|===');
    buf.writeln('| Indicateur | Valeur');
    buf.writeln('| Paquets analysés | ${packages.length}');
    buf.writeln('| Licences (expressions) distinctes | ${byLicense.length}');
    buf.writeln('| Paquets sous licence copyleft fort (GPL/AGPL) | $strongCopyleftPackages');
    buf.writeln('| Paquets sous licence copyleft faible (LGPL/MPL/EPL/CDDL/CPL/EUPL) | $weakCopyleftPackages');
    buf.writeln('| Paquets sans licence détectée | ${unknown.length}');
    buf.writeln('|===');
    buf.writeln();

    if (strongCopyleftTokens.isNotEmpty) {
      buf.writeln('[WARNING]');
      buf.writeln('====');
      buf.writeln('Licences copyleft fort détectées ($strongCopyleftPackages paquet(s)) — '
          'la redistribution du logiciel combiné peut être soumise à '
          'obligation de publication du code source : '
          '${(strongCopyleftTokens.toList()..sort()).join(', ')}.');
      buf.writeln('====');
      buf.writeln();
    }

    if (unknown.isNotEmpty) {
      final sortedUnknown = List<Package>.from(unknown)
        ..sort((a, b) => a.name.compareTo(b.name));
      buf.writeln('[NOTE]');
      buf.writeln('====');
      buf.writeln('${unknown.length} paquet(s) sans licence détectée, à vérifier manuellement :');
      buf.writeln();
      for (final pkg in sortedUnknown) {
        buf.writeln('* ${_esc(pkg.name)} ${_esc(pkg.fullVersion)}');
      }
      buf.writeln('====');
      buf.writeln();
    }

    buf.writeln('== Détail par licence');
    buf.writeln();

    for (final license in sortedLicenses) {
      final pkgs = List<Package>.from(byLicense[license]!)
        ..sort((a, b) => a.name.compareTo(b.name));
      final category = _classify(license);
      final tag = switch (category) {
        LicenseCategory.strongCopyleft => ' [copyleft fort]',
        LicenseCategory.weakCopyleft => ' [copyleft faible]',
        LicenseCategory.permissive => '',
        LicenseCategory.unknown => '',
      };
      buf.writeln('=== ${_esc(license)}$tag (${pkgs.length})');
      buf.writeln();
      for (final pkg in pkgs) {
        buf.writeln('* ${_esc(pkg.name)} ${_esc(pkg.fullVersion)}');
      }
      buf.writeln();
    }

    buf.writeln('_Généré par sbom_generator — ${packages.length} paquet(s), '
        '${byLicense.length} licence(s) distincte(s)._');

    await File(outputPath).writeAsString(buf.toString());
  }

  /// Splits a (possibly compound "A AND B OR C") license expression into
  /// individual tokens and returns those whose own classification matches
  /// [target]. Used to keep the copyleft warning list readable instead of
  /// dumping entire compound expressions.
  static Iterable<String> _copyleftTokens(String license, LicenseCategory target) {
    final tokens = license.split(RegExp(r'\s+(AND|OR)\s+', caseSensitive: false));
    return tokens
        .map((t) => t.trim())
        .where((t) => t.isNotEmpty && _classify(t) == target);
  }

  static LicenseCategory _classify(String license) {
    final s = license.trim();
    if (s.isEmpty) return LicenseCategory.unknown;
    final upper = s.toUpperCase();

    final isAgpl = upper.contains('AGPL');
    final isBareGpl = RegExp(r'(?<![A-Z])GPL').hasMatch(upper);
    if (isAgpl || isBareGpl) return LicenseCategory.strongCopyleft;

    const weakMarkers = ['LGPL', 'MPL', 'EPL', 'CDDL', 'CPL', 'EUPL'];
    if (weakMarkers.any(upper.contains)) return LicenseCategory.weakCopyleft;

    return LicenseCategory.permissive;
  }

  // Dans une cellule/section AsciiDoc, "|" en début de contenu est ambigu.
  String _esc(String s) => s.replaceAll('|', '\\|');
}
