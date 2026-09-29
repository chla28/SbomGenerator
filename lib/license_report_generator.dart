import 'dart:convert';
import 'dart:io';
import 'models.dart';

/// Heuristic classification of an SPDX-ish license string, used to flag
/// copyleft licenses in the report. Not a legal assessment.
enum LicenseCategory { unknown, permissive, weakCopyleft, strongCopyleft }

/// Formats de sortie du rapport de licences.
enum LicenseReportFormat {
  asciidoc('asciidoc', 'adoc'),
  markdown('markdown', 'md'),
  html('html', 'html'),
  csv('csv', 'csv'),
  json('json', 'json');

  final String cliName;
  final String extension;
  const LicenseReportFormat(this.cliName, this.extension);

  static LicenseReportFormat? parse(String name) {
    for (final f in values) {
      if (f.cliName == name.toLowerCase() ||
          (f == asciidoc && name.toLowerCase() == 'adoc')) {
        return f;
      }
    }
    return null;
  }
}

/// Un paquet d'un groupe de licence (vue allégée pour les rapports).
class LicensedPackage {
  final String name;
  final String version;
  final String purl;
  const LicensedPackage(this.name, this.version, this.purl);
}

/// Paquets partageant exactement la même expression de licence.
class LicenseGroup {
  final String license;
  final LicenseCategory category;
  final List<LicensedPackage> packages;
  const LicenseGroup(this.license, this.category, this.packages);
}

/// Résultat de l'analyse, indépendant du format de rendu.
class LicenseReport {
  final String title;
  final int totalPackages;
  final List<LicenseGroup> groups; // triés par licence
  final List<LicensedPackage> unknown; // sans licence, triés par nom
  final int strongCopyleftPackages;
  final int weakCopyleftPackages;
  final List<String> strongCopyleftTokens;
  final List<String> weakCopyleftTokens;

  const LicenseReport({
    required this.title,
    required this.totalPackages,
    required this.groups,
    required this.unknown,
    required this.strongCopyleftPackages,
    required this.weakCopyleftPackages,
    required this.strongCopyleftTokens,
    required this.weakCopyleftTokens,
  });
}

/// Generates an AsciiDoc license-compliance report from a list of [Package],
/// grouped by license with a summary and copyleft/unknown-license warnings.
///
/// Input packages are expected to already carry their license as read back
/// from a SBOM file (see `SbomReader`), i.e. an SPDX expression or the raw
/// string stored in the source document.
class LicenseReportGenerator {
  /// Regroupe [packages] par licence et calcule les compteurs copyleft.
  LicenseReport analyze(List<Package> packages, {String? documentName}) {
    final byLicense = <String, List<Package>>{};
    for (final pkg in packages) {
      final key = pkg.license.trim();
      byLicense.putIfAbsent(key, () => []).add(pkg);
    }

    final unknownPkgs = byLicense.remove('') ?? [];

    // Les expressions composées (« A AND B AND … ») sont fréquentes dans les
    // paquets Debian/RPM (toutes les licences trouvées dans les sources sont
    // concaténées). On les garde telles quelles comme clé de regroupement
    // (fidèle à ce qui est déclaré), mais l'avertissement copyleft liste les
    // identifiants individuels plutôt que ces chaînes composées, illisibles.
    var strongPackages = 0;
    var weakPackages = 0;
    final strongTokens = <String>{};
    final weakTokens = <String>{};
    for (final entry in byLicense.entries) {
      switch (classify(entry.key)) {
        case LicenseCategory.strongCopyleft:
          strongPackages += entry.value.length;
          strongTokens.addAll(
              _copyleftTokens(entry.key, LicenseCategory.strongCopyleft));
        case LicenseCategory.weakCopyleft:
          weakPackages += entry.value.length;
          weakTokens
              .addAll(_copyleftTokens(entry.key, LicenseCategory.weakCopyleft));
        case LicenseCategory.permissive:
        case LicenseCategory.unknown:
          break;
      }
    }

    LicensedPackage view(Package p) =>
        LicensedPackage(p.name, p.fullVersion, p.purl);
    List<LicensedPackage> sorted(List<Package> l) =>
        (List<Package>.from(l)..sort((a, b) => a.name.compareTo(b.name)))
            .map(view)
            .toList();

    final licenses = byLicense.keys.toList()..sort();
    return LicenseReport(
      title: documentName ?? 'Rapport de licences',
      totalPackages: packages.length,
      groups: [
        for (final l in licenses)
          LicenseGroup(l, classify(l), sorted(byLicense[l]!)),
      ],
      unknown: sorted(unknownPkgs),
      strongCopyleftPackages: strongPackages,
      weakCopyleftPackages: weakPackages,
      strongCopyleftTokens: strongTokens.toList()..sort(),
      weakCopyleftTokens: weakTokens.toList()..sort(),
    );
  }

  /// Rend le rapport dans le format demandé.
  String render(
    List<Package> packages, {
    String? documentName,
    LicenseReportFormat format = LicenseReportFormat.asciidoc,
  }) {
    final r = analyze(packages, documentName: documentName);
    return switch (format) {
      LicenseReportFormat.asciidoc => _asciidoc(r),
      LicenseReportFormat.markdown => _markdown(r),
      LicenseReportFormat.html => _html(r),
      LicenseReportFormat.csv => _csv(r),
      LicenseReportFormat.json => _json(r),
    };
  }

  Future<void> writeToFile(
    List<Package> packages,
    String outputPath, {
    String? documentName,
    LicenseReportFormat format = LicenseReportFormat.asciidoc,
  }) async {
    await File(outputPath).writeAsString(
        render(packages, documentName: documentName, format: format));
  }

  String _asciidoc(LicenseReport r) {
    final buf = StringBuffer();
    final title = r.title;
    final packagesLen = r.totalPackages;
    final unknown = r.unknown;
    final strongCopyleftPackages = r.strongCopyleftPackages;
    final weakCopyleftPackages = r.weakCopyleftPackages;
    final strongCopyleftTokens = r.strongCopyleftTokens;

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
    buf.writeln('| Paquets analysés | $packagesLen');
    buf.writeln('| Licences (expressions) distinctes | ${r.groups.length}');
    buf.writeln(
        '| Paquets sous licence copyleft fort (GPL/AGPL) | $strongCopyleftPackages');
    buf.writeln(
        '| Paquets sous licence copyleft faible (LGPL/MPL/EPL/CDDL/CPL/EUPL) | $weakCopyleftPackages');
    buf.writeln('| Paquets sans licence détectée | ${unknown.length}');
    buf.writeln('|===');
    buf.writeln();

    if (strongCopyleftTokens.isNotEmpty) {
      buf.writeln('[WARNING]');
      buf.writeln('====');
      buf.writeln(
          'Licences copyleft fort détectées ($strongCopyleftPackages paquet(s)) — '
          'la redistribution du logiciel combiné peut être soumise à '
          'obligation de publication du code source : '
          '${strongCopyleftTokens.join(', ')}.');
      buf.writeln('====');
      buf.writeln();
    }

    if (unknown.isNotEmpty) {
      buf.writeln('[NOTE]');
      buf.writeln('====');
      buf.writeln(
          '${unknown.length} paquet(s) sans licence détectée, à vérifier manuellement :');
      buf.writeln();
      for (final pkg in unknown) {
        buf.writeln('* ${_esc(pkg.name)} ${_esc(pkg.version)}');
      }
      buf.writeln('====');
      buf.writeln();
    }

    buf.writeln('== Détail par licence');
    buf.writeln();

    for (final g in r.groups) {
      buf.writeln(
          '=== ${_esc(g.license)}${_tag(g.category)} (${g.packages.length})');
      buf.writeln();
      for (final pkg in g.packages) {
        buf.writeln('* ${_esc(pkg.name)} ${_esc(pkg.version)}');
      }
      buf.writeln();
    }

    buf.writeln('_Généré par sbom_generator — $packagesLen paquet(s), '
        '${r.groups.length} licence(s) distincte(s)._');
    return buf.toString();
  }

  static String _tag(LicenseCategory c) => switch (c) {
        LicenseCategory.strongCopyleft => ' [copyleft fort]',
        LicenseCategory.weakCopyleft => ' [copyleft faible]',
        LicenseCategory.permissive || LicenseCategory.unknown => '',
      };

  String _markdown(LicenseReport r) {
    final buf = StringBuffer();
    String md(String x) => x.replaceAll('|', '\\|');
    buf.writeln('# ${r.title}');
    buf.writeln();
    buf.writeln('## Résumé');
    buf.writeln();
    buf.writeln('| Indicateur | Valeur |');
    buf.writeln('|---|---|');
    buf.writeln('| Paquets analysés | ${r.totalPackages} |');
    buf.writeln('| Licences (expressions) distinctes | ${r.groups.length} |');
    buf.writeln(
        '| Paquets sous licence copyleft fort (GPL/AGPL) | ${r.strongCopyleftPackages} |');
    buf.writeln(
        '| Paquets sous licence copyleft faible (LGPL/MPL/EPL/CDDL/CPL/EUPL) | ${r.weakCopyleftPackages} |');
    buf.writeln('| Paquets sans licence détectée | ${r.unknown.length} |');
    buf.writeln();
    if (r.strongCopyleftTokens.isNotEmpty) {
      buf.writeln('> **Attention** — licences copyleft fort détectées '
          '(${r.strongCopyleftPackages} paquet(s)) : la redistribution du '
          'logiciel combiné peut être soumise à obligation de publication '
          'du code source : ${r.strongCopyleftTokens.join(', ')}.');
      buf.writeln();
    }
    if (r.unknown.isNotEmpty) {
      buf.writeln('> **À vérifier** — ${r.unknown.length} paquet(s) sans '
          'licence détectée :');
      buf.writeln('>');
      for (final p in r.unknown) {
        buf.writeln('> * ${md(p.name)} ${md(p.version)}');
      }
      buf.writeln();
    }
    buf.writeln('## Détail par licence');
    buf.writeln();
    for (final g in r.groups) {
      buf.writeln(
          '### ${md(g.license)}${_tag(g.category)} (${g.packages.length})');
      buf.writeln();
      for (final p in g.packages) {
        buf.writeln('* ${md(p.name)} ${md(p.version)}');
      }
      buf.writeln();
    }
    buf.writeln('_Généré par sbom_generator — ${r.totalPackages} paquet(s), '
        '${r.groups.length} licence(s) distincte(s)._');
    return buf.toString();
  }

  String _html(LicenseReport r) {
    final h = const HtmlEscape();
    final buf = StringBuffer();
    buf.writeln('<!DOCTYPE html>');
    buf.writeln('<html lang="fr"><head><meta charset="utf-8">');
    buf.writeln('<title>${h.convert(r.title)}</title>');
    buf.writeln('<style>'
        'body{font-family:sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#222}'
        'table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.3rem .7rem;text-align:left}'
        '.warn{background:#fdecea;border-left:4px solid #d32f2f;padding:.5rem 1rem}'
        '.note{background:#fff8e1;border-left:4px solid #f9a825;padding:.5rem 1rem}'
        '.tag{font-size:.75rem;border-radius:3px;padding:0 .4rem;color:#fff}'
        '.strong{background:#d32f2f}.weak{background:#ef6c00}'
        '</style></head><body>');
    buf.writeln('<h1>${h.convert(r.title)}</h1>');
    buf.writeln('<h2>Résumé</h2><table>');
    void row(String k, Object v) =>
        buf.writeln('<tr><th>${h.convert(k)}</th><td>$v</td></tr>');
    row('Paquets analysés', r.totalPackages);
    row('Licences (expressions) distinctes', r.groups.length);
    row('Paquets sous licence copyleft fort (GPL/AGPL)',
        r.strongCopyleftPackages);
    row('Paquets sous licence copyleft faible (LGPL/MPL/EPL/CDDL/CPL/EUPL)',
        r.weakCopyleftPackages);
    row('Paquets sans licence détectée', r.unknown.length);
    buf.writeln('</table>');
    if (r.strongCopyleftTokens.isNotEmpty) {
      buf.writeln('<p class="warn"><strong>Attention</strong> — licences '
          'copyleft fort détectées (${r.strongCopyleftPackages} paquet(s)) : '
          'la redistribution du logiciel combiné peut être soumise à '
          'obligation de publication du code source : '
          '${h.convert(r.strongCopyleftTokens.join(', '))}.</p>');
    }
    if (r.unknown.isNotEmpty) {
      buf.writeln('<div class="note"><strong>À vérifier</strong> — '
          '${r.unknown.length} paquet(s) sans licence détectée :<ul>');
      for (final p in r.unknown) {
        buf.writeln('<li>${h.convert('${p.name} ${p.version}')}</li>');
      }
      buf.writeln('</ul></div>');
    }
    buf.writeln('<h2>Détail par licence</h2>');
    for (final g in r.groups) {
      final tag = switch (g.category) {
        LicenseCategory.strongCopyleft =>
          ' <span class="tag strong">copyleft fort</span>',
        LicenseCategory.weakCopyleft =>
          ' <span class="tag weak">copyleft faible</span>',
        _ => '',
      };
      buf.writeln(
          '<h3>${h.convert(g.license)}$tag (${g.packages.length})</h3><ul>');
      for (final p in g.packages) {
        buf.writeln('<li>${h.convert('${p.name} ${p.version}')}</li>');
      }
      buf.writeln('</ul>');
    }
    buf.writeln('<p><em>Généré par sbom_generator — ${r.totalPackages} '
        'paquet(s), ${r.groups.length} licence(s) distincte(s).</em></p>');
    buf.writeln('</body></html>');
    return buf.toString();
  }

  static String _categoryName(LicenseCategory c) => switch (c) {
        LicenseCategory.strongCopyleft => 'strong-copyleft',
        LicenseCategory.weakCopyleft => 'weak-copyleft',
        LicenseCategory.permissive => 'permissive',
        LicenseCategory.unknown => 'unknown',
      };

  String _csv(LicenseReport r) {
    String q(String x) =>
        RegExp(r'[",\r\n]').hasMatch(x) ? '"${x.replaceAll('"', '""')}"' : x;
    final buf = StringBuffer('license,category,name,version,purl\r\n');
    for (final g in r.groups) {
      for (final p in g.packages) {
        buf.write('${q(g.license)},${_categoryName(g.category)},${q(p.name)},'
            '${q(p.version)},${q(p.purl)}\r\n');
      }
    }
    for (final p in r.unknown) {
      buf.write(',unknown,${q(p.name)},${q(p.version)},${q(p.purl)}\r\n');
    }
    return buf.toString();
  }

  String _json(LicenseReport r) {
    Map<String, String> pkg(LicensedPackage p) =>
        {'name': p.name, 'version': p.version, 'purl': p.purl};
    return const JsonEncoder.withIndent('  ').convert({
      'name': r.title,
      'summary': {
        'packages': r.totalPackages,
        'distinctLicenses': r.groups.length,
        'strongCopyleftPackages': r.strongCopyleftPackages,
        'weakCopyleftPackages': r.weakCopyleftPackages,
        'unknownPackages': r.unknown.length,
      },
      'strongCopyleftLicenses': r.strongCopyleftTokens,
      'weakCopyleftLicenses': r.weakCopyleftTokens,
      'licenses': [
        for (final g in r.groups)
          {
            'license': g.license,
            'category': _categoryName(g.category),
            'packages': g.packages.map(pkg).toList(),
          },
      ],
      'unknown': r.unknown.map(pkg).toList(),
    });
  }

  /// Splits a (possibly compound "A AND B OR C") license expression into
  /// individual tokens and returns those whose own classification matches
  /// [target]. Used to keep the copyleft warning list readable instead of
  /// dumping entire compound expressions.
  static Iterable<String> _copyleftTokens(
      String license, LicenseCategory target) {
    final tokens =
        license.split(RegExp(r'\s+(AND|OR)\s+', caseSensitive: false));
    return tokens
        .map((t) => t.trim())
        .where((t) => t.isNotEmpty && classify(t) == target);
  }

  /// Classification heuristique d'une expression de licence.
  static LicenseCategory classify(String license) {
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
