import 'dart:io';

/// Builds a cross-scanner vulnerability *synthesis* report (Markdown /
/// AsciiDoc) from the normalised results of `sbom_generator scan`.
///
/// Mirrors the GUI "Tableau de bord" export: a global summary, a
/// severity breakdown per scanner, and a cross-scanner CVE presence matrix.
/// The AsciiDoc form is what feeds `asciidoctor-pdf` (see
/// [renderAsciiDocToPdf]).
///
/// Each finding is the `{id, severity, package, published, modified}` map
/// produced by the scanner runners in `bin/sbom_generator.dart`. A `null`
/// list for a scanner key means "not run / failed"; an empty list means
/// "ran, no findings".
class ScanReportGenerator {
  final String sbomPath;
  final Map<String, List<Map<String, dynamic>>?> resultsByScanner;
  final DateTime generatedAt;
  final Map<String, String?> toolVersions;

  ScanReportGenerator({
    required this.sbomPath,
    required this.resultsByScanner,
    DateTime? generatedAt,
    this.toolVersions = const {},
  }) : generatedAt = generatedAt ?? DateTime.now();

  static const _scannerOrder = ['grype', 'osv', 'trivy'];
  static const _scannerLabels = {
    'grype': 'Grype',
    'osv': 'OSV-Scanner',
    'trivy': 'Trivy',
  };

  // OSV-Scanner sometimes prefixes a CVE with the distro advisory origin
  // (`DEBIAN-CVE-2026-13221`) where Grype/Trivy report the bare id — strip a
  // leading `<PREFIX>-` so the cross-scanner match is not fooled into
  // counting the same vulnerability twice (same rationale as the GUI).
  static final RegExp _distroPrefixedCveRe =
      RegExp(r'^[A-Z]+-(CVE-\d{4}-\d+)$');

  static String _normalizeId(String id) =>
      _distroPrefixedCveRe.firstMatch(id)?.group(1) ?? id;

  static int _sevOrd(String s) => switch (s.toLowerCase()) {
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        'low' => 3,
        _ => 4,
      };

  Iterable<String> get _scannersRun =>
      _scannerOrder.where((s) => resultsByScanner[s] != null);

  int get _uniqueCveCount {
    final ids = <String>{};
    for (final s in _scannersRun) {
      for (final v in resultsByScanner[s]!) {
        ids.add(_normalizeId((v['id'] as String?) ?? ''));
      }
    }
    ids.remove('');
    return ids.length;
  }

  int get _totalFindings =>
      _scannersRun.fold(0, (n, s) => n + resultsByScanner[s]!.length);

  /// severity → count, for one scanner's findings.
  Map<String, int> _severityCounts(List<Map<String, dynamic>> vulns) {
    final counts = <String, int>{};
    for (final v in vulns) {
      final raw = ((v['severity'] as String?) ?? '').toLowerCase();
      final key = const {'critical', 'high', 'medium', 'low'}.contains(raw)
          ? raw
          : 'autre';
      counts[key] = (counts[key] ?? 0) + 1;
    }
    return counts;
  }

  /// CVE (id normalisé) → premier paquet non vide vu par un scanner.
  Map<String, String> get _packageById {
    final m = <String, String>{};
    for (final s in _scannerOrder) {
      for (final v in resultsByScanner[s] ?? const []) {
        final id = _normalizeId((v['id'] as String?) ?? '');
        final pkg = (v['package'] as String?) ?? '';
        if (id.isNotEmpty && pkg.isNotEmpty && pkg != '@') {
          m.putIfAbsent(id, () => pkg);
        }
      }
    }
    return m;
  }

  /// CVE (id normalisé) → note explicative, pour les cas où Grype ne voit
  /// aucun correctif pour la distribution installée (« won't fix » /
  /// « not fixed », statut `<no-dsa>` du Debian Security Tracker) alors
  /// qu'OSV-Scanner ou Trivy annoncent une version corrigée — laquelle est,
  /// pour un avis de distribution, généralement le correctif porté dans les
  /// branches *unstable* / *testing*, pas une mise à jour installable sur la
  /// release stable en place. Confusion fréquente : la note lève l'ambiguïté.
  Map<String, String> cveNotes() {
    final grype = resultsByScanner['grype'];
    if (grype == null) return const {};

    // Grype : la CVE dispose-t-elle d'un correctif exploitable ?
    final grypeSeen = <String>{};
    final grypeHasFix = <String, bool>{};
    for (final v in grype) {
      final id = _normalizeId((v['id'] as String?) ?? '');
      if (id.isEmpty) continue;
      grypeSeen.add(id);
      final state = ((v['fixState'] as String?) ?? '').toLowerCase();
      final vers = (v['fixedVersions'] as List?) ?? const [];
      final hasFix = state == 'fixed' || vers.isNotEmpty;
      grypeHasFix[id] = (grypeHasFix[id] ?? false) || hasFix;
    }

    // OSV-Scanner / Trivy : versions corrigées annoncées, par scanner.
    final fixedBy = <String, Map<String, Set<String>>>{};
    for (final s in const ['osv', 'trivy']) {
      for (final v in resultsByScanner[s] ?? const []) {
        final id = _normalizeId((v['id'] as String?) ?? '');
        if (id.isEmpty) continue;
        final vers = ((v['fixedVersions'] as List?) ?? const [])
            .map((e) => '$e')
            .where((e) => e.isNotEmpty)
            .toSet();
        if (vers.isEmpty) continue;
        ((fixedBy[id] ??= {})[s] ??= <String>{}).addAll(vers);
      }
    }

    final notes = <String, String>{};
    for (final id in grypeSeen) {
      if (grypeHasFix[id] == true) continue;
      final fb = fixedBy[id];
      if (fb == null || fb.isEmpty) continue;
      final vers = <String>{for (final vs in fb.values) ...vs}.toList()..sort();
      final who = fb.keys.map((s) => _scannerLabels[s]).join(' / ');
      notes[id] = 'Grype ne voit aucun correctif pour la distribution '
          'installée (« won\'t fix » / « non corrigé »). $who annonce une '
          'version corrigée (${vers.map((v) => '`$v`').join(', ')}) : pour un '
          'avis de distribution, il s\'agit en général du correctif porté dans '
          'les branches *unstable* / *testing*, pas d\'une mise à jour '
          'disponible pour la release stable en place.';
    }
    return notes;
  }

  /// One row per unique (normalised) CVE across every scanner that ran,
  /// sorted by worst severity first.
  List<_CrossRow> _crossRows() {
    final idsByScanner = {
      for (final s in _scannersRun)
        s: {
          for (final v in resultsByScanner[s]!)
            _normalizeId((v['id'] as String?) ?? '')
        }..remove(''),
    };
    final sevByScanner = {
      for (final s in _scannersRun)
        s: <String, String>{
          for (final v in resultsByScanner[s]!)
            _normalizeId((v['id'] as String?) ?? ''):
                (v['severity'] as String?) ?? '',
        },
    };
    // Premier paquet non vide rencontré pour chaque CVE (tous scanners).
    final pkgById = _packageById;
    final all = <String>{for (final ids in idsByScanner.values) ...ids}.toList();

    // Sévérité affichée = la pire rapportée par un scanner quelconque
    // (un CVE "HIGH" chez Trivy et "Unknown" chez Grype reste un HIGH).
    String worstSeverity(String id) {
      String best = '';
      var bestOrd = 5;
      for (final s in _scannerOrder) {
        final sev = sevByScanner[s]?[id];
        if (sev == null || sev.isEmpty) continue;
        final o = _sevOrd(sev);
        if (o < bestOrd) {
          bestOrd = o;
          best = sev;
        }
      }
      return best;
    }

    all.sort((a, b) {
      final c = _sevOrd(worstSeverity(a)).compareTo(_sevOrd(worstSeverity(b)));
      return c != 0 ? c : a.compareTo(b);
    });

    return [
      for (final id in all)
        _CrossRow(
          id: id,
          severity: worstSeverity(id),
          package: pkgById[id] ?? '',
          present: {for (final s in _scannerOrder) s: idsByScanner[s]?.contains(id) ?? false},
        ),
    ];
  }

  /// CVE uniques (toutes sources confondues) dont la pire sévérité est dans
  /// [keep] — pour un affichage d'alerte en console pendant un build.
  List<ScanAlert> alerts(
      {Set<String> keep = const {'critical', 'high'}}) {
    return [
      for (final r in _crossRows())
        if (keep.contains(r.severity.toLowerCase()))
          ScanAlert(
            id: r.id,
            severity: r.severity,
            package: r.package,
            scanners: [
              for (final s in _scannerOrder)
                if (r.present[s] ?? false) _scannerLabels[s]!,
            ],
          ),
    ];
  }

  // ── Markdown ─────────────────────────────────────────────────────────────

  String toMarkdown() {
    final b = StringBuffer();
    final run = _scannersRun.toList();
    b.writeln('# Rapport de synthèse — vulnérabilités du SBOM');
    b.writeln();
    b.writeln('- **SBOM analysé :** `${_mdEsc(sbomPath)}`');
    b.writeln('- **Généré le :** ${_timestamp()}');
    b.writeln();

    b.writeln('## Résumé global');
    b.writeln();
    b.writeln('| Indicateur | Valeur |');
    b.writeln('|---|---|');
    b.writeln('| Scanners exécutés | ${run.length} / 3'
        '${run.isEmpty ? "" : " (${run.map((s) => _scannerLabels[s]).join(', ')})"} |');
    b.writeln('| CVE uniques (tous scanners) | $_uniqueCveCount |');
    b.writeln('| Résultats bruts cumulés | $_totalFindings |');
    b.writeln();

    if (toolVersions.isNotEmpty) {
      b.writeln('## Outils');
      b.writeln();
      b.writeln('| Outil | Version |');
      b.writeln('|---|---|');
      toolVersions.forEach((k, v) =>
          b.writeln('| ${_mdEsc(k)} | ${_mdEsc(v ?? "inconnue")} |'));
      b.writeln();
    }

    b.writeln('## Répartition par scanner');
    b.writeln();
    for (final s in _scannerOrder) {
      b.writeln('### ${_scannerLabels[s]}');
      b.writeln();
      final vulns = resultsByScanner[s];
      if (vulns == null) {
        b.writeln('_Non exécuté._');
      } else if (vulns.isEmpty) {
        b.writeln('Aucune vulnérabilité détectée.');
      } else {
        final counts = _severityCounts(vulns);
        b.writeln('| Sévérité | Nombre |');
        b.writeln('|---|---|');
        for (final sev in const ['critical', 'high', 'medium', 'low', 'autre']) {
          if ((counts[sev] ?? 0) > 0) {
            b.writeln('| ${sev == 'autre' ? 'Autre' : sev.toUpperCase()} | ${counts[sev]} |');
          }
        }
        b.writeln('| **Total** | **${vulns.length}** |');
      }
      b.writeln();
    }

    if (run.length >= 2) {
      b.writeln('## Comparaison inter-scanners');
      b.writeln();
      final rows = _crossRows();
      if (rows.isEmpty) {
        b.writeln('_Aucune CVE détectée par les scanners exécutés._');
      } else {
        b.writeln('| Sévérité | CVE / ID | Grype | OSV-Scanner | Trivy |');
        b.writeln('|---|---|:-:|:-:|:-:|');
        for (final r in rows) {
          b.writeln('| ${r.severity.isEmpty ? "?" : r.severity.toUpperCase()} '
              '| ${_mdEsc(r.id)} '
              '| ${r.present['grype']! ? '✓' : '—'} '
              '| ${r.present['osv']! ? '✓' : '—'} '
              '| ${r.present['trivy']! ? '✓' : '—'} |');
        }
      }
      b.writeln();
      b.writeln('> Des comptages très différents entre scanners sur les paquets '
          'système (Debian/Alpine/RPM) ne signalent pas forcément une erreur : '
          'OSV-Scanner en mode « scan de SBOM » peut ne trouver aucune CVE sur '
          'ces paquets, et Grype/Trivy n\'ont pas la même exhaustivité sur les '
          'avis distro. Voir la documentation, section « Pourquoi Grype, '
          'OSV-Scanner et Trivy ne trouvent pas les mêmes CVE ».');
      b.writeln();

      final notes = cveNotes();
      if (notes.isNotEmpty) {
        final pkgById = _packageById;
        b.writeln('### Notes par CVE');
        b.writeln();
        for (final r in rows) {
          final n = notes[r.id];
          if (n == null) continue;
          final pkg = pkgById[r.id] ?? '';
          b.writeln('- **${_mdEsc(r.id)}**'
              '${pkg.isEmpty ? '' : ' (`${_mdEsc(pkg)}`)'} — $n');
        }
        b.writeln();
      }
    }

    b.writeln('---');
    b.writeln();
    b.writeln('_Généré par sbom-generator._');
    return b.toString();
  }

  // ── AsciiDoc ─────────────────────────────────────────────────────────────

  String toAsciiDoc() {
    final b = StringBuffer();
    final run = _scannersRun.toList();
    b.writeln('= Rapport de synthèse — vulnérabilités du SBOM');
    b.writeln(':doctype: article');
    b.writeln(':toc:');
    b.writeln(':toc-title: Sommaire');
    b.writeln(':toclevels: 1');
    b.writeln(':icons: font');
    b.writeln();
    b.writeln('SBOM analysé : `${_adocEsc(sbomPath)}` +');
    b.writeln('Généré le : ${_timestamp()}');
    b.writeln();

    b.writeln('== Résumé global');
    b.writeln();
    b.writeln('[cols="<3,<1",options="header"]');
    b.writeln('|===');
    b.writeln('| Indicateur | Valeur');
    b.writeln('| Scanners exécutés | ${run.length} / 3');
    b.writeln('| CVE uniques (tous scanners confondus) | $_uniqueCveCount');
    b.writeln('| Résultats bruts cumulés | $_totalFindings');
    b.writeln('|===');
    b.writeln();

    if (toolVersions.isNotEmpty) {
      b.writeln('== Outils');
      b.writeln();
      b.writeln('[cols="<3,<1",options="header"]');
      b.writeln('|===');
      b.writeln('| Outil | Version');
      toolVersions.forEach((k, v) =>
          b.writeln('| ${_adocEsc(k)} | ${_adocEsc(v ?? "inconnue")}'));
      b.writeln('|===');
      b.writeln();
    }

    b.writeln('== Répartition par scanner');
    b.writeln();
    for (final s in _scannerOrder) {
      b.writeln('=== ${_scannerLabels[s]}');
      b.writeln();
      final vulns = resultsByScanner[s];
      if (vulns == null) {
        b.writeln('_Non exécuté._');
      } else if (vulns.isEmpty) {
        b.writeln('Aucune vulnérabilité détectée.');
      } else {
        final counts = _severityCounts(vulns);
        b.writeln('[cols="<2,<1",options="header"]');
        b.writeln('|===');
        b.writeln('| Sévérité | Nombre');
        for (final sev in const ['critical', 'high', 'medium', 'low', 'autre']) {
          if ((counts[sev] ?? 0) > 0) {
            b.writeln('| ${_sevBadge(sev)} | ${counts[sev]}');
          }
        }
        b.writeln('| *Total* | *${vulns.length}*');
        b.writeln('|===');
      }
      b.writeln();
    }

    if (run.length >= 2) {
      b.writeln('== Comparaison inter-scanners');
      b.writeln();
      final rows = _crossRows();
      if (rows.isEmpty) {
        b.writeln('_Aucune CVE détectée par les scanners exécutés._');
      } else {
        b.writeln('[cols="<1,<3,^1,^1,^1",options="header"]');
        b.writeln('|===');
        b.writeln('| Sévérité | CVE / ID | Grype | OSV-Scanner | Trivy');
        for (final r in rows) {
          b.writeln('| ${_sevBadge(r.severity)} '
              '| ${_adocEsc(r.id)} '
              '| ${r.present['grype']! ? '✓' : '—'} '
              '| ${r.present['osv']! ? '✓' : '—'} '
              '| ${r.present['trivy']! ? '✓' : '—'}');
        }
        b.writeln('|===');
      }
      b.writeln();
      b.writeln('[NOTE]');
      b.writeln('====');
      b.writeln('Des comptages très différents entre scanners sur les paquets '
          'système (Debian/Alpine/RPM) ne signalent pas forcément une erreur. '
          'OSV-Scanner en mode « scan de SBOM » peut ne trouver aucune CVE sur '
          'ces paquets (son API n\'indexe les avis distro que sous une forme de '
          'purl absente du SBOM standard). Grype et Trivy n\'ont par ailleurs '
          'pas la même exhaustivité sur ces mêmes paquets : Grype reprend '
          'l\'intégralité du Debian Security Tracker (avis « won\'t fix » '
          'inclus) là où Trivy ne remonte qu\'un sous-ensemble. Voir la '
          'documentation utilisateur, section « Pourquoi Grype, OSV-Scanner et '
          'Trivy ne trouvent pas les mêmes CVE ».');
      b.writeln('====');
      b.writeln();

      final notes = cveNotes();
      if (notes.isNotEmpty) {
        final pkgById = _packageById;
        b.writeln('=== Notes par CVE');
        b.writeln();
        for (final r in rows) {
          final n = notes[r.id];
          if (n == null) continue;
          final pkg = pkgById[r.id] ?? '';
          b.writeln('* *${_adocEsc(r.id)}*'
              '${pkg.isEmpty ? '' : ' (`${_adocEsc(pkg)}`)'} — $n');
        }
        b.writeln();
      }
    }

    b.writeln('_Généré par sbom-generator._');
    return b.toString();
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  String _timestamp() {
    final d = generatedAt.toUtc();
    String p(int n) => n.toString().padLeft(2, '0');
    return '${d.year}-${p(d.month)}-${p(d.day)} ${p(d.hour)}:${p(d.minute)} UTC';
  }

  static String _mdEsc(String s) => s.replaceAll('|', r'\|');
  static String _adocEsc(String s) => s.replaceAll('|', r'\|');

  static String _sevBadge(String severity) {
    final role = switch (severity.toLowerCase()) {
      'critical' => 'sev-critical',
      'high' => 'sev-high',
      'medium' => 'sev-medium',
      'low' => 'sev-low',
      _ => 'sev-other',
    };
    final label = severity.isEmpty ? '?' : severity.toUpperCase();
    return '[.$role]#$label#';
  }
}

class _CrossRow {
  final String id;
  final String severity;
  final String package;
  final Map<String, bool> present;
  _CrossRow(
      {required this.id,
      required this.severity,
      required this.package,
      required this.present});
}

/// Une CVE unique au-dessus d'un seuil de sévérité, pour l'affichage d'alerte.
class ScanAlert {
  final String id;
  final String severity;
  final String package;
  final List<String> scanners;
  ScanAlert({
    required this.id,
    required this.severity,
    required this.package,
    required this.scanners,
  });
}

// ── AsciiDoc → PDF ─────────────────────────────────────────────────────────

const String _kPdfThemeYaml = '''
extends: default
page:
  margin: [2cm, 1.8cm, 2cm, 1.8cm]
base:
  font_color: 263238
  font_size: 10.5
  line_height: 1.35
heading:
  font_color: 0D47A1
  font_style: bold
  h1:
    font_size: 20
    border_bottom_width: 0.75
    border_bottom_color: 1565C0
  h2:
    font_size: 15
    font_color: 1565C0
    margin_top: 18
    border_bottom_width: 0.5
    border_bottom_color: CFD8DC
  h3:
    font_size: 12
    font_color: 00695C
toc:
  font_color: 37474F
  dot_leader:
    font_color: CFD8DC
table:
  border_color: CFD8DC
  border_width: 0.5
  head:
    background_color: 1565C0
    font_color: FFFFFF
    font_style: bold
  even_row:
    background_color: F5F7FA
role:
  sev-critical:
    background_color: B71C1C
    font_color: FFFFFF
    font_style: bold
  sev-high:
    background_color: BF360C
    font_color: FFFFFF
    font_style: bold
  sev-medium:
    background_color: E65100
    font_color: FFFFFF
    font_style: bold
  sev-low:
    background_color: 2E7D32
    font_color: FFFFFF
    font_style: bold
  sev-other:
    background_color: 607D8B
    font_color: FFFFFF
    font_style: bold
''';

/// Converts an AsciiDoc file to PDF via `asciidoctor-pdf` (with the shared
/// theme). Returns the process result; throws [ProcessException] if the
/// executable is not found — callers keep the `.adoc` and warn.
Future<ProcessResult> renderAsciiDocToPdf(
    String adocPath, String pdfPath) async {
  final theme = File(
      '${Directory.systemTemp.path}/sbom_generator_scan_pdf_theme.yml');
  await theme.writeAsString(_kPdfThemeYaml);
  return Process.run(
      'asciidoctor-pdf', [adocPath, '-o', pdfPath, '-a', 'pdf-theme=${theme.path}']);
}
