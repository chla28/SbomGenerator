import 'dart:io';

import 'layer_scan.dart';
import 'vuln_enrichment.dart';

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

  /// Signaux d'exploitabilité / exploitation active par CVE (id normalisé).
  /// Vide = enrichissement non exécuté : les sections/colonnes dédiées sont
  /// alors omises.
  final Map<String, ExploitInfo> exploitById;

  /// Couches de l'image (`scan --per-layer`) : les résultats portent alors une
  /// clé `layer` (index). Vide = rapport sans section « Couches ».
  final List<LayerRef> layers;

  /// Méthode de `--per-layer` : `attribute` ou `each` (voir `layer_scan.dart`).
  final String? layerScanMode;

  ScanReportGenerator({
    required this.sbomPath,
    required this.resultsByScanner,
    DateTime? generatedAt,
    this.toolVersions = const {},
    this.exploitById = const {},
    this.layers = const [],
    this.layerScanMode,
  }) : generatedAt = generatedAt ?? DateTime.now();

  bool get _hasLayers => layers.isNotEmpty;

  /// Index des couches où chaque CVE (id normalisé) a été trouvée.
  Map<String, Set<int>> get _layersById {
    final m = <String, Set<int>>{};
    for (final vulns in resultsByScanner.values) {
      for (final v in vulns ?? const <Map<String, dynamic>>[]) {
        final i = v['layer'];
        final id = _normalizeId((v['id'] as String?) ?? '');
        if (i is int && id.isNotEmpty) (m[id] ??= {}).add(i);
      }
    }
    return m;
  }

  String _layersCell(Map<String, Set<int>> byId, String id) {
    final l = (byId[id]?.toList() ?? const <int>[])..sort();
    return l.isEmpty ? '—' : l.join(', ');
  }

  String get _layerModeText => switch (layerScanMode) {
        'each' => 'SBOM de chaque couche scanné séparément : une CVE est '
            'comptée dans chaque couche qui apporte le paquet vulnérable, '
            'y compris une version remplacée plus haut dans la pile',
        _ => 'un seul scan du SBOM global, chaque CVE rattachée à la couche '
            'qui a introduit son paquet (CVE de l\'image finale uniquement)',
      };

  static String _short(String s, int max) =>
      s.length <= max ? s : '${s.substring(0, max - 1)}…';

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

  // ── Exploitabilité / exploitation active ─────────────────────────────────

  /// Seuil EPSS au-delà duquel une CVE est comptée « à surveiller ».
  static const epssWatchThreshold = 0.10;

  ExploitInfo _exploitFor(String id) =>
      exploitById[id] ?? ExploitInfo.empty;

  /// L'enrichissement a-t-il produit au moins un signal exploitable ?
  bool get hasExploitData =>
      exploitById.values.any((e) => e.hasAnySignal);

  int get _kevCount => _crossRows().where((r) => _exploitFor(r.id).inKev).length;

  int get _epssWatchCount => _crossRows()
      .where((r) => (_exploitFor(r.id).epssScore ?? 0) >= epssWatchThreshold)
      .length;

  int get _pocCount =>
      _crossRows().where((r) => _exploitFor(r.id).pocKnown).length;

  /// Une CVE mérite-t-elle de figurer dans la « Priorisation par risque » ?
  /// (KEV, PoC public, ou EPSS au-dessus du seuil de veille.)
  bool _isPrioritised(String id) {
    final e = _exploitFor(id);
    return e.inKev ||
        e.pocKnown ||
        (e.epssScore ?? 0) >= epssWatchThreshold;
  }

  /// Lignes inter-scanners avec au moins un signal d'exploitation notable,
  /// ordonnées par risque décroissant (KEV, puis EPSS, puis sévérité).
  List<_CrossRow> _riskRows() {
    final rows =
        _crossRows().where((r) => _isPrioritised(r.id)).toList();
    rows.sort((a, b) {
      final ra = _exploitFor(a.id).riskScore(a.severity);
      final rb = _exploitFor(b.id).riskScore(b.severity);
      final c = rb.compareTo(ra);
      return c != 0 ? c : a.id.compareTo(b.id);
    });
    return rows;
  }

  /// Nombre de CVE écartées de la « Priorisation par risque » faute de signal.
  int get _riskRowsOmitted =>
      _crossRows().where((r) => !_isPrioritised(r.id)).length;

  /// `0.97 (p99)` / `—`.
  static String _fmtEpss(ExploitInfo e) {
    if (e.epssScore == null) return '—';
    final pct = ((e.epssPercentile ?? 0) * 100).round();
    return '${e.epssScore!.toStringAsFixed(2)} (p$pct)';
  }

  static String _fmtDate(DateTime? d) {
    if (d == null) return '—';
    String p(int n) => n.toString().padLeft(2, '0');
    return '${d.year}-${p(d.month)}-${p(d.day)}';
  }

  /// `2.8` / `—`, éventuellement suffixé de la maturité de l'exploit.
  static String _fmtExploitability(ExploitInfo e) {
    final parts = <String>[];
    if (e.cvssExploitabilityScore != null) {
      parts.add(e.cvssExploitabilityScore!.toStringAsFixed(1));
    }
    if (e.exploitMaturity != null) parts.add('mat. ${e.exploitMaturity}');
    return parts.isEmpty ? '—' : parts.join(', ');
  }

  static String _fmtPoc(ExploitInfo e) {
    if (e.pocCount > 0) return '${e.pocCount} dépôt(s)';
    if (e.pocKnown) return 'oui';
    return '—';
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
    if (hasExploitData) {
      b.writeln('| CVE activement exploitées (CISA KEV) | $_kevCount |');
      b.writeln('| CVE avec EPSS ≥ '
          '${(epssWatchThreshold * 100).round()} % | $_epssWatchCount |');
      b.writeln('| CVE avec PoC / exploit public | $_pocCount |');
    }
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

    if (_hasLayers) {
      b.writeln('## Couches de l\'image');
      b.writeln();
      b.writeln('Méthode : $_layerModeText.');
      b.writeln();
      b.writeln('| Couche | Digest | Instruction | CVE | Critiques | Élevées |');
      b.writeln('|---|---|---|--:|--:|--:|');
      for (final l in summarizeByLayer(resultsByScanner, layers)) {
        b.writeln('| ${l.layer.index} | `${l.layer.shortDigest}` '
            '| ${_mdEsc(_short(l.layer.createdBy ?? '—', 90))} '
            '| ${l.total} | ${l.count('critical')} | ${l.count('high')} |');
      }
      b.writeln();
    }

    if (run.length >= 2) {
      b.writeln('## Comparaison inter-scanners');
      b.writeln();
      final rows = _crossRows();
      final layersById = _layersById;
      if (rows.isEmpty) {
        b.writeln('_Aucune CVE détectée par les scanners exécutés._');
      } else {
        b.writeln('| Sévérité | CVE / ID | Grype | OSV-Scanner | Trivy |'
            '${_hasLayers ? ' Couche(s) |' : ''}');
        b.writeln('|---|---|:-:|:-:|:-:|${_hasLayers ? '---|' : ''}');
        for (final r in rows) {
          b.writeln('| ${r.severity.isEmpty ? "?" : r.severity.toUpperCase()} '
              '| ${_mdEsc(r.id)} '
              '| ${r.present['grype']! ? '✓' : '—'} '
              '| ${r.present['osv']! ? '✓' : '—'} '
              '| ${r.present['trivy']! ? '✓' : '—'} |'
              '${_hasLayers ? ' ${_layersCell(layersById, r.id)} |' : ''}');
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

    if (hasExploitData) {
      final pkgById = _packageById;
      b.writeln('## Exploitabilité et exploitation active');
      b.writeln();

      final kevRows =
          _riskRows().where((r) => _exploitFor(r.id).inKev).toList();
      if (kevRows.isNotEmpty) {
        b.writeln('### CVE activement exploitées (CISA KEV)');
        b.writeln();
        b.writeln('| CVE / ID | Paquet | Ajout KEV | Échéance | Rançongiciel |');
        b.writeln('|---|---|---|---|:-:|');
        for (final r in kevRows) {
          final e = _exploitFor(r.id);
          b.writeln('| ${_mdEsc(r.id)} '
              '| ${_mdEsc(pkgById[r.id] ?? r.package)} '
              '| ${_fmtDate(e.kevDateAdded)} '
              '| ${_fmtDate(e.kevDueDate)} '
              '| ${e.kevRansomware ? '⚠️ oui' : '—'} |');
        }
        b.writeln();
      }

      b.writeln('### Priorisation par risque');
      b.writeln();
      final riskRows = _riskRows();
      if (riskRows.isEmpty) {
        b.writeln('_Aucune CVE avec signal d\'exploitation notable '
            '(CISA KEV, PoC public, ou EPSS ≥ '
            '${(epssWatchThreshold * 100).round()} %)._');
        b.writeln();
      } else {
        b.writeln('CVE avec un signal d\'exploitation notable, ordonnées par : '
            'KEV, puis probabilité EPSS, puis sévérité.');
        b.writeln();
        b.writeln('| CVE / ID | Sévérité | Paquet | KEV | EPSS | Exploitabilité CVSS | PoC public |');
        b.writeln('|---|---|---|:-:|---|---|---|');
        for (final r in riskRows) {
          final e = _exploitFor(r.id);
          b.writeln('| ${_mdEsc(r.id)} '
              '| ${r.severity.isEmpty ? "?" : r.severity.toUpperCase()} '
              '| ${_mdEsc(pkgById[r.id] ?? r.package)} '
              '| ${e.inKev ? '✓' : '—'} '
              '| ${_fmtEpss(e)} '
              '| ${_fmtExploitability(e)} '
              '| ${_fmtPoc(e)} |');
        }
        b.writeln();
        if (_riskRowsOmitted > 0) {
          b.writeln('> $_riskRowsOmitted autre(s) CVE sans signal d\'exploitation '
              'notable ne sont pas listées ici (voir la matrice ci-dessus).');
          b.writeln();
        }
      }
      b.writeln('> **KEV** : CVE au catalogue CISA Known Exploited '
          'Vulnerabilities — exploitation active confirmée. **EPSS** : '
          'probabilité d\'exploitation dans les 30 jours (score et percentile, '
          'FIRST.org). **Exploitabilité CVSS** : sous-score AV/AC/PR/UI (0–3,9) '
          'et maturité de l\'exploit quand elle est publiée. **PoC public** : '
          'dépôt(s) d\'exploit recensé(s).');
      b.writeln();
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
    final sbomName = sbomPath.split(RegExp(r'[/\\]')).last;
    b.writeln('= Rapport de vulnérabilités: Synthèse inter-scanners');
    b.writeln('sbom-generator');
    b.writeln(':doctype: article');
    b.writeln(':title-page:');
    b.writeln(':toc:');
    b.writeln(':toc-title: Sommaire');
    b.writeln(':toclevels: 2');
    b.writeln(':revdate: ${_frenchDate()}');
    b.writeln(':icons: font');
    b.writeln();

    b.writeln('== Résumé exécutif');
    b.writeln();
    b.writeln('*SBOM analysé* : `${_adocEsc(sbomName)}` +');
    b.writeln('*Scanners exécutés* : ${run.length} / 3'
        '${run.isEmpty ? '' : ' (${run.map((s) => _scannerLabels[s]).join(', ')})'}'
        ' — *$_uniqueCveCount* CVE uniques');
    b.writeln();
    final crit = _crossSevCount('critical');
    final high = _crossSevCount('high');
    b.writeln('[cols="^1,^1,^1,^1",frame=none,grid=cols]');
    b.writeln('|===');
    b.writeln('h| Critiques h| Élevées h| CISA KEV h| EPSS >= '
        '${(epssWatchThreshold * 100).round()} %');
    b.writeln('| [.${crit > 0 ? 'h1-num-alert' : 'h1-num'}]*$crit* '
        '| [.h1-num]*$high* '
        '| [.${_kevCount > 0 ? 'h1-num-alert' : 'h1-num'}]*$_kevCount* '
        '| [.h1-num]*$_epssWatchCount*');
    b.writeln('|===');
    b.writeln();
    final (verdictRole, verdictText) = _verdict();
    b.writeln('[.$verdictRole]*$verdictText*');
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

    if (_hasLayers) {
      b.writeln('== Couches de l\'image');
      b.writeln();
      b.writeln('Méthode : $_layerModeText.');
      b.writeln();
      b.writeln('[cols="2,3,7,2,3,3",options="header"]');
      b.writeln('|===');
      b.writeln('| Couche | Digest | Instruction | CVE | Critiques | Élevées');
      for (final l in summarizeByLayer(resultsByScanner, layers)) {
        final crit = l.count('critical');
        b.writeln('| ${l.layer.index} | `${l.layer.shortDigest}` '
            '| ${_adocEsc(_short(l.layer.createdBy ?? '—', 160))} '
            '| ${l.total} '
            '| ${crit > 0 ? '*$crit*' : '0'} | ${l.count('high')}');
      }
      b.writeln('|===');
      b.writeln();
    }

    if (run.length >= 2) {
      b.writeln('== Comparaison inter-scanners');
      b.writeln();
      final rows = _crossRows();
      final layersById = _layersById;
      if (rows.isEmpty) {
        b.writeln('_Aucune CVE détectée par les scanners exécutés._');
      } else {
        b.writeln(_hasLayers
            ? '[cols="2,5,1,1,1,2",options="header"]'
            : '[cols="2,5,1,1,1",options="header"]');
        b.writeln('|===');
        b.writeln('| Sévérité | CVE / ID | Grype | OSV | Trivy'
            '${_hasLayers ? ' | Couche(s)' : ''}');
        for (final r in rows) {
          b.writeln('| ${_sevBadge(r.severity)} '
              '| ${_adocEsc(r.id)} '
              '| ${r.present['grype']! ? '✓' : '—'} '
              '| ${r.present['osv']! ? '✓' : '—'} '
              '| ${r.present['trivy']! ? '✓' : '—'}'
              '${_hasLayers ? ' | ${_layersCell(layersById, r.id)}' : ''}');
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

    if (hasExploitData) {
      final pkgById = _packageById;
      b.writeln('== Exploitabilité et exploitation active');
      b.writeln();

      final kevRows =
          _riskRows().where((r) => _exploitFor(r.id).inKev).toList();
      if (kevRows.isNotEmpty) {
        b.writeln('=== CVE activement exploitées (CISA KEV)');
        b.writeln();
        b.writeln('[cols="3,3,2,2,2",options="header"]');
        b.writeln('|===');
        b.writeln('| CVE / ID | Paquet | Ajout KEV | Échéance | Rançongiciel');
        for (final r in kevRows) {
          final e = _exploitFor(r.id);
          b.writeln('| ${_adocEsc(r.id)} '
              '| ${_adocEsc(pkgById[r.id] ?? r.package)} '
              '| ${_fmtDate(e.kevDateAdded)} '
              '| ${_fmtDate(e.kevDueDate)} '
              '| ${e.kevRansomware ? 'oui' : '—'}');
        }
        b.writeln('|===');
        b.writeln();
      }

      b.writeln('=== Priorisation par risque');
      b.writeln();
      final riskRows = _riskRows();
      if (riskRows.isEmpty) {
        b.writeln('_Aucune CVE avec signal d\'exploitation notable '
            '(CISA KEV, PoC public, ou EPSS >= '
            '${(epssWatchThreshold * 100).round()} %)._');
        b.writeln();
      } else {
        b.writeln('CVE avec un signal d\'exploitation notable, ordonnées par : '
            'KEV, puis probabilité EPSS, puis sévérité.');
        b.writeln();
        b.writeln('[cols="3,2,4,2,2,3,1",options="header"]');
        b.writeln('|===');
        b.writeln('| CVE / ID | Sévérité | Paquet | KEV | EPSS '
            '| Exploit. CVSS | PoC');
        for (final r in riskRows) {
          final e = _exploitFor(r.id);
          b.writeln('| ${_adocEsc(r.id)} '
              '| ${_sevBadge(r.severity)} '
              '| ${_adocEsc(pkgById[r.id] ?? r.package)} '
              '| ${e.inKev ? '✓' : '—'} '
              '| ${_fmtEpss(e)} '
              '| ${_adocEsc(_fmtExploitability(e))} '
              '| ${_fmtPoc(e)}');
        }
        b.writeln('|===');
        b.writeln();
        if (_riskRowsOmitted > 0) {
          b.writeln('NOTE: $_riskRowsOmitted autre(s) CVE sans signal '
              'd\'exploitation notable ne sont pas listées ici (voir la '
              'matrice ci-dessus).');
          b.writeln();
        }
      }
      b.writeln('[NOTE]');
      b.writeln('====');
      b.writeln('*KEV* : CVE au catalogue CISA Known Exploited Vulnerabilities '
          '— exploitation active confirmée. *EPSS* : probabilité d\'exploitation '
          'dans les 30 jours (score et percentile, FIRST.org). '
          '*Exploitabilité CVSS* : sous-score AV/AC/PR/UI (0–3,9) et maturité de '
          'l\'exploit quand elle est publiée. *PoC public* : dépôt(s) d\'exploit '
          'recensé(s).');
      b.writeln('====');
      b.writeln();
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

  /// Date longue en français (« 8 septembre 2026 ») pour l'en-tête du rapport.
  String _frenchDate() {
    const months = [
      'janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août',
      'septembre', 'octobre', 'novembre', 'décembre'
    ];
    final d = generatedAt;
    return '${d.day} ${months[d.month - 1]} ${d.year}';
  }

  static String _mdEsc(String s) => s.replaceAll('|', r'\|');
  static String _adocEsc(String s) => s.replaceAll('|', r'\|');

  /// Libellé français d'une sévérité (les scanners rapportent l'anglais).
  static String frSeverity(String severity) => switch (severity.toLowerCase()) {
        'critical' => 'CRITIQUE',
        'high' => 'ÉLEVÉE',
        'medium' => 'MOYENNE',
        'low' => 'FAIBLE',
        'negligible' => 'NÉGLIGEABLE',
        '' => '?',
        _ => severity.toUpperCase(),
      };

  static String _sevRole(String severity) => switch (severity.toLowerCase()) {
        'critical' => 'sev-critical',
        'high' => 'sev-high',
        'medium' => 'sev-medium',
        'low' => 'sev-low',
        _ => 'sev-other',
      };

  static String _sevBadge(String severity) =>
      '[.${_sevRole(severity)}]#${frSeverity(severity)}#';

  /// Nombre de CVE uniques dont la pire sévérité (tous scanners) vaut [level].
  int _crossSevCount(String level) => _crossRows()
      .where((r) => r.severity.toLowerCase() == level)
      .length;

  /// Verdict de la page de garde : (rôle de thème, phrase).
  (String, String) _verdict() {
    final crit = _crossSevCount('critical');
    final high = _crossSevCount('high');
    final kev = _kevCount;
    if (kev > 0) {
      return (
        'verdict-urgent',
        'Action immédiate requise. $kev CVE du catalogue CISA KEV '
            '${kev > 1 ? 'sont exploitées' : 'est exploitée'} activement dans la '
            'nature — appliquer les correctifs sans délai.'
      );
    }
    if (crit > 0) {
      return (
        'verdict-urgent',
        'Action prioritaire. $crit vulnérabilité(s) critique(s) à corriger '
            'en priorité.'
      );
    }
    if (high > 0) {
      return (
        'verdict-watch',
        'À traiter. $high vulnérabilité(s) de sévérité élevée identifiée(s).'
      );
    }
    return (
      'verdict-ok',
      'Aucune vulnérabilité critique ni élevée détectée par les scanners '
          'exécutés.'
    );
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

// IMPORTANT : copie synchronisée de `_kPdfThemeYaml` de
// `gui/lib/widgets/pdf_report.dart` — garder les deux identiques.
// `extends: default-sans` : thème sans-serif fourni par asciidoctor-pdf
// (aucun fichier de police supplémentaire à embarquer).
const String _kPdfThemeYaml = '''
extends: default-sans
page:
  size: A4
  margin: [1.7cm, 1.7cm, 2.4cm, 1.7cm]
base:
  font_size: 9.8
  font_color: 222E39
  line_height: 1.42
link:
  font_color: 1A4C8B
heading:
  font_color: 1B3A5C
  font_style: bold
  line_height: 1.15
  margin_top: 14
  margin_bottom: 5
  h1:
    font_size: 20
    font_color: 15314F
  h2:
    font_size: 14
    font_color: 1B3A5C
    margin_top: 18
    border_bottom_width: 0.75
    border_bottom_color: D3DCE3
  h3:
    font_size: 11.5
    font_color: 2C4A63
    margin_top: 12
  h4:
    font_size: 10
    font_color: 46586A
title_page:
  text_align: left
  title:
    top: 34%
    font_size: 28
    font_color: 15314F
    line_height: 1.05
  subtitle:
    font_size: 13
    font_style: normal
    font_color: 566878
  authors:
    margin_top: 24
    font_size: 10.5
    font_color: 46586A
  revision:
    margin_top: 6
    font_size: 9.5
    font_color: 6B7A88
toc:
  font_color: 30455A
  dot_leader:
    font_color: C7D0D9
table:
  border_color: D3DCE3
  border_width: 0.5
  grid_width: 0.5
  cell_padding: [4, 6, 4, 6]
  head:
    background_color: 2C4A63
    font_color: FFFFFF
    font_style: bold
  body:
    stripe_background_color: F3F6F9
  foot:
    background_color: EEF2F5
admonition:
  border_color: D3DCE3
  border_width: 0.5
  background_color: F7F9FB
  padding: [8, 10, 8, 10]
  label:
    font_color: 46586A
code:
  background_color: F3F5F7
  border_color: E4E9ED
  border_width: 0.5
  font_size: 8.5
footer:
  font_size: 8
  font_color: 7A8894
  border_width: 0.5
  border_color: D3DCE3
  height: 26
  padding: [7, 2, 0, 2]
  vertical_align: top
  recto:
    left:
      content: '{document-title}'
    right:
      content: 'Page {page-number} / {page-count}'
  verso:
    left:
      content: '{document-title}'
    right:
      content: 'Page {page-number} / {page-count}'
role:
  h1-num:
    font_size: 19
    font_color: 15314F
    font_style: bold
  h1-num-alert:
    font_size: 19
    font_color: B3261E
    font_style: bold
  verdict-urgent:
    font_color: B3261E
    font_style: bold
  verdict-watch:
    font_color: 8A5000
    font_style: bold
  verdict-ok:
    font_color: 1B5E20
    font_style: bold
  muted:
    font_color: 6B7A88
  sev-critical:
    background_color: B3261E
    font_color: FFFFFF
    font_style: bold
  sev-high:
    background_color: C4531A
    font_color: FFFFFF
    font_style: bold
  sev-medium:
    background_color: B9770E
    font_color: FFFFFF
    font_style: bold
  sev-low:
    background_color: 2E7D32
    font_color: FFFFFF
    font_style: bold
  sev-other:
    background_color: 5B6B7A
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
