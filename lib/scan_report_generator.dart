import 'dart:convert';
import 'dart:io';

import 'i18n.dart';
import 'layer_scan.dart';
import 'remediation.dart';
import 'report_input.dart';
import 'vex.dart';
import 'vuln_enrichment.dart';

/// Évolution entre un rapport de référence et le rapport courant, par couple
/// (CVE normalisée, nom de paquet).
class ReportTrend {
  final DateTime? baselineDate;

  /// Clé `CVE|paquet` → sévérité la plus haute.
  final Map<String, String> added;
  final Map<String, String> removed;
  final int unchanged;
  final int beforeTotal;
  final int afterTotal;

  const ReportTrend({
    this.baselineDate,
    required this.added,
    required this.removed,
    required this.unchanged,
    required this.beforeTotal,
    required this.afterTotal,
  });

  static final _distro = RegExp(r'^[A-Z]+-(CVE-\d{4}-\d+)$');

  static Map<String, String> _keys(
      Map<String, List<Map<String, dynamic>>?> results) {
    final out = <String, String>{};
    for (final vulns in results.values) {
      for (final v in vulns ?? const <Map<String, dynamic>>[]) {
        var id = '${v['id'] ?? ''}';
        id = _distro.firstMatch(id)?.group(1) ?? id;
        if (id.isEmpty) continue;
        final pkg = '${v['package'] ?? ''}';
        final at = pkg.lastIndexOf('@');
        final name = (at > 0 ? pkg.substring(0, at) : pkg).toLowerCase();
        final sev = '${v['severity'] ?? ''}'.toLowerCase();
        final key = '$id|$name';
        final cur = out[key];
        if (cur == null || severityRank(sev) > severityRank(cur)) {
          out[key] = sev;
        }
      }
    }
    return out;
  }

  factory ReportTrend.compute(
    Map<String, List<Map<String, dynamic>>?> before,
    Map<String, List<Map<String, dynamic>>?> after, {
    DateTime? baselineDate,
  }) {
    final b = _keys(before), a = _keys(after);
    return ReportTrend(
      baselineDate: baselineDate,
      added: {
        for (final e in a.entries)
          if (!b.containsKey(e.key)) e.key: e.value,
      },
      removed: {
        for (final e in b.entries)
          if (!a.containsKey(e.key)) e.key: e.value,
      },
      unchanged: a.keys.where(b.containsKey).length,
      beforeTotal: b.length,
      afterTotal: a.length,
    );
  }
}

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

  /// Cibles analysées (libellés) ; vide = [sbomPath] seul.
  final List<String> targets;

  /// Seuil du rapport : `all`, `critical`, `high` ou `medium`. Les CVE
  /// retenues sont celles dont la pire sévérité (tous scanners) atteint le
  /// seuil, ou qui sont au catalogue CISA KEV ; voir [fromInput].
  final String threshold;

  /// Nombre de CVE uniques avant application du seuil (`null` = pas de seuil).
  final int? uniqueBeforeThreshold;

  /// Déclarations VEX (section dédiée) et CVE qu'elles ont écartées.
  final List<VexStatement> vexStatements;
  final List<VexHit> vexSuppressed;

  /// Évolution depuis un rapport de référence (`null` = pas de comparaison).
  final ReportTrend? trend;

  ScanReportGenerator({
    required this.sbomPath,
    required this.resultsByScanner,
    DateTime? generatedAt,
    this.toolVersions = const {},
    this.exploitById = const {},
    this.layers = const [],
    this.layerScanMode,
    this.targets = const [],
    this.threshold = 'all',
    this.uniqueBeforeThreshold,
    this.vexStatements = const [],
    this.vexSuppressed = const [],
    this.trend,
  }) : generatedAt = generatedAt ?? DateTime.now();

  /// Seuils acceptés par [fromInput].
  static const thresholds = ['all', 'critical', 'high', 'medium'];

  static int _thresholdMax(String t) => switch (t) {
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        _ => 99,
      };

  /// Construit le rapport à partir d'un fichier lu par [ReportInput] : applique
  /// le VEX embarqué (sauf [applyVex] faux), calcule la tendance par rapport à
  /// [compareWith], puis le seuil de sévérité [threshold].
  factory ScanReportGenerator.fromInput(
    ReportInput input, {
    String threshold = 'all',
    ReportInput? compareWith,
    bool applyVex = true,
    String? sbomPath,
    Map<String, String?> extraTools = const {},
    DateTime? generatedAt,
  }) {
    final vex = applyVex ? input.vex : const <VexStatement>[];
    final hits = <VexHit>[];
    Map<String, List<Map<String, dynamic>>?> applyVexTo(
        Map<String, List<Map<String, dynamic>>?> r,
        {bool record = false}) {
      if (vex.isEmpty) return r;
      final doc = _VexIndex(vex);
      final seen = <String>{};
      return {
        for (final e in r.entries)
          e.key: e.value == null
              ? null
              : [
                  for (final v in e.value!)
                    if (!_suppressed(doc, v, record ? hits : null, seen)) v,
                ],
      };
    }

    final afterVex = applyVexTo(input.results, record: true);
    final trend = compareWith == null
        ? null
        : ReportTrend.compute(applyVexTo(compareWith.results), afterVex,
            baselineDate: compareWith.generatedAt);

    // Seuil de sévérité : par CVE (toutes ses lignes) — voir la doc de classe.
    var results = afterVex;
    int? before;
    if (threshold != 'all') {
      final worst = <String, String>{};
      final ids = <String>{};
      for (final vulns in afterVex.values) {
        for (final v in vulns ?? const <Map<String, dynamic>>[]) {
          final id = _normalizeId('${v['id'] ?? ''}');
          if (id.isEmpty) continue;
          ids.add(id);
          final sev = '${v['severity'] ?? ''}';
          final cur = worst[id];
          if (cur == null || _sevOrd(sev) < _sevOrd(cur)) worst[id] = sev;
        }
      }
      before = ids.length;
      final max = _thresholdMax(threshold);
      bool keep(Map<String, dynamic> v) {
        final id = _normalizeId('${v['id'] ?? ''}');
        return _sevOrd(worst[id] ?? '${v['severity'] ?? ''}') <= max ||
            (input.exploit[id]?.inKev ?? false);
      }

      results = {
        for (final e in afterVex.entries)
          e.key: e.value == null ? null : [...e.value!.where(keep)],
      };
    }

    return ScanReportGenerator(
      sbomPath: sbomPath ?? (input.targets.isEmpty ? '' : input.targets.first),
      resultsByScanner: results,
      generatedAt: generatedAt ?? input.generatedAt,
      toolVersions: {...input.toolVersions, ...extraTools},
      exploitById: input.exploit,
      layers: input.layers,
      layerScanMode: input.layerScanMode,
      targets: input.targets,
      threshold: threshold,
      uniqueBeforeThreshold: before,
      vexStatements: vex,
      vexSuppressed: [...input.vexSuppressed, ...hits],
      trend: trend,
    );
  }

  static bool _suppressed(_VexIndex vex, Map<String, dynamic> v,
      List<VexHit>? hits, Set<String> seen) {
    final id = '${v['id'] ?? ''}';
    final pkg = '${v['package'] ?? ''}';
    final (name, ver) = splitPackage(pkg);
    final st = vex.find(_normalizeId(id), name, ver);
    if (st == null || !st.suppresses) return false;
    if (hits != null && seen.add('${_normalizeId(id)}|$pkg')) {
      hits.add(VexHit(_normalizeId(id), pkg, st));
    }
    return true;
  }

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
        'each' => tr(
            'SBOM de chaque couche scanné séparément : une CVE est '
                'comptée dans chaque couche qui apporte le paquet vulnérable, '
                'y compris une version remplacée plus haut dans la pile',
            'each layer SBOM scanned separately: a CVE is counted in every '
                'layer that brings the vulnerable package, including a '
                'version replaced higher in the stack'),
        _ => tr(
            'un seul scan du SBOM global, chaque CVE rattachée à la couche '
                'qui a introduit son paquet (CVE de l\'image finale uniquement)',
            'a single scan of the global SBOM, each CVE attached to the layer '
                'that introduced its package (final-image CVEs only)'),
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
      final versTxt = vers.map((v) => '`$v`').join(', ');
      notes[id] = tr(
          'Grype ne voit aucun correctif pour la distribution '
              'installée (« won\'t fix » / « non corrigé »). $who annonce une '
              'version corrigée ($versTxt) : pour un '
              'avis de distribution, il s\'agit en général du correctif porté dans '
              'les branches *unstable* / *testing*, pas d\'une mise à jour '
              'disponible pour la release stable en place.',
          'Grype sees no fix for the installed distribution '
              '("won\'t fix" / "not fixed"). $who reports a '
              'fixed version ($versTxt): for a '
              'distribution advisory, this is usually the fix carried in '
              'the *unstable* / *testing* branches, not an update '
              'available for the stable release in place.');
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
    final all =
        <String>{for (final ids in idsByScanner.values) ...ids}.toList();

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
          present: {
            for (final s in _scannerOrder)
              s: idsByScanner[s]?.contains(id) ?? false
          },
        ),
    ];
  }

  /// CVE uniques (toutes sources confondues) dont la pire sévérité est dans
  /// [keep] — pour un affichage d'alerte en console pendant un build.
  List<ScanAlert> alerts({Set<String> keep = const {'critical', 'high'}}) {
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

  ExploitInfo _exploitFor(String id) => exploitById[id] ?? ExploitInfo.empty;

  /// L'enrichissement a-t-il produit au moins un signal exploitable ?
  bool get hasExploitData => exploitById.values.any((e) => e.hasAnySignal);

  int get _kevCount =>
      _crossRows().where((r) => _exploitFor(r.id).inKev).length;

  int get _epssWatchCount => _crossRows()
      .where((r) => (_exploitFor(r.id).epssScore ?? 0) >= epssWatchThreshold)
      .length;

  int get _pocCount =>
      _crossRows().where((r) => _exploitFor(r.id).pocKnown).length;

  /// Une CVE mérite-t-elle de figurer dans la « Priorisation par risque » ?
  /// (KEV, PoC public, ou EPSS au-dessus du seuil de veille.)
  bool _isPrioritised(String id) {
    final e = _exploitFor(id);
    return e.inKev || e.pocKnown || (e.epssScore ?? 0) >= epssWatchThreshold;
  }

  /// Lignes inter-scanners avec au moins un signal d'exploitation notable,
  /// ordonnées par risque décroissant (KEV, puis EPSS, puis sévérité).
  List<_CrossRow> _riskRows() {
    final rows = _crossRows().where((r) => _isPrioritised(r.id)).toList();
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
    if (e.pocCount > 0) {
      return tr('${e.pocCount} dépôt(s)', '${e.pocCount} repo(s)');
    }
    if (e.pocKnown) return tr('oui', 'yes');
    return '—';
  }

  // ── Markdown ─────────────────────────────────────────────────────────────

  String toMarkdown() {
    final b = StringBuffer();
    final run = _scannersRun.toList();
    b.writeln(tr('# Rapport de synthèse — vulnérabilités du SBOM',
        '# Summary report — SBOM vulnerabilities'));
    b.writeln();
    b.writeln(tr('- **SBOM analysé :** `${_mdEsc(sbomPath)}`',
        '- **Analysed SBOM:** `${_mdEsc(sbomPath)}`'));
    b.writeln(tr('- **Généré le :** ${_timestamp()}',
        '- **Generated on:** ${_timestamp()}'));
    b.writeln();

    b.writeln(tr('## Résumé global', '## Global summary'));
    b.writeln();
    b.writeln(tr('| Indicateur | Valeur |', '| Indicator | Value |'));
    b.writeln('|---|---|');
    b.writeln('| ${tr('Scanners exécutés', 'Scanners run')} | ${run.length} / 3'
        '${run.isEmpty ? "" : " (${run.map((s) => _scannerLabels[s]).join(', ')})"} |');
    b.writeln(
        '| ${tr('CVE uniques (tous scanners)', 'Unique CVEs (all scanners)')} | $_uniqueCveCount |');
    b.writeln(
        '| ${tr('Résultats bruts cumulés', 'Cumulated raw results')} | $_totalFindings |');
    if (hasExploitData) {
      b.writeln(
          '| ${tr('CVE activement exploitées (CISA KEV)', 'Actively exploited CVEs (CISA KEV)')} | $_kevCount |');
      b.writeln('| ${tr('CVE avec EPSS ≥', 'CVEs with EPSS ≥')} '
          '${(epssWatchThreshold * 100).round()} % | $_epssWatchCount |');
      b.writeln(
          '| ${tr('CVE avec PoC / exploit public', 'CVEs with a public PoC / exploit')} | $_pocCount |');
    }
    b.writeln();

    if (toolVersions.isNotEmpty) {
      b.writeln(tr('## Outils', '## Tools'));
      b.writeln();
      b.writeln(tr('| Outil | Version |', '| Tool | Version |'));
      b.writeln('|---|---|');
      toolVersions.forEach((k, v) => b.writeln(
          '| ${_mdEsc(k)} | ${_mdEsc(v ?? tr("inconnue", "unknown"))} |'));
      b.writeln();
    }

    b.writeln(tr('## Répartition par scanner', '## Breakdown by scanner'));
    b.writeln();
    for (final s in _scannerOrder) {
      b.writeln('### ${_scannerLabels[s]}');
      b.writeln();
      final vulns = resultsByScanner[s];
      if (vulns == null) {
        b.writeln(tr('_Non exécuté._', '_Not run._'));
      } else if (vulns.isEmpty) {
        b.writeln(
            tr('Aucune vulnérabilité détectée.', 'No vulnerability detected.'));
      } else {
        final counts = _severityCounts(vulns);
        b.writeln(tr('| Sévérité | Nombre |', '| Severity | Count |'));
        b.writeln('|---|---|');
        for (final sev in const [
          'critical',
          'high',
          'medium',
          'low',
          'autre'
        ]) {
          if ((counts[sev] ?? 0) > 0) {
            b.writeln(
                '| ${sev == 'autre' ? tr('Autre', 'Other') : sev.toUpperCase()} | ${counts[sev]} |');
          }
        }
        b.writeln('| **Total** | **${vulns.length}** |');
      }
      b.writeln();
    }

    if (_hasLayers) {
      b.writeln(tr('## Couches de l\'image', '## Image layers'));
      b.writeln();
      b.writeln('${tr('Méthode', 'Method')}: $_layerModeText.');
      b.writeln();
      b.writeln(tr(
          '| Couche | Digest | Instruction | CVE | Critiques | Élevées |',
          '| Layer | Digest | Instruction | CVE | Critical | High |'));
      b.writeln('|---|---|---|--:|--:|--:|');
      for (final l in summarizeByLayer(resultsByScanner, layers)) {
        b.writeln('| ${l.layer.index} | `${l.layer.shortDigest}` '
            '| ${_mdEsc(_short(l.layer.createdBy ?? '—', 90))} '
            '| ${l.total} | ${l.count('critical')} | ${l.count('high')} |');
      }
      b.writeln();
    }

    if (run.length >= 2) {
      b.writeln(
          tr('## Comparaison inter-scanners', '## Cross-scanner comparison'));
      b.writeln();
      final rows = _crossRows();
      final layersById = _layersById;
      if (rows.isEmpty) {
        b.writeln(tr('_Aucune CVE détectée par les scanners exécutés._',
            '_No CVE detected by the scanners that ran._'));
      } else {
        b.writeln(
            '| ${tr('Sévérité', 'Severity')} | CVE / ID | Grype | OSV-Scanner | Trivy |'
            '${_hasLayers ? ' ${tr('Couche(s)', 'Layer(s)')} |' : ''}');
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
      b.writeln(tr(
          '> Des comptages très différents entre scanners sur les paquets '
              'système (Debian/Alpine/RPM) ne signalent pas forcément une erreur : '
              'OSV-Scanner en mode « scan de SBOM » peut ne trouver aucune CVE sur '
              'ces paquets, et Grype/Trivy n\'ont pas la même exhaustivité sur les '
              'avis distro. Voir la documentation, section « Pourquoi Grype, '
              'OSV-Scanner et Trivy ne trouvent pas les mêmes CVE ».',
          '> Very different counts between scanners on system packages '
              '(Debian/Alpine/RPM) do not necessarily indicate an error: '
              'OSV-Scanner in "SBOM scan" mode may find no CVE on these '
              'packages, and Grype/Trivy are not equally exhaustive on '
              'distro advisories. See the documentation, section "Why Grype, '
              'OSV-Scanner and Trivy do not find the same CVEs".'));
      b.writeln();

      final notes = cveNotes();
      if (notes.isNotEmpty) {
        final pkgById = _packageById;
        b.writeln(tr('### Notes par CVE', '### Notes per CVE'));
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
      b.writeln(tr('## Exploitabilité et exploitation active',
          '## Exploitability and active exploitation'));
      b.writeln();

      final kevRows =
          _riskRows().where((r) => _exploitFor(r.id).inKev).toList();
      if (kevRows.isNotEmpty) {
        b.writeln(tr('### CVE activement exploitées (CISA KEV)',
            '### Actively exploited CVEs (CISA KEV)'));
        b.writeln();
        b.writeln(tr(
            '| CVE / ID | Paquet | Ajout KEV | Échéance | Rançongiciel |',
            '| CVE / ID | Package | KEV added | Due date | Ransomware |'));
        b.writeln('|---|---|---|---|:-:|');
        for (final r in kevRows) {
          final e = _exploitFor(r.id);
          b.writeln('| ${_mdEsc(r.id)} '
              '| ${_mdEsc(pkgById[r.id] ?? r.package)} '
              '| ${_fmtDate(e.kevDateAdded)} '
              '| ${_fmtDate(e.kevDueDate)} '
              '| ${e.kevRansomware ? '⚠️ ${tr('oui', 'yes')}' : '—'} |');
        }
        b.writeln();
      }

      b.writeln(tr('### Priorisation par risque', '### Risk prioritisation'));
      b.writeln();
      final riskRows = _riskRows();
      if (riskRows.isEmpty) {
        b.writeln(tr(
            '_Aucune CVE avec signal d\'exploitation notable '
                '(CISA KEV, PoC public, ou EPSS ≥ '
                '${(epssWatchThreshold * 100).round()} %)._',
            '_No CVE with a notable exploitation signal '
                '(CISA KEV, public PoC, or EPSS ≥ '
                '${(epssWatchThreshold * 100).round()} %)._'));
        b.writeln();
      } else {
        b.writeln(tr(
            'CVE avec un signal d\'exploitation notable, ordonnées par : '
                'KEV, puis probabilité EPSS, puis sévérité.',
            'CVEs with a notable exploitation signal, ordered by: '
                'KEV, then EPSS probability, then severity.'));
        b.writeln();
        b.writeln(tr(
            '| CVE / ID | Sévérité | Paquet | KEV | EPSS | Exploitabilité CVSS | PoC public |',
            '| CVE / ID | Severity | Package | KEV | EPSS | CVSS exploitability | Public PoC |'));
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
          b.writeln(tr(
              '> $_riskRowsOmitted autre(s) CVE sans signal d\'exploitation '
                  'notable ne sont pas listées ici (voir la matrice ci-dessus).',
              '> $_riskRowsOmitted other CVE(s) with no notable exploitation '
                  'signal are not listed here (see the matrix above).'));
          b.writeln();
        }
      }
      b.writeln(tr(
          '> **KEV** : CVE au catalogue CISA Known Exploited '
              'Vulnerabilities — exploitation active confirmée. **EPSS** : '
              'probabilité d\'exploitation dans les 30 jours (score et percentile, '
              'FIRST.org). **Exploitabilité CVSS** : sous-score AV/AC/PR/UI (0–3,9) '
              'et maturité de l\'exploit quand elle est publiée. **PoC public** : '
              'dépôt(s) d\'exploit recensé(s).',
          '> **KEV**: CVE in the CISA Known Exploited '
              'Vulnerabilities catalog — confirmed active exploitation. **EPSS**: '
              'probability of exploitation within 30 days (score and percentile, '
              'FIRST.org). **CVSS exploitability**: AV/AC/PR/UI sub-score (0–3.9) '
              'and exploit maturity when published. **Public PoC**: '
              'recorded exploit repository(ies).'));
      b.writeln();
    }

    _mdExtras(b);
    b.writeln('---');
    b.writeln();
    b.writeln(
        tr('_Généré par sbom-generator._', '_Generated by sbom-generator._'));
    return b.toString();
  }

  /// Remédiation, tendance, VEX et détail des CVE au format Markdown.
  void _mdExtras(StringBuffer b) {
    final items = _remediation.where((i) => i.targetVersion != null).toList();
    if (items.isNotEmpty) {
      b.writeln(tr('## Remédiation', '## Remediation'));
      b.writeln();
      b.writeln(tr(
          '| Paquet | Mise à jour | CVE corrigées | dont KEV | Restantes | Gain |',
          '| Package | Update | CVEs fixed | of which KEV | Remaining | Gain |'));
      b.writeln('|---|---|---|---|---|---|');
      for (final i in items.take(_remediationRows)) {
        b.writeln(
            '| `${_mdEsc(i.packageName)}` | ${_mdEsc(i.installedVersion)} → '
            '**${_mdEsc(i.targetVersion!)}** | ${i.fixed.length} | ${i.kevFixed} '
            '| ${i.unfixed.length} | ${_gain(i.gain)} |');
      }
      b.writeln();
    }
    final t = trend;
    if (t != null) {
      b.writeln(tr('## Tendance', '## Trend'));
      b.writeln();
      b.writeln(tr(
          '- **Nouvelles :** ${t.added.length}\n- **Disparues :** ${t.removed.length}\n- **Inchangées :** ${t.unchanged}\n- **Total :** ${t.beforeTotal} → ${t.afterTotal}',
          '- **New:** ${t.added.length}\n- **Gone:** ${t.removed.length}\n- **Unchanged:** ${t.unchanged}\n- **Total:** ${t.beforeTotal} → ${t.afterTotal}'));
      b.writeln();
      for (final e in t.added.entries.take(50)) {
        b.writeln(
            '- ${tr('nouvelle', 'new')} : ${_fmtTrendKey(e.key)} (${frSeverity(e.value)})');
      }
      if (t.added.isNotEmpty) b.writeln();
    }
    if (vexStatements.isNotEmpty) {
      b.writeln('## VEX');
      b.writeln();
      b.writeln(tr('| CVE | Produits | État | Justification |',
          '| CVE | Products | Status | Justification |'));
      b.writeln('|---|---|---|---|');
      for (final s in vexStatements) {
        b.writeln('| ${_mdEsc(s.vulnId)} | '
            '${s.products.isEmpty ? tr('tous', 'all') : _mdEsc(s.products.join(', '))} | '
            '${_vexStatusLabel(s.status)} | '
            '${_mdEsc([
          if (s.justification != null) s.justification!,
          if (s.impactStatement != null) s.impactStatement!
        ].join(' — '))} |');
      }
      b.writeln();
      b.writeln(tr('${vexSuppressed.length} CVE écartée(s) du rapport.',
          '${vexSuppressed.length} CVE(s) dropped from the report.'));
      b.writeln();
    }
    final rows = _crossRows();
    if (rows.isNotEmpty) {
      b.writeln(tr('## Détail des CVE', '## CVE details'));
      b.writeln();
      for (final r in rows) {
        final fs = _findingsOf(r.id);
        b.writeln('### ${r.id}');
        b.writeln();
        final withPkg = fs.where((f) => '${f['package'] ?? ''}'.isNotEmpty);
        if (withPkg.isNotEmpty) {
          final (name, ver) = splitPackage('${withPkg.first['package']}');
          final fixed = [
            for (final x
                in (withPkg.first['fixedVersions'] as List? ?? const []))
              '$x'
          ];
          b.writeln('- **${tr('Paquet', 'Package')} :** `$name $ver'
              '${fixed.isEmpty ? '' : ' → ${fixed.join(', ')}'}`');
        }
        b.writeln('- **${tr('Signalé par', 'Reported by')} :** ${[
          for (final f in fs)
            '${f['scanner']} (${frSeverity('${f['severity'] ?? ''}')})'
        ].join(', ')}');
        final e = _exploitFor(r.id);
        if (e.inKev) b.writeln('- **CISA KEV :** ${tr('oui', 'yes')}');
        if (e.epssScore != null) b.writeln('- **EPSS :** ${_fmtEpss(e)}');
        b.writeln();
      }
    }
  }

  // ── AsciiDoc ─────────────────────────────────────────────────────────────

  String toAsciiDoc() {
    final b = StringBuffer();
    final run = _scannersRun.toList();
    final sbomName = sbomPath.split(RegExp(r'[/\\]')).last;
    b.writeln(tr('= Rapport de vulnérabilités: Synthèse inter-scanners',
        '= Vulnerability report: Cross-scanner summary'));
    b.writeln('sbom-generator');
    b.writeln(':doctype: article');
    b.writeln(':title-page:');
    b.writeln(':toc:');
    b.writeln(tr(':toc-title: Sommaire', ':toc-title: Contents'));
    b.writeln(':toclevels: 2');
    b.writeln(':revdate: ${_frenchDate()}');
    b.writeln(':icons: font');
    b.writeln();

    b.writeln(tr('== Résumé exécutif', '== Executive summary'));
    b.writeln();
    if (targets.length > 1) {
      b.writeln('${tr('*Cibles analysées*', '*Analysed targets*')} : '
          '${targets.map((x) => '`${_adocEsc(x)}`').join(', ')} +');
    } else {
      var shown = targets.length == 1 ? targets.single : sbomName;
      if (!shown.contains(' ')) shown = shown.split(RegExp(r'[/\\]')).last;
      b.writeln('${tr('*Cible analysée*', '*Analysed target*')} : '
          '`${_adocEsc(shown)}` +');
    }
    b.writeln(
        '${tr('*Scanners exécutés*', '*Scanners run*')} : ${run.length} / 3'
        '${run.isEmpty ? '' : ' (${run.map((s) => _scannerLabels[s]).join(', ')})'}'
        ' — *$_uniqueCveCount* ${tr('CVE uniques', 'unique CVEs')}');
    b.writeln();
    if (threshold != 'all') {
      b.writeln(tr(
          'NOTE: rapport limité aux CVE de sévérité *$_thresholdLabel* '
              '(ou présentes au catalogue CISA KEV) : $_uniqueCveCount '
              '${uniqueBeforeThreshold == null ? '' : 'sur $uniqueBeforeThreshold '}'
              'CVE uniques.',
          'NOTE: report limited to CVEs of *$_thresholdLabel* severity '
              '(or listed in the CISA KEV catalog): $_uniqueCveCount '
              '${uniqueBeforeThreshold == null ? '' : 'of $uniqueBeforeThreshold '}'
              'unique CVEs.'));
      b.writeln();
    }
    if (vexSuppressed.isNotEmpty) {
      b.writeln(tr(
          'NOTE: ${vexSuppressed.length} CVE écartée(s) par une déclaration '
              'VEX (voir la section « VEX »).',
          'NOTE: ${vexSuppressed.length} CVE(s) dropped by a VEX statement '
              '(see the "VEX" section).'));
      b.writeln();
    }
    final crit = _crossSevCount('critical');
    final high = _crossSevCount('high');
    b.writeln('[cols="^1,^1,^1,^1",frame=none,grid=cols]');
    b.writeln('|===');
    b.writeln(tr('h| Critiques h| Élevées h| CISA KEV h| EPSS >= ',
            'h| Critical h| High h| CISA KEV h| EPSS >= ') +
        ''
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
      b.writeln(tr('== Outils', '== Tools'));
      b.writeln();
      b.writeln('[cols="<3,<1",options="header"]');
      b.writeln('|===');
      b.writeln(tr('| Outil | Version', '| Tool | Version'));
      toolVersions.forEach((k, v) => b.writeln(
          '| ${_adocEsc(k)} | ${_adocEsc(v ?? tr("inconnue", "unknown"))}'));
      b.writeln('|===');
      b.writeln();
    }

    b.writeln(tr('== Répartition par scanner', '== Breakdown by scanner'));
    b.writeln();
    for (final s in _scannerOrder) {
      b.writeln('=== ${_scannerLabels[s]}');
      b.writeln();
      final vulns = resultsByScanner[s];
      if (vulns == null) {
        b.writeln(tr('_Non exécuté._', '_Not run._'));
      } else if (vulns.isEmpty) {
        b.writeln(
            tr('Aucune vulnérabilité détectée.', 'No vulnerability detected.'));
      } else {
        final counts = _severityCounts(vulns);
        final svg = buildSeverityBarSvg(counts);
        if (svg != null) {
          b.writeln(svgImageMacro(svg));
          b.writeln();
        }
        b.writeln('[cols="<2,<1",options="header"]');
        b.writeln('|===');
        b.writeln(tr('| Sévérité | Nombre', '| Severity | Count'));
        for (final sev in const [
          'critical',
          'high',
          'medium',
          'low',
          'autre'
        ]) {
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
      b.writeln(tr('== Couches de l\'image', '== Image layers'));
      b.writeln();
      b.writeln('${tr('Méthode', 'Method')}: $_layerModeText.');
      b.writeln();
      b.writeln('[cols="2,3,7,2,3,3",options="header"]');
      b.writeln('|===');
      b.writeln(tr(
          '| Couche | Digest | Instruction | CVE | Critiques | Élevées',
          '| Layer | Digest | Instruction | CVE | Critical | High'));
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

    if (run.isNotEmpty) {
      b.writeln(
          tr('== Comparaison inter-scanners', '== Cross-scanner comparison'));
      b.writeln();
      final rows = _crossRows();
      final layersById = _layersById;
      if (rows.isEmpty) {
        b.writeln(tr('_Aucune CVE détectée par les scanners exécutés._',
            '_No CVE detected by the scanners that ran._'));
      } else {
        b.writeln(_hasLayers
            ? '[cols="2,5,1,1,1,2",options="header"]'
            : '[cols="2,5,1,1,1",options="header"]');
        b.writeln('|===');
        b.writeln(tr('| Sévérité | CVE / ID | Grype | OSV | Trivy',
                '| Severity | CVE / ID | Grype | OSV | Trivy') +
            '${_hasLayers ? ' | ${tr('Couche(s)', 'Layer(s)')}' : ''}');
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
      if (run.length >= 2) {
        b.writeln('[NOTE]');
        b.writeln('====');
        b.writeln(tr(
            'Des comptages très différents entre scanners sur les paquets '
                'système (Debian/Alpine/RPM) ne signalent pas forcément une erreur. '
                'OSV-Scanner en mode « scan de SBOM » peut ne trouver aucune CVE sur '
                'ces paquets (son API n\'indexe les avis distro que sous une forme de '
                'purl absente du SBOM standard). Grype et Trivy n\'ont par ailleurs '
                'pas la même exhaustivité sur ces mêmes paquets : Grype reprend '
                'l\'intégralité du Debian Security Tracker (avis « won\'t fix » '
                'inclus) là où Trivy ne remonte qu\'un sous-ensemble. Voir la '
                'documentation utilisateur, section « Pourquoi Grype, OSV-Scanner et '
                'Trivy ne trouvent pas les mêmes CVE ».',
            'Very different counts between scanners on system packages '
                '(Debian/Alpine/RPM) do not necessarily indicate an error. '
                'OSV-Scanner in "SBOM scan" mode may find no CVE on these '
                'packages (its API only indexes distro advisories under a purl '
                'form absent from the standard SBOM). Grype and Trivy are also '
                'not equally exhaustive on these same packages: Grype takes '
                'the whole Debian Security Tracker ("won\'t fix" advisories '
                'included) where Trivy only reports a subset. See the '
                'user documentation, section "Why Grype, OSV-Scanner and '
                'Trivy do not find the same CVEs".'));
        b.writeln('====');
        b.writeln();
      }

      final notes = cveNotes();
      if (notes.isNotEmpty) {
        final pkgById = _packageById;
        b.writeln(tr('=== Notes par CVE', '=== Notes per CVE'));
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
      b.writeln(tr('== Exploitabilité et exploitation active',
          '== Exploitability and active exploitation'));
      b.writeln();

      final kevRows =
          _riskRows().where((r) => _exploitFor(r.id).inKev).toList();
      if (kevRows.isNotEmpty) {
        b.writeln(tr('=== CVE activement exploitées (CISA KEV)',
            '=== Actively exploited CVEs (CISA KEV)'));
        b.writeln();
        b.writeln('[cols="3,3,2,2,2",options="header"]');
        b.writeln('|===');
        b.writeln(tr(
            '| CVE / ID | Paquet | Ajout KEV | Échéance | Rançongiciel',
            '| CVE / ID | Package | KEV added | Due date | Ransomware'));
        for (final r in kevRows) {
          final e = _exploitFor(r.id);
          b.writeln('| ${_adocEsc(r.id)} '
              '| ${_adocEsc(pkgById[r.id] ?? r.package)} '
              '| ${_fmtDate(e.kevDateAdded)} '
              '| ${_fmtDate(e.kevDueDate)} '
              '| ${e.kevRansomware ? tr('oui', 'yes') : '—'}');
        }
        b.writeln('|===');
        b.writeln();
      }

      b.writeln(tr('=== Priorisation par risque', '=== Risk prioritisation'));
      b.writeln();
      final riskRows = _riskRows();
      if (riskRows.isEmpty) {
        b.writeln(tr(
            '_Aucune CVE avec signal d\'exploitation notable '
                '(CISA KEV, PoC public, ou EPSS >= '
                '${(epssWatchThreshold * 100).round()} %)._',
            '_No CVE with a notable exploitation signal '
                '(CISA KEV, public PoC, or EPSS >= '
                '${(epssWatchThreshold * 100).round()} %)._'));
        b.writeln();
      } else {
        b.writeln(tr(
            'CVE avec un signal d\'exploitation notable, ordonnées par : '
                'KEV, puis probabilité EPSS, puis sévérité.',
            'CVEs with a notable exploitation signal, ordered by: '
                'KEV, then EPSS probability, then severity.'));
        b.writeln();
        b.writeln('[cols="3,2,4,2,2,3,1",options="header"]');
        b.writeln('|===');
        b.writeln(tr('| CVE / ID | Sévérité | Paquet | KEV | EPSS ',
                '| CVE / ID | Severity | Package | KEV | EPSS ') +
            tr('| Exploit. CVSS | PoC', '| CVSS exploit. | PoC'));
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
          b.writeln(tr(
              'NOTE: $_riskRowsOmitted autre(s) CVE sans signal '
                  'd\'exploitation notable ne sont pas listées ici (voir la '
                  'matrice ci-dessus).',
              'NOTE: $_riskRowsOmitted other CVE(s) with no notable '
                  'exploitation signal are not listed here (see the '
                  'matrix above).'));
          b.writeln();
        }
      }
      b.writeln('[NOTE]');
      b.writeln('====');
      b.writeln(tr(
          '*KEV* : CVE au catalogue CISA Known Exploited Vulnerabilities '
              '— exploitation active confirmée. *EPSS* : probabilité d\'exploitation '
              'dans les 30 jours (score et percentile, FIRST.org). '
              '*Exploitabilité CVSS* : sous-score AV/AC/PR/UI (0–3,9) et maturité de '
              'l\'exploit quand elle est publiée. *PoC public* : dépôt(s) d\'exploit '
              'recensé(s).',
          '*KEV*: CVE in the CISA Known Exploited Vulnerabilities catalog '
              '— confirmed active exploitation. *EPSS*: probability of exploitation '
              'within 30 days (score and percentile, FIRST.org). '
              '*CVSS exploitability*: AV/AC/PR/UI sub-score (0–3.9) and exploit '
              'maturity when published. *Public PoC*: recorded exploit '
              'repository(ies).'));
      b.writeln('====');
      b.writeln();
    }

    _adocRemediation(b);
    _adocTrend(b);
    _adocVex(b);
    _adocDetail(b);

    b.writeln(
        tr('_Généré par sbom-generator._', '_Generated by sbom-generator._'));
    return b.toString();
  }

  // ── Sections communes AsciiDoc / Markdown ────────────────────────────────

  String get _thresholdLabel => switch (threshold) {
        'critical' => 'Critical',
        'high' => '≥ High',
        'medium' => '≥ Medium',
        _ => 'All',
      };

  static String _gain(double g) => g.toStringAsFixed(g >= 100 ? 0 : 1);

  /// Plan de remédiation : par paquet, mise à jour la plus économique.
  List<RemediationItem> get _remediation {
    final inputs = <RemediationInput>[];
    for (final s in _scannersRun) {
      for (final v in resultsByScanner[s]!) {
        final (name, ver) = splitPackage('${v['package'] ?? ''}');
        final fixed = [
          for (final f in (v['fixedVersions'] as List? ?? const [])) '$f'
        ];
        inputs.add((
          scanner: _scannerLabels[s]!,
          id: '${v['id'] ?? ''}',
          severity: '${v['severity'] ?? ''}',
          packageName: name,
          installedVersion: ver,
          fixedVersion:
              fixed.isEmpty ? '${v['fixState'] ?? ''}' : fixed.join(', '),
        ));
      }
    }
    return buildRemediation(inputs, exploitById: exploitById);
  }

  static const _remediationRows = 30;

  void _adocRemediation(StringBuffer b) {
    final items = _remediation.where((i) => i.targetVersion != null).toList();
    if (items.isEmpty) return;
    b.writeln(tr('== Remédiation', '== Remediation'));
    b.writeln();
    b.writeln(tr(
        'Par paquet, la mise à jour minimale qui corrige toutes les CVE '
            'corrigeables, classée par *gain de risque* (sévérité, exploitation '
            'active KEV, probabilité EPSS).',
        'Per package, the minimal update that fixes every fixable CVE, ranked '
            'by *risk reduction* (severity, active exploitation KEV, EPSS '
            'probability).'));
    b.writeln();
    b.writeln('[cols="4,3,1,1,1,1",options="header"]');
    b.writeln('|===');
    b.writeln(tr(
        '| Paquet | Mise à jour | CVE corrigées | dont KEV | Restantes | Gain',
        '| Package | Update | CVEs fixed | of which KEV | Remaining | Gain'));
    for (final i in items.take(_remediationRows)) {
      b.writeln('| `${_adocEsc(i.packageName)}` '
          '| ${_adocEsc(i.installedVersion)} → *${_adocEsc(i.targetVersion!)}* '
          '| ${i.fixed.length} | ${i.kevFixed > 0 ? '*${i.kevFixed}*' : '0'} '
          '| ${i.unfixed.length} | ${_gain(i.gain)}');
    }
    b.writeln('|===');
    b.writeln();
    if (items.length > _remediationRows) {
      b.writeln(tr(
          'NOTE: ${items.length - _remediationRows} autre(s) paquet(s) à mettre à jour ne sont pas listés (gain plus faible).',
          'NOTE: ${items.length - _remediationRows} other package(s) to update are not listed (lower gain).'));
      b.writeln();
    }
    final noFix = _remediation.where((i) => i.targetVersion == null).length;
    if (noFix > 0) {
      b.writeln(tr('NOTE: $noFix paquet(s) n\'ont aucun correctif connu.',
          'NOTE: $noFix package(s) have no known fix.'));
      b.writeln();
    }
    b.writeln(tr(
        '_La version cible est une heuristique (comparaison numérique des versions) : à vérifier avec le gestionnaire de paquets._',
        '_The target version is a heuristic (numeric version comparison): check it with the package manager._'));
    b.writeln();
  }

  static String _fmtTrendKey(String key) {
    final i = key.indexOf('|');
    return i < 0 ? key : '${key.substring(0, i)} (`${key.substring(i + 1)}`)';
  }

  void _adocTrend(StringBuffer b) {
    final t = trend;
    if (t == null) return;
    b.writeln(tr('== Tendance', '== Trend'));
    b.writeln();
    final since = t.baselineDate == null ? '' : _fmtDate(t.baselineDate);
    b.writeln(tr(
        'Évolution depuis le rapport de référence${since.isEmpty ? '' : ' du $since'}.',
        'Change since the reference report${since.isEmpty ? '' : ' of $since'}.'));
    b.writeln();
    b.writeln('[cols="^1,^1,^1,^1",frame=none,grid=cols]');
    b.writeln('|===');
    b.writeln(tr('h| Nouvelles h| Disparues h| Inchangées h| Total',
        'h| New h| Gone h| Unchanged h| Total'));
    b.writeln(
        '| [.${t.added.isEmpty ? 'h1-num' : 'h1-num-alert'}]*${t.added.length}* '
        '| [.h1-num]*${t.removed.length}* | [.h1-num]*${t.unchanged}* '
        '| [.h1-num]*${t.beforeTotal} → ${t.afterTotal}*');
    b.writeln('|===');
    b.writeln();
    void list(String title, Map<String, String> m) {
      if (m.isEmpty) return;
      final rows = m.entries.toList()
        ..sort((a, c) {
          final o = _sevOrd(a.value).compareTo(_sevOrd(c.value));
          return o != 0 ? o : a.key.compareTo(c.key);
        });
      b.writeln('=== $title');
      b.writeln();
      b.writeln('[cols="2,6",options="header"]');
      b.writeln('|===');
      b.writeln(tr('| Sévérité | CVE (paquet)', '| Severity | CVE (package)'));
      for (final e in rows.take(50)) {
        b.writeln('| ${_sevBadge(e.value)} | ${_adocEsc(_fmtTrendKey(e.key))}');
      }
      b.writeln('|===');
      if (rows.length > 50) {
        b.writeln();
        b.writeln(tr('NOTE: ${rows.length - 50} autre(s) non listée(s).',
            'NOTE: ${rows.length - 50} more not listed.'));
      }
      b.writeln();
    }

    list(tr('Nouvelles CVE', 'New CVEs'), t.added);
    list(
        tr('CVE disparues (corrigées ou plus détectées)',
            'Gone CVEs (fixed or no longer detected)'),
        t.removed);
  }

  String _vexStatusLabel(String s) => switch (s) {
        'not_affected' => tr('non affectée', 'not affected'),
        'affected' => tr('affectée', 'affected'),
        'fixed' => tr('corrigée', 'fixed'),
        _ => tr('à l\'étude', 'under investigation'),
      };

  void _adocVex(StringBuffer b) {
    if (vexStatements.isEmpty) return;
    b.writeln('== VEX');
    b.writeln();
    b.writeln(tr(
        '${vexStatements.length} déclaration(s) VEX appliquée(s) : '
            '${vexSuppressed.length} CVE écartée(s) du rapport.',
        '${vexStatements.length} VEX statement(s) applied: '
            '${vexSuppressed.length} CVE(s) dropped from the report.'));
    b.writeln();
    b.writeln('[cols="3,4,2,5",options="header"]');
    b.writeln('|===');
    b.writeln(tr('| CVE | Produits | État | Justification / explication',
        '| CVE | Products | Status | Justification / explanation'));
    for (final s in vexStatements) {
      final why = [
        if (s.justification != null) s.justification!,
        if (s.impactStatement != null) s.impactStatement!,
      ].join(' — ');
      b.writeln('| ${_adocEsc(s.vulnId)} '
          '| ${s.products.isEmpty ? tr('tous', 'all') : _adocEsc(s.products.join(', '))} '
          '| ${_vexStatusLabel(s.status)} | ${_adocEsc(why.isEmpty ? '—' : why)}');
    }
    b.writeln('|===');
    b.writeln();
    if (vexSuppressed.isNotEmpty) {
      b.writeln('=== ${tr('CVE écartées', 'Dropped CVEs')}');
      b.writeln();
      for (final h in vexSuppressed) {
        b.writeln('* *${_adocEsc(h.id)}* (`${_adocEsc(h.package)}`) — '
            '${_vexStatusLabel(h.statement.status)}');
      }
      b.writeln();
    }
  }

  /// Versions, dates et signaux d'une CVE, agrégés sur tous les scanners.
  List<Map<String, dynamic>> _findingsOf(String id) => [
        for (final s in _scannersRun)
          for (final v in resultsByScanner[s]!)
            if (_normalizeId('${v['id'] ?? ''}') == id)
              {...v, 'scanner': _scannerLabels[s]!},
      ];

  static String _day(Object? iso) {
    final d = DateTime.tryParse('$iso');
    return d == null ? '—' : _fmtDate(d);
  }

  void _adocDetail(StringBuffer b) {
    final rows = _crossRows();
    if (rows.isEmpty) return;
    b.writeln(tr('== Détail des CVE', '== CVE details'));
    b.writeln();
    b.writeln(threshold == 'all'
        ? tr('Fiche de chacune des ${rows.length} CVE du rapport.',
            'Detail of each of the ${rows.length} CVEs in the report.')
        : tr(
            'Fiche des ${rows.length} CVE retenues (sévérité $_thresholdLabel ou CISA KEV).',
            'Detail of the ${rows.length} retained CVEs ($_thresholdLabel severity or CISA KEV).'));
    b.writeln();
    for (final r in rows) {
      final fs = _findingsOf(r.id);
      b.writeln('=== ${_adocEsc(r.id)}');
      b.writeln();
      b.writeln('[cols="<1h,<3a"]');
      b.writeln('|===');
      final withPkg = fs.where((f) => '${f['package'] ?? ''}'.isNotEmpty);
      if (withPkg.isNotEmpty) {
        final f = withPkg.first;
        final (name, ver) = splitPackage('${f['package']}');
        final fixed = [
          for (final x in (f['fixedVersions'] as List? ?? const [])) '$x'
        ];
        b.writeln('| ${tr('Paquet', 'Package')} | `${_adocEsc('$name $ver'
            '${fixed.isEmpty ? '' : ' → ${fixed.join(', ')}'}')}`');
      }
      b.writeln('| ${tr('Signalé par', 'Reported by')} | ${_adocEsc([
        for (final f in fs)
          '${f['scanner']} (${frSeverity('${f['severity'] ?? ''}')})'
      ].join(', '))}');
      final dates = [
        for (final f in fs)
          if (f['published'] != null || f['modified'] != null)
            tr('${f['scanner']} : publiée ${_day(f['published'])}, modifiée ${_day(f['modified'])}',
                '${f['scanner']}: published ${_day(f['published'])}, modified ${_day(f['modified'])}'),
      ];
      if (dates.isNotEmpty) {
        b.writeln(
            '| ${tr('Dates', 'Dates')} | ${_adocEsc(dates.join(' +\n'))}');
      }
      var desc = '';
      for (final f in fs) {
        final x = '${f['extra'] ?? ''}';
        if (x.contains(' ') && x.length > 12 && x.length > desc.length)
          desc = x;
      }
      if (desc.isNotEmpty) {
        b.writeln('| Description | ${_adocEsc(desc)}');
      }
      final e = _exploitFor(r.id);
      if (e.inKev) {
        b.writeln('| CISA KEV | ${tr('Oui — ajoutée le ${_fmtDate(e.kevDateAdded)}'
            '${e.kevDueDate == null ? '' : ', échéance ${_fmtDate(e.kevDueDate)}'}'
            '${e.kevRansomware ? ', utilisée par des rançongiciels' : ''}', 'Yes — added on ${_fmtDate(e.kevDateAdded)}'
            '${e.kevDueDate == null ? '' : ', due ${_fmtDate(e.kevDueDate)}'}'
            '${e.kevRansomware ? ', used by ransomware' : ''}')}');
      }
      if (e.epssScore != null) b.writeln('| EPSS | ${_fmtEpss(e)}');
      if (e.cvssExploitabilityScore != null ||
          e.exploitMaturity != null ||
          e.cvssBaseScore != null) {
        b.writeln('| CVSS | ${_adocEsc([
          if (e.cvssBaseScore != null)
            'base ${e.cvssBaseScore!.toStringAsFixed(1)}',
          if (e.cvssExploitabilityScore != null || e.exploitMaturity != null)
            _fmtExploitability(e),
        ].join(' · '))}${e.cvssVector == null ? '' : ' +\n`${_adocEsc(e.cvssVector!)}`'}');
      }
      if (e.pocKnown) {
        b.writeln('| ${tr('PoC public', 'Public PoC')} | ${_fmtPoc(e)}'
            '${e.pocUrls.isEmpty ? '' : ' +\n${e.pocUrls.map(_adocEsc).join(' +\n')}'}');
      }
      final enc = Uri.encodeComponent(r.id);
      final links = [
        if (r.id.toUpperCase().startsWith('CVE-')) ...[
          'https://nvd.nist.gov/vuln/detail/$enc',
          'https://www.cve.org/CVERecord?id=$enc',
        ],
        if (r.id.toUpperCase().startsWith('GHSA-'))
          'https://github.com/advisories/$enc',
        'https://osv.dev/vulnerability/$enc',
      ];
      b.writeln('| ${tr('Références', 'References')} | ${links.join(' +\n')}');
      b.writeln('|===');
      b.writeln();
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  String _timestamp() {
    final d = generatedAt.toUtc();
    String p(int n) => n.toString().padLeft(2, '0');
    return '${d.year}-${p(d.month)}-${p(d.day)} ${p(d.hour)}:${p(d.minute)} UTC';
  }

  /// Date longue (« 8 septembre 2026 » / « 8 September 2026 ») pour l'en-tête
  /// du rapport.
  String _frenchDate() {
    if (currentLang == Lang.en) {
      const en = [
        'January',
        'February',
        'March',
        'April',
        'May',
        'June',
        'July',
        'August',
        'September',
        'October',
        'November',
        'December'
      ];
      final d = generatedAt;
      return '${d.day} ${en[d.month - 1]} ${d.year}';
    }
    const months = [
      'janvier',
      'février',
      'mars',
      'avril',
      'mai',
      'juin',
      'juillet',
      'août',
      'septembre',
      'octobre',
      'novembre',
      'décembre'
    ];
    final d = generatedAt;
    return '${d.day} ${months[d.month - 1]} ${d.year}';
  }

  static String _mdEsc(String s) => s.replaceAll('|', r'\|');
  static String _adocEsc(String s) => s.replaceAll('|', r'\|');

  /// Libellé français d'une sévérité (les scanners rapportent l'anglais).
  static String frSeverity(String severity) => switch (severity.toLowerCase()) {
        'critical' => tr('CRITIQUE', 'CRITICAL'),
        'high' => tr('ÉLEVÉE', 'HIGH'),
        'medium' => tr('MOYENNE', 'MEDIUM'),
        'low' => tr('FAIBLE', 'LOW'),
        'negligible' => tr('NÉGLIGEABLE', 'NEGLIGIBLE'),
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
  int _crossSevCount(String level) =>
      _crossRows().where((r) => r.severity.toLowerCase() == level).length;

  /// Verdict de la page de garde : (rôle de thème, phrase).
  (String, String) _verdict() {
    final crit = _crossSevCount('critical');
    final high = _crossSevCount('high');
    final kev = _kevCount;
    if (kev > 0) {
      return (
        'verdict-urgent',
        tr(
            'Action immédiate requise. $kev CVE du catalogue CISA KEV '
                '${kev > 1 ? 'sont exploitées' : 'est exploitée'} activement dans la '
                'nature — appliquer les correctifs sans délai.',
            'Immediate action required. $kev CVE(s) from the CISA KEV catalog '
                '${kev > 1 ? 'are' : 'is'} actively exploited in the '
                'wild — apply the fixes without delay.')
      );
    }
    if (crit > 0) {
      return (
        'verdict-urgent',
        tr(
            'Action prioritaire. $crit vulnérabilité(s) critique(s) à corriger '
                'en priorité.',
            'Priority action. $crit critical vulnerability(ies) to fix '
                'first.')
      );
    }
    if (high > 0) {
      return (
        'verdict-watch',
        tr('À traiter. $high vulnérabilité(s) de sévérité élevée identifiée(s).',
            'To address. $high high-severity vulnerability(ies) identified.')
      );
    }
    return (
      'verdict-ok',
      tr(
          'Aucune vulnérabilité critique ni élevée détectée par les scanners '
              'exécutés.',
          'No critical or high vulnerability detected by the scanners '
              'that ran.')
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
  final theme =
      File('${Directory.systemTemp.path}/sbom_generator_scan_pdf_theme.yml');
  await theme.writeAsString(_kPdfThemeYaml);
  return Process.run('asciidoctor-pdf',
      [adocPath, '-o', pdfPath, '-a', 'pdf-theme=${theme.path}']);
}

/// Index de déclarations VEX (la plus récente d'abord) pour [ScanReportGenerator].
class _VexIndex {
  final List<VexStatement> _statements;
  _VexIndex(List<VexStatement> s) : _statements = s.reversed.toList();

  VexStatement? find(String vulnId, String name, String version) {
    final id = vulnId.toUpperCase();
    for (final s in _statements) {
      if (s.vulnId.toUpperCase() == id && s.appliesTo(name, version)) return s;
    }
    return null;
  }
}

/// Barre de répartition par sévérité (SVG) : segments proportionnels
/// Critical/High/Medium/Low/Autre, mêmes couleurs que le thème PDF.
/// asciidoctor-pdf n'honore pas les fonds de cellule : la barre est une image.
String? buildSeverityBarSvg(
  Map<String, int> countsBySeverity, {
  int width = 640,
  int height = 22,
}) {
  int c(String key) => countsBySeverity.entries
      .where((e) => e.key.toLowerCase() == key)
      .fold(0, (sum, e) => sum + e.value);
  final total = countsBySeverity.values.fold(0, (sum, v) => sum + v);
  if (total == 0) return null;
  final critical = c('critical');
  final high = c('high');
  final medium = c('medium');
  final low = c('low');
  final other = total - critical - high - medium - low;
  final segments = <(int, String)>[
    (critical, 'B3261E'),
    (high, 'C4531A'),
    (medium, 'B9770E'),
    (low, '2E7D32'),
    (other > 0 ? other : 0, '5B6B7A'),
  ].where((s) => s.$1 > 0).toList();
  final radius = height / 2;
  final buf = StringBuffer()
    ..writeln('<svg xmlns="http://www.w3.org/2000/svg" '
        'width="$width" height="$height">')
    ..writeln('<clipPath id="r"><rect x="0" y="0" '
        'width="$width" height="$height" rx="$radius" ry="$radius"/></clipPath>')
    ..writeln('<g clip-path="url(#r)">');
  var x = 0.0;
  for (final (count, color) in segments) {
    final w = width * count / total;
    buf.writeln('<rect x="${x.toStringAsFixed(1)}" y="0" '
        'width="${w.toStringAsFixed(1)}" height="$height" fill="#$color"/>');
    x += w;
  }
  buf.writeln('</g></svg>');
  return buf.toString();
}

/// Encode un SVG en macro image AsciiDoc (data URI, sans fichier temporaire).
String svgImageMacro(String svg, {String? alt}) {
  alt ??= tr('Répartition par sévérité', 'Severity breakdown');
  final b64 = base64Encode(utf8.encode(svg));
  return 'image::data:image/svg+xml;base64,$b64[$alt,pdfwidth=100%]';
}
