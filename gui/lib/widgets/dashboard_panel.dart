import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../models/layer_scan.dart';
import '../services/scan_enrichment.dart';
import '../services/settings_service.dart';
import 'cve_detail.dart';
import 'grype_panel.dart';
import 'osv_panel.dart';
import 'pdf_report.dart';
import 'trivy_panel.dart';
import 'vuln_shared.dart' show adocEscape, SortHeader, VulnRow;

// ─── Tableau de bord de synthèse ─────────────────────────────────────────────

class DashboardPanel extends StatefulWidget {
  final List<GrypeVuln>? grypeVulns;
  final List<OsvVuln>? osvVulns;
  final List<TrivyVuln>? trivyVulns;

  /// Signaux d'exploitabilité par CVE (id normalisé), fusionnés depuis les
  /// trois onglets. Vide = enrichissement non exécuté.
  final Map<String, ExploitInfo> exploitById;

  /// Cible(s) analysée(s) rapportée(s) par les onglets de scan — pour l'en-tête
  /// du rapport exporté. Généralement une seule entrée.
  final List<String> scanTargets;

  /// Analyses par couche des onglets de scan (clé : nom du scanner —
  /// « Grype », « OSV-Scanner », « Trivy »). Vide = pas de section Couches.
  final Map<String, LayerScanResult> layerScans;

  const DashboardPanel({
    super.key,
    required this.grypeVulns,
    required this.osvVulns,
    required this.trivyVulns,
    this.exploitById = const {},
    this.scanTargets = const [],
    this.layerScans = const {},
  });

  // Normalise les sévérités en clé minuscule commune
  static String _norm(String s) => s.toLowerCase();

  static Map<String, int> _countByKey(Iterable<String> severities) {
    final m = <String, int>{};
    for (final s in severities) {
      m[_norm(s)] = (m[_norm(s)] ?? 0) + 1;
    }
    return m;
  }

  @override
  State<DashboardPanel> createState() => _DashboardPanelState();
}

class _DashboardPanelState extends State<DashboardPanel> {
  // Seuil de sévérité du rapport PDF (mémorisé entre sessions).
  ReportSeverityThreshold _threshold = ReportSeverityThreshold.all;

  @override
  void initState() {
    super.initState();
    SettingsService.loadReportSeverity().then((v) {
      if (!mounted || v == null) return;
      setState(() => _threshold = ReportSeverityThreshold.values.firstWhere(
          (t) => t.name == v,
          orElse: () => ReportSeverityThreshold.all));
    });
  }

  Future<void> _export(BuildContext context) async {
    final adoc = await _buildDashboardReport(
      grype: widget.grypeVulns,
      osv: widget.osvVulns,
      trivy: widget.trivyVulns,
      threshold: _threshold,
      exploitById: widget.exploitById,
      scanTargets: widget.scanTargets,
      layerScans: widget.layerScans,
      crossSortCol: _effectiveCrossSort,
      crossSortAsc: _effectiveCrossAsc,
    );
    if (!context.mounted) return;
    await _exportDashboard(context, adoc: adoc, threshold: _threshold);
  }


  // Tri du tableau « Comparaison inter-scanners ». `null` = tri par défaut :
  // priorisation par risque (KEV → EPSS → sévérité) si l'enrichissement a
  // tourné, sinon sévérité décroissante.
  _CrossSort? _crossSort;
  bool _crossSortAsc = true;

  _CrossSort get _effectiveCrossSort =>
      _crossSort ??
      (widget.exploitById.isNotEmpty
          ? _CrossSort.kev
          : _CrossSort.severity);

  bool get _effectiveCrossAsc => _crossSort == null ? true : _crossSortAsc;

  void _onCrossSort(_CrossSort col) => setState(() {
        if (_crossSort == col) {
          _crossSortAsc = !_crossSortAsc;
        } else {
          _crossSort = col;
          // EPSS : décroissant au premier clic (score le plus élevé en tête).
          _crossSortAsc = col != _CrossSort.epss;
        }
      });

  @override
  Widget build(BuildContext context) {
    final grype = widget.grypeVulns;
    final osv = widget.osvVulns;
    final trivy = widget.trivyVulns;

    // CVE IDs uniques sur l'ensemble des scanners (normalisés — voir
    // _normalizeVulnId)
    final allIds = <String>{
      if (grype != null) ...grype.map((v) => _normalizeVulnId(v.id)),
      if (osv != null) ...osv.map((v) => _normalizeVulnId(v.id)),
      if (trivy != null) ...trivy.map((v) => _normalizeVulnId(v.id)),
    };
    final scansRun = [grype, osv, trivy].where((l) => l != null).length;
    final layers = _layerSynthesis(grype, osv, trivy, widget.layerScans);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Synthèse globale ──
          _GlobalSummary(
            uniqueIds: allIds.length,
            scansRun: scansRun,
            grypeCount: grype?.length,
            osvCount: osv?.length,
            trivyCount: trivy?.length,
            onExport: scansRun == 0 ? null : () => _export(context),
            threshold: _threshold,
            onThresholdChanged: (t) {
              setState(() => _threshold = t);
              SettingsService.saveReportSeverity(t.name);
            },
          ),

          const SizedBox(height: 20),

          // ── Cartes par scanner ──
          LayoutBuilder(builder: (_, constraints) {
            final wide = constraints.maxWidth > 750;
            final cards = [
              _ScannerCard(
                name: 'Grype',
                icon: Icons.security_outlined,
                color: const Color(0xFF1565C0),
                vulns: grype,
                severities: grype?.map((v) => v.severity).toList(),
              ),
              _ScannerCard(
                name: 'OSV-Scanner',
                icon: Icons.plagiarism_outlined,
                color: const Color(0xFF6A1B9A),
                vulns: osv,
                severities: osv?.map((v) => v.severity).toList(),
              ),
              _ScannerCard(
                name: 'Trivy',
                icon: Icons.shield_outlined,
                color: const Color(0xFF00695C),
                vulns: trivy,
                severities: trivy?.map((v) => v.severity).toList(),
              ),
            ];
            return wide
                ? IntrinsicHeight(
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: cards
                          .expand((c) => [Expanded(child: c), const SizedBox(width: 16)])
                          .toList()
                        ..removeLast(),
                    ),
                  )
                : Column(
                    children: cards
                        .expand((c) => [c, const SizedBox(height: 16)])
                        .toList()
                      ..removeLast(),
                  );
          }),

          // ── Couches de l'image (analyse par couche) ──
          if (layers != null) ...[
            const SizedBox(height: 24),
            _LayersSection(synthesis: layers),
          ],

          // ── Comparaison inter-scanners (union complète des CVE) ──
          if (scansRun >= 2 && allIds.isNotEmpty) ...[
            const SizedBox(height: 24),
            _CrossScannerSection(
              grypeVulns: grype,
              osvVulns: osv,
              trivyVulns: trivy,
              scansRun: scansRun,
              exploitById: widget.exploitById,
              sortCol: _effectiveCrossSort,
              sortAsc: _effectiveCrossAsc,
              onSort: _onCrossSort,
              layersById: layers?.layersById ?? const {},
            ),
          ],
        ],
      ),
    );
  }
}

// ─── Comparaison inter-scanners : calcul partagé (widget + export) ─────────
//
// Union complète : toutes les CVE vues par au moins un scanner, pas
// seulement celles communes à plusieurs — c'est justement en gardant les
// CVE isolées qu'on repère les écarts de détection entre scanners. Triée
// par sévérité max (depuis grype en priorité). Utilisée à la fois par
// _CrossScannerSection (affichage) et _exportDashboard (rapport AsciiDoc),
// pour que le rapport exporté reflète exactement le tableau affiché.
typedef _CrossRowData = ({
  String id,
  String severity,
  bool inGrype,
  bool inOsv,
  bool inTrivy,
});

// OSV-Scanner préfixe parfois un CVE par l'origine de l'avis distro (ex.
// `DEBIAN-CVE-2026-13221` pour un paquet Debian), là où Grype et Trivy
// rapportent le même identifiant nu (`CVE-2026-13221`) — sans normalisation,
// la comparaison inter-scanners par correspondance exacte de chaîne compte
// la même vulnérabilité comme deux ID distincts, dont un "vu par un seul
// scanner". Vérifié empiriquement sur une image Debian réelle : sur les 95
// ID `DEBIAN-CVE-xxxx` rapportés par OSV-Scanner, 90 correspondent
// exactement (une fois le préfixe retiré) à un ID rapporté par Grype et 94
// à un ID rapporté par Trivy. Le motif générique `PREFIXE-CVE-xxxx` couvre
// aussi les variantes d'autres écosystèmes (ex. UBUNTU-, ALPINE-) sans
// nécessiter de liste de préfixes en dur.
final RegExp _distroPrefixedCveRe = RegExp(r'^[A-Z]+-(CVE-\d{4}-\d+)$');

String _normalizeVulnId(String id) =>
    _distroPrefixedCveRe.firstMatch(id)?.group(1) ?? id;

// ─── Seuil de sévérité du rapport PDF ───────────────────────────────────────

/// Niveau de sévérité minimal des CVE reprises dans le rapport PDF du
/// tableau de bord.
enum ReportSeverityThreshold {
  critical('Critical', 0),
  high('≥ High', 1),
  medium('≥ Medium', 2),
  all('All', 99);

  const ReportSeverityThreshold(this.label, this._maxOrd);

  final String label;
  final int _maxOrd;

  bool accepts(String severity) =>
      this == all || _crossSevOrd(severity) <= _maxOrd;
}

/// Vulnérabilités reprises dans le rapport pour [threshold]. Une CVE (id
/// normalisé) est retenue — avec toutes ses lignes, tous scanners — si sa
/// pire sévérité, tous scanners confondus, atteint le seuil, ou si elle est
/// au catalogue CISA KEV (exploitation active, quelle que soit la
/// sévérité). Filtrer par CVE plutôt que ligne à ligne garde la comparaison
/// inter-scanners fidèle : une CVE High pour Grype et Medium pour Trivy
/// reste marquée comme vue par les deux.
({List<GrypeVuln>? grype, List<OsvVuln>? osv, List<TrivyVuln>? trivy})
    filterForReport(
  List<GrypeVuln>? grype,
  List<OsvVuln>? osv,
  List<TrivyVuln>? trivy,
  ReportSeverityThreshold threshold,
  Map<String, ExploitInfo> exploitById,
) {
  if (threshold == ReportSeverityThreshold.all) {
    return (grype: grype, osv: osv, trivy: trivy);
  }
  final worst = <String, String>{};
  for (final l in <List<VulnRow>?>[grype, osv, trivy]) {
    for (final v in l ?? const <VulnRow>[]) {
      final id = _normalizeVulnId(v.id);
      final prev = worst[id];
      if (prev == null || _crossSevOrd(v.severity) < _crossSevOrd(prev)) {
        worst[id] = v.severity;
      }
    }
  }
  bool keep(VulnRow v) {
    final id = _normalizeVulnId(v.id);
    return threshold.accepts(worst[id] ?? v.severity) ||
        (exploitById[id]?.inKev ?? false);
  }

  return (
    grype: grype?.where(keep).toList(),
    osv: osv?.where(keep).toList(),
    trivy: trivy?.where(keep).toList(),
  );
}

// ─── Synthèse par couche (analyse par couche des onglets de scan) ──────────

/// Couches de l'image et CVE (id normalisé) de chaque couche, tous scanners
/// confondus.
class _LayerSynthesis {
  final List<LayerInfo> layers;

  /// Méthode employée par scanner (« Grype : rattachement… »).
  final Map<String, String> modes;

  /// CVE → couches où elle a été trouvée.
  final Map<String, Set<int>> layersById;

  /// Couche → CVE → pire sévérité.
  final Map<int, Map<String, String>> worstByLayer;

  const _LayerSynthesis(
      this.layers, this.modes, this.layersById, this.worstByLayer);

  int count(int layer, [String? severity]) {
    final m = worstByLayer[layer] ?? const {};
    return severity == null
        ? m.length
        : m.values.where((s) => s.toLowerCase() == severity).length;
  }

  String layersLabel(String id) {
    final l = (layersById[id]?.toList() ?? <int>[])..sort();
    return l.isEmpty ? '—' : l.join(', ');
  }
}

_LayerSynthesis? _layerSynthesis(
  List<GrypeVuln>? grype,
  List<OsvVuln>? osv,
  List<TrivyVuln>? trivy,
  Map<String, LayerScanResult> scans,
) {
  if (scans.isEmpty) return null;
  final layers = <int, LayerInfo>{};
  for (final s in scans.values) {
    for (final l in s.layers) {
      layers.putIfAbsent(l.index, () => l);
    }
  }
  final byId = <String, Set<int>>{};
  final worst = <int, Map<String, String>>{};
  void take(String scanner, List<VulnRow>? vulns) {
    final scan = scans[scanner];
    if (scan == null || vulns == null) return;
    for (final v in vulns) {
      final id = _normalizeVulnId(v.id);
      final ls = scan.layersOf(v.id, v.packageName, v.installedVersion);
      (byId[id] ??= {}).addAll(ls);
      for (final l in ls) {
        final m = worst[l] ??= {};
        final prev = m[id];
        final sev = v.severity;
        if (prev == null || _crossSevOrd(sev) < _crossSevOrd(prev)) m[id] = sev;
      }
    }
  }

  take('Grype', grype);
  take('OSV-Scanner', osv);
  take('Trivy', trivy);
  return _LayerSynthesis(
    layers.values.toList()..sort((a, b) => a.index.compareTo(b.index)),
    {for (final e in scans.entries) e.key: e.value.modeLabel},
    byId,
    worst,
  );
}

List<_CrossRowData> _crossScannerRows(
  List<GrypeVuln>? grypeVulns,
  List<OsvVuln>? osvVulns,
  List<TrivyVuln>? trivyVulns,
) {
  final grypeIds =
      grypeVulns?.map((v) => _normalizeVulnId(v.id)).toSet() ?? {};
  final osvIds = osvVulns?.map((v) => _normalizeVulnId(v.id)).toSet() ?? {};
  final trivyIds =
      trivyVulns?.map((v) => _normalizeVulnId(v.id)).toSet() ?? {};
  final crossIds = {...grypeIds, ...osvIds, ...trivyIds}.toList();

  final grypeMap = {
    for (final v in grypeVulns ?? []) _normalizeVulnId(v.id): v.severity
  };
  final osvMap = {
    for (final v in osvVulns ?? []) _normalizeVulnId(v.id): v.severity
  };
  final trivyMap = {
    for (final v in trivyVulns ?? []) _normalizeVulnId(v.id): v.severity
  };

  int sevOrd(String? s) => switch ((s ?? '').toLowerCase()) {
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        'low' => 3,
        _ => 4,
      };

  crossIds.sort((a, b) {
    final sa = [grypeMap[a], osvMap[a], trivyMap[a]]
        .map((s) => sevOrd(s))
        .reduce((x, y) => x < y ? x : y);
    final sb = [grypeMap[b], osvMap[b], trivyMap[b]]
        .map((s) => sevOrd(s))
        .reduce((x, y) => x < y ? x : y);
    return sa.compareTo(sb);
  });

  return [
    for (final id in crossIds)
      (
        id: id,
        severity: grypeMap[id] ?? osvMap[id] ?? trivyMap[id] ?? '',
        inGrype: grypeIds.contains(id),
        inOsv: osvIds.contains(id),
        inTrivy: trivyIds.contains(id),
      ),
  ];
}

/// Colonne de tri du tableau « Comparaison inter-scanners ».
enum _CrossSort { severity, cveId, grype, osv, trivy, kev, epss }

int _crossSevOrd(String s) => switch (s.toLowerCase()) {
      'critical' => 0,
      'high' => 1,
      'medium' => 2,
      'low' => 3,
      _ => 4,
    };

/// Trie les lignes de la comparaison inter-scanners selon la colonne active.
/// Partagé entre l'affichage (`_CrossScannerSection`) et l'export
/// (`_exportDashboard`) pour que le rapport reflète exactement l'ordre affiché.
///
/// * `severity` : sévérité décroissante (Critical en tête) en ascendant.
/// * `cveId` : ordre alphabétique.
/// * `grype` / `osv` / `trivy` : CVE vues par ce scanner d'abord (✓ avant —).
/// * `kev` : « priorisation risque » — CISA KEV, puis EPSS décroissant, puis
///   sévérité (c'est le tri par défaut quand l'enrichissement a tourné).
/// * `epss` : score EPSS (ascendant ; l'appelant démarre en décroissant).
List<_CrossRowData> _sortCrossRows(
  List<_CrossRowData> rows,
  _CrossSort col,
  bool asc,
  Map<String, ExploitInfo> exploitById,
) {
  ExploitInfo ex(String id) => exploitById[id] ?? ExploitInfo.empty;

  int base(_CrossRowData a, _CrossRowData b) {
    switch (col) {
      case _CrossSort.severity:
        return _crossSevOrd(a.severity).compareTo(_crossSevOrd(b.severity));
      case _CrossSort.cveId:
        return a.id.compareTo(b.id);
      case _CrossSort.grype:
        return (a.inGrype ? 0 : 1).compareTo(b.inGrype ? 0 : 1);
      case _CrossSort.osv:
        return (a.inOsv ? 0 : 1).compareTo(b.inOsv ? 0 : 1);
      case _CrossSort.trivy:
        return (a.inTrivy ? 0 : 1).compareTo(b.inTrivy ? 0 : 1);
      case _CrossSort.kev:
        final ea = ex(a.id), eb = ex(b.id);
        if (ea.inKev != eb.inKev) return ea.inKev ? -1 : 1;
        final e = (eb.epssScore ?? -1).compareTo(ea.epssScore ?? -1);
        if (e != 0) return e;
        return _crossSevOrd(a.severity).compareTo(_crossSevOrd(b.severity));
      case _CrossSort.epss:
        return (ex(a.id).epssScore ?? -1).compareTo(ex(b.id).epssScore ?? -1);
    }
  }

  return [...rows]..sort((a, b) {
    final c = base(a, b);
    final v = c != 0 ? c : a.id.compareTo(b.id); // départage déterministe
    return asc ? v : -v;
  });
}

/// Verdict d'une page de garde de rapport : (rôle de thème, phrase).
(String, String) _verdict(int critical, int high, int kev) {
  if (kev > 0) {
    return (
      'verdict-urgent',
      'Action immédiate requise. '
          '$kev CVE du catalogue CISA KEV ${kev > 1 ? 'sont exploitées' : 'est exploitée'} '
          'activement dans la nature — appliquer les correctifs sans délai.'
    );
  }
  if (critical > 0) {
    return (
      'verdict-urgent',
      'Action prioritaire. $critical vulnérabilité(s) critique(s) '
          'à corriger en priorité.'
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
    'Aucune vulnérabilité critique ni élevée détectée par les scanners exécutés.'
  );
}

// ─── Export AsciiDoc + PDF ────────────────────────────────────────────────
//
// Contrairement à VulnTableView (grype/osv/trivy_panel.dart), le tableau de
// bord n'a pas de liste ligne-par-ligne unique à exporter : le rapport
// reproduit donc l'ensemble de ce qui est affiché à l'écran — résumé
// global, répartition par sévérité pour chaque scanner, puis comparaison
// inter-scanners complète.
/// Contenu AsciiDoc du rapport du tableau de bord, à partir des listes déjà
/// filtrées par le seuil de sévérité.
Future<String> _dashboardReportAdoc({
  required int scansRun,
  required int uniqueIds,
  required List<GrypeVuln>? grype,
  required List<OsvVuln>? osv,
  required List<TrivyVuln>? trivy,
  required List<_CrossRowData> crossRows,
  Map<String, ExploitInfo> exploitById = const {},
  _CrossSort crossSortCol = _CrossSort.severity,
  bool crossSortAsc = true,
  List<String> scanTargets = const [],
  _LayerSynthesis? layers,
  ReportSeverityThreshold threshold = ReportSeverityThreshold.all,

  /// Nombre de CVE uniques avant filtrage par [threshold].
  int? totalIds,
}) async {
  ExploitInfo exSum(String id) => exploitById[id] ?? ExploitInfo.empty;
  int sevCount(String s) => crossRows
      .where((r) => r.severity.toLowerCase() == s)
      .length;
  final crit = sevCount('critical');
  final high = sevCount('high');
  final kev = crossRows.where((r) => exSum(r.id).inKev).length;
  final epssHi =
      crossRows.where((r) => (exSum(r.id).epssScore ?? 0) >= 0.10).length;

  final buf = StringBuffer();
  buf.writeln('= Rapport de vulnérabilités: Synthèse inter-scanners');
  buf.writeln('SBOM Generator $kGuiVersion');
  buf.writeln(':doctype: article');
  buf.writeln(':title-page:');
  buf.writeln(':toc:');
  buf.writeln(':toc-title: Sommaire');
  buf.writeln(':toclevels: 2');
  buf.writeln(':revdate: ${pdfFrenchDate(DateTime.now())}');
  buf.writeln(':icons: font');
  buf.writeln();

  buf.writeln('== Résumé exécutif');
  buf.writeln();
  if (scanTargets.length == 1) {
    buf.writeln('*Cible analysée* : ${adocEscape(scanTargets.single)} +');
  } else if (scanTargets.length > 1) {
    buf.writeln('*Cibles analysées* : '
        '${scanTargets.map((t) => '`${adocEscape(t)}`').join(', ')} +');
  }
  buf.writeln('*Scanners exécutés* : $scansRun / 3'
      '${scansRun == 0 ? '' : ' (${[
          if (grype != null) 'Grype',
          if (osv != null) 'OSV-Scanner',
          if (trivy != null) 'Trivy',
        ].join(', ')})'} — *$uniqueIds* CVE uniques');
  buf.writeln();
  if (threshold != ReportSeverityThreshold.all) {
    buf.writeln('NOTE: Filtre de sévérité : *${threshold.label}* — '
        '$uniqueIds CVE retenue(s)'
        '${totalIds != null ? ' sur $totalIds' : ''}, d\'après la pire '
        'sévérité rapportée par les scanners. Les CVE au catalogue CISA KEV '
        'sont incluses quelle que soit leur sévérité. Tout le rapport '
        '(compteurs, répartition, couches, comparaison, détail) porte sur '
        'ce sous-ensemble.');
    buf.writeln();
  }
  buf.writeln('[cols="^1,^1,^1,^1",frame=none,grid=cols]');
  buf.writeln('|===');
  buf.writeln('h| Critiques h| Élevées h| CISA KEV h| EPSS ≥ 10 %');
  buf.writeln('| [.${crit > 0 ? 'h1-num-alert' : 'h1-num'}]*$crit* '
      '| [.h1-num]*$high* '
      '| [.${kev > 0 ? 'h1-num-alert' : 'h1-num'}]*$kev* '
      '| [.h1-num]*$epssHi*');
  buf.writeln('|===');
  buf.writeln();
  final (verdictRole, verdictText) = _verdict(crit, high, kev);
  buf.writeln('[.$verdictRole]*$verdictText*');
  buf.writeln();

  // Versions détectées au moment de l'export (pas au moment du scan) —
  // toujours à jour même si l'outil a été mis à jour depuis.
  buf.writeln('== Outils');
  buf.writeln();
  buf.writeln('[cols="<3,<1",options="header"]');
  buf.writeln('|===');
  buf.writeln('| Outil | Version');
  buf.writeln(pdfToolVersionRow('sbom_generator_gui', kGuiVersion));
  if (grype != null) {
    buf.writeln(pdfToolVersionRow('Grype', await grypeVersion()));
  }
  if (osv != null) {
    buf.writeln(pdfToolVersionRow('OSV-Scanner', await osvScannerVersion()));
  }
  if (trivy != null) {
    buf.writeln(pdfToolVersionRow('Trivy', await trivyVersion()));
  }
  buf.writeln('|===');
  buf.writeln();

  buf.writeln('== Répartition par scanner');
  buf.writeln();
  for (final scanner in [
    ('Grype', grype),
    ('OSV-Scanner', osv),
    ('Trivy', trivy),
  ]) {
    final (name, vulns) = scanner;
    buf.writeln('=== $name');
    buf.writeln();
    if (vulns == null) {
      buf.writeln('_Non exécuté._');
    } else if (vulns.isEmpty) {
      buf.writeln('Aucune vulnérabilité détectée.');
    } else {
      final counts =
          DashboardPanel._countByKey(vulns.map((v) => v.severity));
      final svg = buildSeverityBarSvg(counts);
      if (svg != null) {
        buf.writeln(svgImageMacro(svg));
        buf.writeln();
      }
      buf.writeln('[cols="<2,<1",options="header"]');
      buf.writeln('|===');
      buf.writeln('| Sévérité | Nombre');
      for (final s in ['critical', 'high', 'medium', 'low']) {
        if ((counts[s] ?? 0) > 0) {
          buf.writeln('| ${pdfSeverityBadge(s)} | ${counts[s]}');
        }
      }
      final other = counts.entries
          .where((e) =>
              !const {'critical', 'high', 'medium', 'low'}.contains(e.key))
          .fold(0, (s, e) => s + e.value);
      if (other > 0) buf.writeln('| ${pdfSeverityBadge('autre')} | $other');
      buf.writeln('| *Total* | *${vulns.length}*');
      buf.writeln('|===');
    }
    buf.writeln();
  }

  if (layers != null) {
    buf.writeln('== Couches de l\'image');
    buf.writeln();
    buf.writeln('Méthode : ${layers.modes.entries.map((e) => '${e.key} — '
        '${e.value}').join(' ; ')}.');
    buf.writeln();
    buf.writeln('[cols="2,3,7,2,3,3",options="header"]');
    buf.writeln('|===');
    buf.writeln('| Couche | Digest | Instruction | CVE | Critiques | Élevées');
    for (final l in layers.layers) {
      final by = l.createdBy ?? '—';
      buf.writeln('| ${l.index} | `${l.shortDigest}` '
          '| ${adocEscape(by.length > 160 ? '${by.substring(0, 159)}…' : by)} '
          '| ${layers.count(l.index)} | ${layers.count(l.index, 'critical')} '
          '| ${layers.count(l.index, 'high')}');
    }
    buf.writeln('|===');
    buf.writeln();
  }

  buf.writeln('== Comparaison inter-scanners');
  buf.writeln();
  final withExploit = exploitById.isNotEmpty;
  final withLayers = layers != null;
  String layerCell(String id) =>
      withLayers ? ' | ${layers.layersLabel(id)}' : '';
  final layerCol = withLayers ? ',2' : '';
  final layerHead = withLayers ? ' | Couche(s)' : '';
  ExploitInfo ex(String id) => exploitById[id] ?? ExploitInfo.empty;
  // Même ordre qu'à l'écran (colonne de tri active du tableau de bord).
  final rows =
      _sortCrossRows(crossRows, crossSortCol, crossSortAsc, exploitById);
  if (crossRows.isEmpty) {
    buf.writeln('_Aucune CVE détectée par les scanners exécutés._');
  } else {
    if (withExploit) {
      buf.writeln('[cols="2,5,1,1,1,1,1$layerCol",options="header"]');
      buf.writeln('|===');
      buf.writeln('| Sévérité | CVE / ID | KEV | EPSS | Grype | OSV '
          '| Trivy$layerHead');
      for (final row in rows) {
        final e = ex(row.id);
        buf.writeln('| ${pdfSeverityBadge(row.severity)} '
            '| ${adocEscape(row.id)} '
            '| ${e.inKev ? '✓' : '—'} '
            '| ${e.epssScore == null ? '—' : e.epssScore!.toStringAsFixed(2)} '
            '| ${row.inGrype ? '✓' : '—'} '
            '| ${row.inOsv ? '✓' : '—'} '
            '| ${row.inTrivy ? '✓' : '—'}${layerCell(row.id)}');
      }
      buf.writeln('|===');
    } else {
      buf.writeln('[cols="2,5,1,1,1$layerCol",options="header"]');
      buf.writeln('|===');
      buf.writeln('| Sévérité | CVE / ID | Grype | OSV | Trivy$layerHead');
      for (final row in rows) {
        buf.writeln('| ${pdfSeverityBadge(row.severity)} '
            '| ${adocEscape(row.id)} '
            '| ${row.inGrype ? '✓' : '—'} '
            '| ${row.inOsv ? '✓' : '—'} '
            '| ${row.inTrivy ? '✓' : '—'}${layerCell(row.id)}');
      }
      buf.writeln('|===');
    }
  }
  buf.writeln();

  if (scansRun >= 2) {
    buf.writeln('[NOTE]');
    buf.writeln('====');
    buf.writeln('Des comptages très différents entre scanners sur les '
        'paquets système (Debian/Alpine/RPM) ne signalent pas forcément '
        'une erreur. OSV-Scanner peut ne trouver aucune CVE sur ces '
        'paquets lorsqu\'il est lancé en mode « scan de SBOM » : son API '
        'n\'indexe les avis Debian que sous une forme de purl précise, '
        'absente du SBOM standard produit par syft — scanner l\'image '
        'directement (`osv-scanner scan image`) donne une couverture '
        'fiable. Grype et Trivy n\'ont par ailleurs pas la même '
        'exhaustivité sur ces mêmes paquets : Grype reprend l\'intégralité '
        'du Debian Security Tracker (avis « won\'t fix » inclus) là où '
        'Trivy ne remonte qu\'un sous-ensemble plus restreint. Aucun des '
        'deux scanners n\'a tort — leurs chiffres bruts ne sont '
        'simplement pas directement comparables sur ce type de paquet. '
        'Détails et méthode de vérification dans la documentation '
        'utilisateur, section « Pourquoi Grype, OSV-Scanner et Trivy ne '
        'trouvent pas les mêmes CVE ».');
    buf.writeln('====');
    buf.writeln();
  }

  // ── Détail des CVE ──
  // `rows` est déjà filtré par le seuil du rapport (filterForReport : pire
  // sévérité atteignant le seuil, ou CISA KEV) : le détail les reprend toutes
  // plutôt que d'appliquer un second filtre indépendant du menu.
  final detailed = rows;
  if (detailed.isNotEmpty) {
    buf.writeln('== Détail des CVE');
    buf.writeln();
    buf.writeln(threshold == ReportSeverityThreshold.all
        ? '${detailed.length} CVE.'
        : '${detailed.length} CVE retenue(s) : sévérité ${threshold.label} '
            'ou au catalogue CISA KEV.');
    buf.writeln();
    for (final r in detailed) {
      final d = _crossCveDetail(r.id, grype, osv, trivy, exploitById);
      buf.writeln('=== ${adocEscape(r.id)}');
      buf.writeln();
      buf.writeln('[cols="<1h,<3a"]');
      buf.writeln('|===');
      buf.write(d.toAdocRows(adocEscape));
      buf.writeln('|===');
      buf.writeln();
    }
  }

  return buf.toString();
}

/// Rapport AsciiDoc du tableau de bord pour [threshold] : filtre les
/// vulnérabilités ([filterForReport]) puis produit tout le rapport sur ce
/// sous-ensemble.
Future<String> _buildDashboardReport({
  required List<GrypeVuln>? grype,
  required List<OsvVuln>? osv,
  required List<TrivyVuln>? trivy,
  required ReportSeverityThreshold threshold,
  Map<String, ExploitInfo> exploitById = const {},
  List<String> scanTargets = const [],
  Map<String, LayerScanResult> layerScans = const {},
  _CrossSort crossSortCol = _CrossSort.severity,
  bool crossSortAsc = true,
}) {
  final f = filterForReport(grype, osv, trivy, threshold, exploitById);
  Set<String> ids(List<List<VulnRow>?> lists) => {
        for (final l in lists) ...?l?.map((v) => _normalizeVulnId(v.id)),
      };
  return _dashboardReportAdoc(
    scansRun: [f.grype, f.osv, f.trivy].where((l) => l != null).length,
    uniqueIds: ids([f.grype, f.osv, f.trivy]).length,
    grype: f.grype,
    osv: f.osv,
    trivy: f.trivy,
    crossRows: _crossScannerRows(f.grype, f.osv, f.trivy),
    exploitById: exploitById,
    crossSortCol: crossSortCol,
    crossSortAsc: crossSortAsc,
    scanTargets: scanTargets,
    layers: _layerSynthesis(f.grype, f.osv, f.trivy, layerScans),
    threshold: threshold,
    totalIds: ids([grype, osv, trivy]).length,
  );
}

/// Rapport AsciiDoc du tableau de bord (tri par défaut) — pour les tests.
@visibleForTesting
Future<String> dashboardReportAdoc({
  required List<GrypeVuln>? grype,
  required List<OsvVuln>? osv,
  required List<TrivyVuln>? trivy,
  ReportSeverityThreshold threshold = ReportSeverityThreshold.all,
  Map<String, ExploitInfo> exploitById = const {},
  Map<String, LayerScanResult> layerScans = const {},
}) =>
    _buildDashboardReport(
      grype: grype,
      osv: osv,
      trivy: trivy,
      threshold: threshold,
      exploitById: exploitById,
      layerScans: layerScans,
    );

/// Écrit [adoc] dans le fichier choisi par l'utilisateur puis le convertit
/// en PDF.
Future<void> _exportDashboard(
  BuildContext context, {
  required String adoc,
  required ReportSeverityThreshold threshold,
}) async {
  final path = await FilePicker.saveFile(
    dialogTitle: 'Exporter le tableau de bord (AsciiDoc + PDF)',
    fileName: threshold == ReportSeverityThreshold.all
        ? 'rapport-vulnerabilites.adoc'
        : 'rapport-vulnerabilites-${threshold.name}.adoc',
    type: FileType.custom,
    allowedExtensions: ['adoc'],
  );
  if (path == null || !context.mounted) return;
  await File(path).writeAsString(adoc);
  if (!context.mounted) return;

  final pdfPath = path.endsWith('.adoc')
      ? '${path.substring(0, path.length - 5)}.pdf'
      : '$path.pdf';

  try {
    final result = await runAsciidoctorPdf(path, pdfPath);
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(result.exitCode == 0
          ? 'Tableau de bord exporté → $path et $pdfPath'
          : 'Tableau de bord exporté → $path '
              '(échec conversion PDF, code ${result.exitCode})'),
      duration: const Duration(seconds: 5),
    ));
  } catch (_) {
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text('Tableau de bord exporté → $path '
          '(asciidoctor-pdf introuvable, PDF non généré)'),
      duration: const Duration(seconds: 5),
    ));
  }
}

// ─── Synthèse globale ─────────────────────────────────────────────────────────

class _GlobalSummary extends StatelessWidget {
  final int uniqueIds;
  final int scansRun;
  final int? grypeCount;
  final int? osvCount;
  final int? trivyCount;

  /// Exporte la synthèse en AsciiDoc + PDF. `null` désactive le bouton
  /// (aucun scanner exécuté, rien à exporter).
  final VoidCallback? onExport;

  /// Seuil de sévérité du rapport exporté.
  final ReportSeverityThreshold threshold;
  final ValueChanged<ReportSeverityThreshold> onThresholdChanged;

  const _GlobalSummary({
    required this.uniqueIds,
    required this.scansRun,
    required this.grypeCount,
    required this.osvCount,
    required this.trivyCount,
    required this.threshold,
    required this.onThresholdChanged,
    this.onExport,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Icon(Icons.dashboard_outlined,
                size: 32, color: theme.colorScheme.primary),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Tableau de bord des vulnérabilités',
                      style: theme.textTheme.titleMedium
                          ?.copyWith(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 4),
                  Text(
                    scansRun == 0
                        ? 'Aucun scanner exécuté — lancez un scan depuis les onglets Grype, OSV-Scanner ou Trivy.'
                        : '$scansRun scanner(s) exécuté(s) · $uniqueIds CVE(s) unique(s) détecté(s)',
                    style: TextStyle(
                        fontSize: 13,
                        color: theme.colorScheme.onSurface
                            .withValues(alpha: 0.7)),
                  ),
                ],
              ),
            ),
            if (scansRun > 0) ...[
              _StatBadge(label: 'CVE uniques', value: uniqueIds,
                  color: uniqueIds == 0 ? Colors.green : Colors.red[700]!),
              const SizedBox(width: 8),
            ],
            Tooltip(
              message: 'Sévérité minimale des CVE du rapport PDF '
                  '(les CVE CISA KEV sont toujours incluses)',
              child: DropdownButton<ReportSeverityThreshold>(
                key: const Key('report-severity'),
                value: threshold,
                isDense: true,
                underline: const SizedBox.shrink(),
                items: [
                  for (final t in ReportSeverityThreshold.values)
                    DropdownMenuItem(
                      value: t,
                      child: Text(t.label, style: const TextStyle(fontSize: 13)),
                    ),
                ],
                onChanged: (t) {
                  if (t != null) onThresholdChanged(t);
                },
              ),
            ),
            IconButton(
              icon: const Icon(Icons.picture_as_pdf_outlined),
              tooltip: 'Exporter en AsciiDoc + PDF',
              onPressed: onExport,
            ),
          ],
        ),
      ),
    );
  }
}

class _StatBadge extends StatelessWidget {
  final String label;
  final int value;
  final Color color;
  const _StatBadge({required this.label, required this.value, required this.color});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text('$value',
            style: TextStyle(
                fontSize: 28, fontWeight: FontWeight.bold, color: color)),
        Text(label,
            style: const TextStyle(fontSize: 11, color: Colors.grey)),
      ],
    );
  }
}

// ─── Carte scanner ────────────────────────────────────────────────────────────

class _ScannerCard extends StatelessWidget {
  final String name;
  final IconData icon;
  final Color color;
  final List<dynamic>? vulns;
  final List<String>? severities;

  const _ScannerCard({
    required this.name,
    required this.icon,
    required this.color,
    required this.vulns,
    required this.severities,
  });

  @override
  Widget build(BuildContext context) {
    final total = vulns?.length ?? 0;
    final loaded = vulns != null;
    final counts = severities != null
        ? DashboardPanel._countByKey(severities!)
        : <String, int>{};

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── En-tête ──
            Row(
              children: [
                Icon(icon, size: 20, color: color),
                const SizedBox(width: 8),
                Text(name,
                    style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 14,
                        color: color)),
                const Spacer(),
                if (!loaded)
                  Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 8, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.grey[200],
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: const Text('Non exécuté',
                        style:
                            TextStyle(fontSize: 10, color: Colors.grey)),
                  )
                else
                  Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 8, vertical: 2),
                    decoration: BoxDecoration(
                      color: total == 0
                          ? Colors.green[50]
                          : Colors.red[50],
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      total == 0 ? '✓ Aucune' : '$total vulnérabilités',
                      style: TextStyle(
                          fontSize: 11,
                          color: total == 0
                              ? Colors.green[700]
                              : Colors.red[700],
                          fontWeight: FontWeight.w600),
                    ),
                  ),
              ],
            ),

            const SizedBox(height: 12),

            if (!loaded)
              Container(
                padding: const EdgeInsets.symmetric(vertical: 16),
                alignment: Alignment.center,
                child: Column(
                  children: [
                    Icon(Icons.play_circle_outline,
                        size: 32, color: Colors.grey[400]),
                    const SizedBox(height: 6),
                    Text(
                      'Lancez le scan depuis\nl\'onglet $name',
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                          fontSize: 11, color: Colors.grey),
                    ),
                  ],
                ),
              )
            else if (total == 0)
              Container(
                padding: const EdgeInsets.symmetric(vertical: 16),
                alignment: Alignment.center,
                child: Column(
                  children: [
                    Icon(Icons.verified_user_outlined,
                        size: 32, color: Colors.green[400]),
                    const SizedBox(height: 6),
                    Text('Aucune vulnérabilité détectée',
                        style: TextStyle(
                            fontSize: 11, color: Colors.green[700])),
                  ],
                ),
              )
            else ...[
              // ── Barre de sévérité empilée ──
              _SeverityBar(counts: counts, total: total),
              const SizedBox(height: 12),
              // ── Détail par sévérité ──
              for (final entry in _sevRows(counts))
                _SevRow(
                  label: entry.label,
                  count: entry.count,
                  total: total,
                  fg: entry.fg,
                  bg: entry.bg,
                ),
            ],
          ],
        ),
      ),
    );
  }

  static List<_SevEntry> _sevRows(Map<String, int> counts) {
    return [
      _SevEntry('Critical', counts['critical'] ?? 0,
          const Color(0xFFB71C1C), const Color(0xFFFFEBEE)),
      _SevEntry('High', counts['high'] ?? 0,
          const Color(0xFFBF360C), const Color(0xFFFBE9E7)),
      _SevEntry('Medium', counts['medium'] ?? 0,
          const Color(0xFFE65100), const Color(0xFFFFF3E0)),
      _SevEntry('Low', counts['low'] ?? 0,
          const Color(0xFF2E7D32), const Color(0xFFF1F8E9)),
      _SevEntry('Autre', (counts['negligible'] ?? 0) +
          (counts['unknown'] ?? 0) +
          counts.entries
              .where((e) => !const {
                    'critical', 'high', 'medium', 'low',
                    'negligible', 'unknown'
                  }.contains(e.key))
              .fold(0, (s, e) => s + e.value),
          Colors.grey, const Color(0xFFF5F5F5)),
    ].where((e) => e.count > 0).toList();
  }
}

class _SevEntry {
  final String label;
  final int count;
  final Color fg;
  final Color bg;
  const _SevEntry(this.label, this.count, this.fg, this.bg);
}

// ─── Barre empilée ────────────────────────────────────────────────────────────

class _SeverityBar extends StatelessWidget {
  final Map<String, int> counts;
  final int total;

  const _SeverityBar({required this.counts, required this.total});

  @override
  Widget build(BuildContext context) {
    if (total == 0) return const SizedBox.shrink();

    int c(String k) => counts[k] ?? 0;
    final other = total -
        c('critical') - c('high') - c('medium') - c('low') -
        c('negligible') - c('unknown');

    final segs = [
      (c('critical'), const Color(0xFFB71C1C)),
      (c('high'), const Color(0xFFBF360C)),
      (c('medium'), const Color(0xFFE65100)),
      (c('low'), const Color(0xFF2E7D32)),
      (c('negligible') + c('unknown') + (other > 0 ? other : 0), Colors.grey),
    ].where((s) => s.$1 > 0).toList();

    return ClipRRect(
      borderRadius: BorderRadius.circular(4),
      child: SizedBox(
        height: 10,
        child: Row(
          children: [
            for (final seg in segs)
              Expanded(
                flex: seg.$1,
                child: Container(color: seg.$2),
              ),
          ],
        ),
      ),
    );
  }
}

// ─── Ligne de sévérité ────────────────────────────────────────────────────────

class _SevRow extends StatelessWidget {
  final String label;
  final int count;
  final int total;
  final Color fg;
  final Color bg;

  const _SevRow({
    required this.label,
    required this.count,
    required this.total,
    required this.fg,
    required this.bg,
  });

  @override
  Widget build(BuildContext context) {
    final pct = total > 0 ? count / total : 0.0;
    return Padding(
      padding: const EdgeInsets.only(bottom: 5),
      child: Row(
        children: [
          Container(
            width: 68,
            padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
            decoration: BoxDecoration(
              color: bg,
              borderRadius: BorderRadius.circular(3),
              border: Border.all(color: fg, width: 0.6),
            ),
            child: Text(label,
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: fg)),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(3),
              child: LinearProgressIndicator(
                value: pct,
                minHeight: 7,
                backgroundColor: Colors.grey[200],
                valueColor: AlwaysStoppedAnimation<Color>(fg),
              ),
            ),
          ),
          const SizedBox(width: 6),
          SizedBox(
            width: 28,
            child: Text('$count',
                textAlign: TextAlign.right,
                style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                    color: fg)),
          ),
        ],
      ),
    );
  }
}

// ─── Section CVEs multi-scanners ─────────────────────────────────────────────

/// Agrège toutes les infos disponibles (en mémoire) sur une CVE (id
/// normalisé) depuis les trois scanners + l'enrichissement — pour la ligne
/// dépliée et l'export.
CveDetail _crossCveDetail(
  String id,
  List<GrypeVuln>? grype,
  List<OsvVuln>? osv,
  List<TrivyVuln>? trivy,
  Map<String, ExploitInfo> exploitById,
) {
  final views = <ScannerCveView>[];
  for (final v in grype ?? const <GrypeVuln>[]) {
    if (_normalizeVulnId(v.id) != id) continue;
    views.add(ScannerCveView(
      scanner: 'Grype',
      severity: v.severity,
      packageName: v.packageName,
      installedVersion: v.installedVersion,
      fixedVersion: v.fixedVersion,
      extra: v.packageType,
      publishedDate: v.publishedDate,
      modifiedDate: v.modifiedDate,
    ));
    break;
  }
  for (final v in osv ?? const <OsvVuln>[]) {
    if (_normalizeVulnId(v.id) != id) continue;
    views.add(ScannerCveView(
      scanner: 'OSV-Scanner',
      severity: v.severity,
      packageName: v.packageName,
      installedVersion: v.installedVersion,
      fixedVersion: v.fixedVersion,
      extra: v.ecosystem,
      publishedDate: v.publishedDate,
      modifiedDate: v.modifiedDate,
    ));
    break;
  }
  for (final v in trivy ?? const <TrivyVuln>[]) {
    if (_normalizeVulnId(v.id) != id) continue;
    views.add(ScannerCveView(
      scanner: 'Trivy',
      severity: v.severity,
      packageName: v.packageName,
      installedVersion: v.installedVersion,
      fixedVersion: v.fixedVersion,
      extra: v.title,
      publishedDate: v.publishedDate,
      modifiedDate: v.modifiedDate,
    ));
    break;
  }
  return CveDetail(
      id: id, views: views, exploit: exploitById[id] ?? ExploitInfo.empty);
}

class _CrossScannerSection extends StatefulWidget {
  final List<GrypeVuln>? grypeVulns;
  final List<OsvVuln>? osvVulns;
  final List<TrivyVuln>? trivyVulns;
  final int scansRun;
  final Map<String, ExploitInfo> exploitById;
  final _CrossSort sortCol;
  final bool sortAsc;
  final ValueChanged<_CrossSort> onSort;

  /// CVE → couches (analyse par couche) ; vide = pas de colonne.
  final Map<String, Set<int>> layersById;

  const _CrossScannerSection({
    required this.grypeVulns,
    required this.osvVulns,
    required this.trivyVulns,
    required this.scansRun,
    required this.sortCol,
    required this.sortAsc,
    required this.onSort,
    this.exploitById = const {},
    this.layersById = const {},
  });

  @override
  State<_CrossScannerSection> createState() => _CrossScannerSectionState();
}

class _CrossScannerSectionState extends State<_CrossScannerSection> {
  final Set<String> _expanded = {};

  @override
  Widget build(BuildContext context) {
    // Union complète : toutes les CVE vues par au moins un scanner — voir
    // _crossScannerRows. Le tri est appliqué par _sortCrossRows (partagé avec
    // l'export AsciiDoc + PDF pour que le rapport reflète exactement l'ordre
    // affiché).
    final baseRows = _crossScannerRows(
        widget.grypeVulns, widget.osvVulns, widget.trivyVulns);
    if (baseRows.isEmpty) return const SizedBox.shrink();

    final hasExploit = widget.exploitById.isNotEmpty;
    ExploitInfo ex(String id) =>
        widget.exploitById[id] ?? ExploitInfo.empty;
    final rows = _sortCrossRows(
        baseRows, widget.sortCol, widget.sortAsc, widget.exploitById);
    final kevCount =
        hasExploit ? rows.where((r) => ex(r.id).inKev).length : 0;

    Widget header(String label, _CrossSort col, {double? width}) => SortHeader(
        label, widget.sortCol == col, widget.sortAsc,
        () => widget.onSort(col),
        width: width);

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.join_inner, size: 18, color: Colors.deepOrange),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Comparaison inter-scanners (${rows.length} CVE'
                    '${kevCount > 0 ? ', dont $kevCount CISA KEV' : ''})',
                    style: const TextStyle(
                        fontWeight: FontWeight.bold, fontSize: 13),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            // En-têtes de tri
            Container(
              color: Theme.of(context).colorScheme.surfaceContainerHigh,
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              child: Row(
                children: [
                  header('SÉV.', _CrossSort.severity, width: 80),
                  Expanded(child: header('CVE / ID', _CrossSort.cveId)),
                  if (hasExploit) ...[
                    header('KEV', _CrossSort.kev, width: 44),
                    header('EPSS', _CrossSort.epss, width: 56),
                  ],
                  header('Grype', _CrossSort.grype, width: 58),
                  header('OSV', _CrossSort.osv, width: 58),
                  header('Trivy', _CrossSort.trivy, width: 58),
                  if (widget.layersById.isNotEmpty)
                    const SizedBox(
                      width: 70,
                      child: Text('COUCHE(S)',
                          style: TextStyle(
                              fontSize: 10,
                              fontWeight: FontWeight.bold,
                              color: Colors.grey)),
                    ),
                  const SizedBox(width: 24),
                ],
              ),
            ),
            // Lignes — toutes affichées, le SingleChildScrollView parent gère le défilement
            for (final row in rows)
              _CrossRow(
                id: row.id,
                inGrype: row.inGrype,
                inOsv: row.inOsv,
                inTrivy: row.inTrivy,
                severity: row.severity,
                scansRun: widget.scansRun,
                hasExploit: hasExploit,
                exploit: hasExploit ? ex(row.id) : null,
                layers: widget.layersById.isEmpty
                    ? null
                    : ((widget.layersById[row.id]?.toList() ?? <int>[])
                          ..sort())
                        .join(', '),
                expanded: _expanded.contains(row.id),
                onToggle: () => setState(() {
                  _expanded.contains(row.id)
                      ? _expanded.remove(row.id)
                      : _expanded.add(row.id);
                }),
                detail: _expanded.contains(row.id)
                    ? CveDetailPanel(
                        detail: _crossCveDetail(row.id, widget.grypeVulns,
                            widget.osvVulns, widget.trivyVulns,
                            widget.exploitById))
                    : null,
              ),
          ],
        ),
      ),
    );
  }
}

class _CrossRow extends StatelessWidget {
  final String id;
  final bool inGrype;
  final bool inOsv;
  final bool inTrivy;
  final String severity;
  final int scansRun;
  final bool hasExploit;
  final ExploitInfo? exploit;

  /// Couches où la CVE a été trouvée (`null` : pas de colonne).
  final String? layers;
  final bool expanded;
  final VoidCallback? onToggle;
  final Widget? detail;

  const _CrossRow({
    required this.id,
    required this.inGrype,
    required this.inOsv,
    required this.inTrivy,
    required this.severity,
    required this.scansRun,
    this.hasExploit = false,
    this.exploit,
    this.layers,
    this.expanded = false,
    this.onToggle,
    this.detail,
  });

  static Color _fg(String s) => switch (s.toLowerCase()) {
        'critical' => const Color(0xFFB71C1C),
        'high' => const Color(0xFFBF360C),
        'medium' => const Color(0xFFE65100),
        'low' => const Color(0xFF2E7D32),
        _ => Colors.grey,
      };

  static Color _bg(String s) => switch (s.toLowerCase()) {
        'critical' => const Color(0xFFFFEBEE),
        'high' => const Color(0xFFFBE9E7),
        'medium' => const Color(0xFFFFF3E0),
        'low' => const Color(0xFFF1F8E9),
        _ => const Color(0xFFF5F5F5),
      };

  @override
  Widget build(BuildContext context) {
    final fg = _fg(severity);
    final bg = _bg(severity);
    final foundByCount =
        [inGrype, inOsv, inTrivy].where((present) => present).length;
    // Vue par un seul scanner alors que plusieurs ont tourné : c'est
    // précisément l'écart de détection que ce tableau doit faire ressortir.
    final isIsolated = foundByCount == 1 && scansRun > 1;

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        InkWell(
          onTap: onToggle,
          child: Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: isIsolated
            ? const Color(0xFFFFF8E1)
            : (expanded ? Theme.of(context).colorScheme.surfaceContainerHigh
                : null),
        border: Border(
          left: BorderSide(
            color: isIsolated ? Colors.amber[700]! : Colors.transparent,
            width: 3,
          ),
          bottom: BorderSide(color: Colors.grey[200]!, width: 0.5),
        ),
      ),
      child: Row(
        children: [
          SizedBox(
            width: 80,
            child: Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
              decoration: BoxDecoration(
                color: bg,
                borderRadius: BorderRadius.circular(3),
                border: Border.all(color: fg, width: 0.6),
              ),
              child: Text(
                severity.isEmpty ? '?' : severity,
                style: TextStyle(
                    fontSize: 9,
                    fontWeight: FontWeight.bold,
                    color: fg),
              ),
            ),
          ),
          if (isIsolated) ...[
            Tooltip(
              message: 'Vu par un seul scanner sur $scansRun',
              child: Icon(Icons.error_outline,
                  size: 13, color: Colors.amber[800]),
            ),
            const SizedBox(width: 4),
          ],
          Expanded(
            child: Row(children: [
              Flexible(
                child: Text(
                  id,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      fontWeight: FontWeight.w500),
                ),
              ),
              if (exploit?.pocKnown ?? false) ...[
                const SizedBox(width: 6),
                const Tooltip(
                  message: 'Exploit / PoC public recensé',
                  child: Icon(Icons.code, size: 12, color: Colors.purple),
                ),
              ],
            ]),
          ),
          if (hasExploit) ...[
            SizedBox(width: 44, child: _kevCell()),
            SizedBox(width: 56, child: _epssCell()),
          ],
          for (final present in [inGrype, inOsv, inTrivy])
            SizedBox(
              width: 58,
              child: Icon(
                present ? Icons.check_circle : Icons.radio_button_unchecked,
                size: 14,
                color: present ? Colors.green[600] : Colors.grey[300],
              ),
            ),
          if (layers != null)
            SizedBox(
              width: 70,
              child: Text(layers!.isEmpty ? '—' : layers!,
                  style: const TextStyle(fontSize: 11),
                  overflow: TextOverflow.ellipsis),
            ),
          SizedBox(
            width: 24,
            child: Icon(
                expanded ? Icons.expand_less : Icons.expand_more,
                size: 18,
                color: Colors.grey[500]),
          ),
        ],
      ),
          ),
        ),
        ?detail,
      ],
    );
  }

  Widget _kevCell() {
    final e = exploit;
    if (e == null || !e.inKev) {
      return const Text('—',
          style: TextStyle(fontSize: 10, color: Colors.grey));
    }
    return Tooltip(
      message: 'CISA KEV — exploitée activement dans la nature'
          '${e.kevRansomware ? ' · usage par rançongiciel' : ''}',
      child: Icon(Icons.local_fire_department,
          size: 14, color: Colors.red[700]),
    );
  }

  Widget _epssCell() {
    final s = exploit?.epssScore;
    if (s == null) {
      return const Text('—',
          style: TextStyle(fontSize: 10, color: Colors.grey));
    }
    final pct = ((exploit!.epssPercentile ?? 0) * 100).round();
    return Tooltip(
      message: 'EPSS ${s.toStringAsFixed(2)} — probabilité d\'exploitation '
          'à 30 jours (percentile $pct)',
      child: Text(
        s.toStringAsFixed(2),
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.bold,
          color: s >= 0.10 ? Colors.deepOrange : Colors.blueGrey,
        ),
      ),
    );
  }
}

// ─── Couches de l'image ──────────────────────────────────────────────────────

class _LayersSection extends StatelessWidget {
  final _LayerSynthesis synthesis;
  const _LayersSection({required this.synthesis});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    const head = TextStyle(
        fontSize: 10, fontWeight: FontWeight.bold, color: Colors.grey);
    Widget num(int n, {Color? color}) => SizedBox(
          width: 64,
          child: Text('$n',
              textAlign: TextAlign.right,
              style: TextStyle(
                  fontSize: 12,
                  fontWeight: n > 0 && color != null ? FontWeight.bold : null,
                  color: n > 0 ? color : Colors.grey)),
        );
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.layers_outlined,
                    size: 18, color: theme.colorScheme.tertiary),
                const SizedBox(width: 8),
                Text('Couches de l\'image (${synthesis.layers.length})',
                    style: const TextStyle(
                        fontWeight: FontWeight.bold, fontSize: 13)),
              ],
            ),
            const SizedBox(height: 4),
            for (final e in synthesis.modes.entries)
              Text('${e.key} : ${e.value}',
                  style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 8),
            Container(
              color: theme.colorScheme.surfaceContainerHigh,
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              child: const Row(
                children: [
                  SizedBox(width: 60, child: Text('COUCHE', style: head)),
                  SizedBox(width: 100, child: Text('DIGEST', style: head)),
                  Expanded(child: Text('INSTRUCTION', style: head)),
                  SizedBox(
                      width: 64,
                      child: Text('CVE', textAlign: TextAlign.right, style: head)),
                  SizedBox(
                      width: 64,
                      child: Text('CRIT.', textAlign: TextAlign.right, style: head)),
                  SizedBox(
                      width: 64,
                      child: Text('ÉLEV.', textAlign: TextAlign.right, style: head)),
                ],
              ),
            ),
            for (final l in synthesis.layers)
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
                decoration: BoxDecoration(
                  border: Border(
                      bottom: BorderSide(color: Colors.grey[200]!, width: 0.5)),
                ),
                child: Row(
                  children: [
                    SizedBox(
                        width: 60,
                        child: Text('${l.index}',
                            style: const TextStyle(
                                fontSize: 12, fontWeight: FontWeight.w600))),
                    SizedBox(
                        width: 100,
                        child: Text(l.shortDigest,
                            style: const TextStyle(
                                fontFamily: 'monospace', fontSize: 11))),
                    Expanded(
                      child: Tooltip(
                        message: l.createdBy ?? '',
                        child: Text(l.createdBy ?? '—',
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(fontSize: 11)),
                      ),
                    ),
                    num(synthesis.count(l.index)),
                    num(synthesis.count(l.index, 'critical'),
                        color: const Color(0xFFB71C1C)),
                    num(synthesis.count(l.index, 'high'),
                        color: const Color(0xFFBF360C)),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }
}
