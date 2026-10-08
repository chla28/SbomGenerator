import 'dart:convert';

import 'i18n.dart';
import 'layer_scan.dart' show LayerRef;
import 'vex.dart';
import 'vuln_enrichment.dart';

/// Noms internes des scanners (clés de `resultsByScanner`).
const reportScanners = ['grype', 'osv', 'trivy'];

/// Une CVE écartée du rapport par une déclaration VEX.
class VexHit {
  final String id;
  final String package;
  final VexStatement statement;
  const VexHit(this.id, this.package, this.statement);
}

/// Données d'un rapport de vulnérabilités, lues dans un fichier produit par
/// `scan --format json` **ou** dans une session de la GUI : un seul lecteur,
/// donc un seul rapport (`ScanReportGenerator`) pour le CLI et la GUI.
class ReportInput {
  /// Résultats par scanner (`null` = scanner non exécuté).
  final Map<String, List<Map<String, dynamic>>?> results;
  final Map<String, ExploitInfo> exploit;
  final Map<String, String?> toolVersions;
  final List<LayerRef> layers;
  final String? layerScanMode;

  /// Cible(s) analysée(s) (libellés).
  final List<String> targets;

  /// Déclarations VEX embarquées.
  final List<VexStatement> vex;

  /// CVE déjà écartées par le VEX avant l'écriture du fichier (`scan`).
  final List<VexHit> vexSuppressed;
  final DateTime? generatedAt;

  const ReportInput({
    required this.results,
    this.exploit = const {},
    this.toolVersions = const {},
    this.layers = const [],
    this.layerScanMode,
    this.targets = const [],
    this.vex = const [],
    this.vexSuppressed = const [],
    this.generatedAt,
  });

  /// Détecte le format (rapport `scan --format json` ou session de la GUI).
  /// Lève [FormatException] pour tout autre contenu.
  factory ReportInput.parse(Map<String, dynamic> json) {
    if (json['schema'] == 'sbom-generator/scan/v1') {
      return ReportInput._fromScan(json);
    }
    if (json['format'] is int && json['savedAt'] is String) {
      return ReportInput._fromSession(json);
    }
    throw FormatException(tr(
        'fichier non reconnu : attendu un `scan --format json` ou une session de la GUI',
        'unrecognised file: expected a `scan --format json` output or a GUI session'));
  }

  factory ReportInput.decode(String text) =>
      ReportInput.parse(jsonDecode(text) as Map<String, dynamic>);

  // ── scan --format json ───────────────────────────────────────────────────

  factory ReportInput._fromScan(Map<String, dynamic> j) {
    final ran = {
      for (final s in (j['scanners'] as List? ?? const [])) '$s',
    };
    final results = <String, List<Map<String, dynamic>>?>{
      for (final s in reportScanners) s: ran.contains(s) ? [] : null,
    };
    for (final f in (j['findings'] as List? ?? const [])) {
      if (f is! Map) continue;
      final s = '${f['scanner']}';
      if (!results.containsKey(s)) continue;
      final m = Map<String, dynamic>.from(f)
        ..remove('scanner')
        ..remove('exploit');
      (results[s] ??= []).add(m);
    }
    return ReportInput(
      results: results,
      exploit: _exploitMap(j['exploit']),
      toolVersions: {
        for (final e in ((j['toolVersions'] as Map?) ?? const {}).entries)
          '${e.key}': e.value as String?,
      },
      layers: _layers(j['layers']),
      layerScanMode: j['layerScanMode'] as String?,
      targets: [
        if ('${j['target'] ?? ''}'.isNotEmpty) '${j['target']}',
      ],
      vex: _vex(j['vex']),
      vexSuppressed: _hits(j['vexSuppressed']),
      generatedAt: DateTime.tryParse('${j['generatedAt']}'),
    );
  }

  // ── session de la GUI ────────────────────────────────────────────────────

  factory ReportInput._fromSession(Map<String, dynamic> j) {
    final layerScans = (j['layerScans'] as Map?) ?? const {};
    // Couches de chaque (scanner → clé id\0paquet\0version → indices).
    List<int> layersOf(String scanner, String id, String pkg, String ver) {
      final byKey = (layerScans[scanner] as Map?)?['byKey'] as Map?;
      final raw = byKey?['$id\u0000$pkg\u0000$ver'] as List?;
      return [for (final i in raw ?? const []) (i as num).toInt()]..sort();
    }

    List<Map<String, dynamic>>? convert(
      String key,
      String scanner,
      Map<String, dynamic> Function(Map<String, dynamic>) one,
    ) {
      final raw = j[key];
      if (raw == null) return null;
      final out = <Map<String, dynamic>>[];
      for (final e in (raw as List)) {
        final m = (e as Map).cast<String, dynamic>();
        final f = one(m);
        final layers = layersOf(
            scanner, '${m['id']}', '${m['package']}', '${m['version']}');
        if (layers.isEmpty) {
          out.add(f);
        } else {
          for (final i in layers) {
            out.add({...f, 'layer': i});
          }
        }
      }
      return out;
    }

    Map<String, dynamic> base(Map<String, dynamic> m) {
      final fixed = '${m['fixed'] ?? ''}'.trim();
      final versions = [
        for (final p in fixed.split(RegExp(r'[,;]')))
          if (RegExp(r'\d').hasMatch(p.trim())) p.trim(),
      ];
      return {
        'id': '${m['id']}',
        'severity': '${m['severity']}',
        'package': '${m['package']}@${m['version']}',
        'published': m['published'],
        'modified': m['modified'],
        'fixState': versions.isNotEmpty ? 'fixed' : fixed,
        'fixedVersions': versions,
      };
    }

    final results = <String, List<Map<String, dynamic>>?>{
      'grype': convert(
          'grype',
          'Grype',
          (m) => {
                ...base(m),
                if ('${m['type'] ?? ''}'.isNotEmpty) 'extra': m['type'],
              }),
      'osv': convert(
          'osv',
          'OSV-Scanner',
          (m) => {
                ...base(m),
                if ('${m['ecosystem'] ?? ''}'.isNotEmpty)
                  'extra': m['ecosystem'],
              }),
      'trivy': convert(
          'trivy',
          'Trivy',
          (m) => {
                ...base(m),
                if ('${m['title'] ?? ''}'.isNotEmpty) 'extra': m['title'],
              }),
    };

    // Couches : celles du premier scanner qui en porte.
    var layers = <LayerRef>[];
    String? mode;
    for (final e in layerScans.entries) {
      final ls = _layers((e.value as Map)['layers']);
      if (ls.isNotEmpty) {
        layers = ls;
        mode = (e.value as Map)['mode'] as String?;
        break;
      }
    }
    return ReportInput(
      results: results,
      exploit: _exploitMap(j['exploit']),
      toolVersions: {
        'sbom_generator_gui': j['guiVersion'] as String?,
      },
      layers: layers,
      layerScanMode: mode,
      targets: [for (final t in (j['targets'] as List? ?? const [])) '$t'],
      vex: _vex(j['vex']),
      generatedAt: DateTime.tryParse('${j['savedAt']}'),
    );
  }
}

// ── Sérialisation partagée ───────────────────────────────────────────────────

String? _date(DateTime? d) => d?.toUtc().toIso8601String();
DateTime? _parse(Object? s) => s is String ? DateTime.tryParse(s) : null;

/// Clés identiques à celles des sessions de la GUI.
Map<String, dynamic> exploitToJson(ExploitInfo e) => {
      if (e.inKev) 'kev': true,
      if (e.kevDateAdded != null) 'kevAdded': _date(e.kevDateAdded),
      if (e.kevDueDate != null) 'kevDue': _date(e.kevDueDate),
      if (e.kevRansomware) 'ransomware': true,
      if (e.epssScore != null) 'epss': e.epssScore,
      if (e.epssPercentile != null) 'epssPct': e.epssPercentile,
      if (e.pocKnown) 'poc': true,
      if (e.pocCount > 0) 'pocCount': e.pocCount,
      if (e.pocUrls.isNotEmpty) 'pocUrls': e.pocUrls,
      if (e.cvssBaseScore != null) 'cvss': e.cvssBaseScore,
      if (e.cvssExploitabilityScore != null)
        'cvssExpl': e.cvssExploitabilityScore,
      if (e.cvssVector != null) 'vector': e.cvssVector,
      if (e.exploitMaturity != null) 'maturity': e.exploitMaturity,
    };

ExploitInfo exploitFromJson(Map<String, dynamic> j) => ExploitInfo(
      inKev: j['kev'] == true,
      kevDateAdded: _parse(j['kevAdded']),
      kevDueDate: _parse(j['kevDue']),
      kevRansomware: j['ransomware'] == true,
      epssScore: (j['epss'] as num?)?.toDouble(),
      epssPercentile: (j['epssPct'] as num?)?.toDouble(),
      pocKnown: j['poc'] == true,
      pocCount: (j['pocCount'] as int?) ?? 0,
      pocUrls: [for (final u in (j['pocUrls'] as List? ?? const [])) '$u'],
      cvssBaseScore: (j['cvss'] as num?)?.toDouble(),
      cvssExploitabilityScore: (j['cvssExpl'] as num?)?.toDouble(),
      cvssVector: j['vector'] as String?,
      exploitMaturity: j['maturity'] as String?,
    );

Map<String, ExploitInfo> _exploitMap(Object? raw) => {
      for (final e in ((raw as Map?) ?? const {}).entries)
        '${e.key}': exploitFromJson((e.value as Map).cast<String, dynamic>()),
    };

List<LayerRef> _layers(Object? raw) => [
      for (final l in (raw as List? ?? const []))
        if (l is Map)
          LayerRef(
            index: (l['index'] as num).toInt(),
            digest: '${l['digest'] ?? ''}',
            createdBy: l['createdBy'] as String?,
          ),
    ];

Map<String, dynamic> layerToJson(LayerRef l) => {
      'index': l.index,
      'digest': l.digest,
      if (l.createdBy != null) 'createdBy': l.createdBy,
    };

Map<String, dynamic> hitToJson(VexHit h) => {
      'id': h.id,
      'package': h.package,
      'statement': vexToJson(h.statement),
    };

List<VexHit> _hits(Object? raw) => [
      for (final h in (raw as List? ?? const []))
        if (h is Map)
          for (final st in _vex([h['statement']]))
            VexHit('${h['id']}', '${h['package']}', st),
    ];

Map<String, dynamic> vexToJson(VexStatement s) => {
      'vulnId': s.vulnId,
      'products': s.products,
      'status': s.status,
      if (s.justification != null) 'justification': s.justification,
      if (s.impactStatement != null) 'impact': s.impactStatement,
      if (s.actionStatement != null) 'action': s.actionStatement,
    };

List<VexStatement> _vex(Object? raw) => [
      for (final s in (raw as List? ?? const []))
        if (s is Map && vexStatuses.contains('${s['status']}'))
          VexStatement(
            vulnId: '${s['vulnId']}',
            products: [
              for (final p in (s['products'] as List? ?? const [])) '$p'
            ],
            status: '${s['status']}',
            justification: s['justification'] as String?,
            impactStatement: s['impact'] as String?,
            actionStatement: s['action'] as String?,
          ),
    ];
