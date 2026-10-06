import 'dart:convert';

import '../services/scan_enrichment.dart';
import '../widgets/grype_panel.dart';
import '../widgets/osv_panel.dart';
import '../widgets/trivy_panel.dart';

/// Version du format de fichier de session.
const kSessionFormat = 1;

/// Résultats de scan sauvegardables : les listes de chaque scanner (`null` =
/// scanner non exécuté), les signaux d'exploitabilité et la ou les cibles.
/// Les analyses par couche ne sont pas conservées.
class ScanSession {
  final DateTime savedAt;
  final String guiVersion;
  final List<String> targets;
  final List<GrypeVuln>? grype;
  final List<OsvVuln>? osv;
  final List<TrivyVuln>? trivy;
  final Map<String, ExploitInfo> exploit;

  const ScanSession({
    required this.savedAt,
    required this.guiVersion,
    this.targets = const [],
    this.grype,
    this.osv,
    this.trivy,
    this.exploit = const {},
  });

  bool get isEmpty => grype == null && osv == null && trivy == null;

  /// Identifiants de CVE (normalisés) vus par au moins un scanner.
  int get uniqueCveCount =>
      _keys().map((k) => k.split('\u0000').first).toSet().length;

  /// (CVE normalisée, paquet) → sévérité la plus haute, tous scanners.
  Map<String, String> findings() {
    final out = <String, String>{};
    void add(String id, String pkg, String sev) {
      final key = '${normalizeCveId(id)}\u0000$pkg';
      final cur = out[key];
      if (cur == null || _rank(sev) > _rank(cur)) out[key] = sev.toLowerCase();
    }

    for (final v in grype ?? const <GrypeVuln>[]) {
      add(v.id, v.packageName, v.severity);
    }
    for (final v in osv ?? const <OsvVuln>[]) {
      add(v.id, v.packageName, v.severity);
    }
    for (final v in trivy ?? const <TrivyVuln>[]) {
      add(v.id, v.packageName, v.severity);
    }
    return out;
  }

  Iterable<String> _keys() => findings().keys;

  Map<String, dynamic> toJson() => {
    'format': kSessionFormat,
    'savedAt': savedAt.toUtc().toIso8601String(),
    'guiVersion': guiVersion,
    'targets': targets,
    if (grype != null) 'grype': [for (final v in grype!) _grypeJson(v)],
    if (osv != null) 'osv': [for (final v in osv!) _osvJson(v)],
    if (trivy != null) 'trivy': [for (final v in trivy!) _trivyJson(v)],
    'exploit': {for (final e in exploit.entries) e.key: _exploitJson(e.value)},
  };

  String encode() => const JsonEncoder.withIndent(' ').convert(toJson());

  /// Lève une [FormatException] si [json] n'est pas une session lisible.
  factory ScanSession.fromJson(Map<String, dynamic> json) {
    final format = json['format'];
    if (format is! int || format > kSessionFormat) {
      throw const FormatException('unsupported session format');
    }
    List<T>? list<T>(String key, T Function(Map<String, dynamic>) f) {
      final raw = json[key];
      if (raw == null) return null;
      return [
        for (final e in (raw as List)) f((e as Map).cast<String, dynamic>()),
      ];
    }

    return ScanSession(
      savedAt: DateTime.parse(json['savedAt'] as String),
      guiVersion: '${json['guiVersion'] ?? ''}',
      targets: [for (final t in (json['targets'] as List? ?? const [])) '$t'],
      grype: list('grype', _grypeFrom),
      osv: list('osv', _osvFrom),
      trivy: list('trivy', _trivyFrom),
      exploit: {
        for (final e in ((json['exploit'] as Map?) ?? const {}).entries)
          '${e.key}': _exploitFrom((e.value as Map).cast<String, dynamic>()),
      },
    );
  }

  factory ScanSession.decode(String text) =>
      ScanSession.fromJson(jsonDecode(text) as Map<String, dynamic>);
}

int _rank(String s) => switch (s.toLowerCase()) {
  'critical' => 4,
  'high' => 3,
  'medium' || 'moderate' => 2,
  'low' => 1,
  _ => 0,
};

// ── Comparaison de deux sessions (tendance) ─────────────────────────────────

/// Évolution entre une session de référence et la session courante.
class SessionTrend {
  /// CVE (id, paquet) apparues depuis la référence : clé → sévérité.
  final Map<String, String> added;

  /// CVE de la référence qui ont disparu (corrigées ou plus détectées).
  final Map<String, String> removed;
  final int unchanged;
  final Map<String, int> beforeBySeverity;
  final Map<String, int> afterBySeverity;

  const SessionTrend({
    required this.added,
    required this.removed,
    required this.unchanged,
    required this.beforeBySeverity,
    required this.afterBySeverity,
  });

  int get beforeTotal => beforeBySeverity.values.fold(0, (a, b) => a + b);
  int get afterTotal => afterBySeverity.values.fold(0, (a, b) => a + b);

  factory SessionTrend.compare(ScanSession before, ScanSession after) {
    final b = before.findings(), a = after.findings();
    Map<String, int> count(Map<String, String> f) {
      final m = <String, int>{};
      for (final s in f.values) {
        m[s] = (m[s] ?? 0) + 1;
      }
      return m;
    }

    return SessionTrend(
      added: {
        for (final e in a.entries)
          if (!b.containsKey(e.key)) e.key: e.value,
      },
      removed: {
        for (final e in b.entries)
          if (!a.containsKey(e.key)) e.key: e.value,
      },
      unchanged: a.keys.where(b.containsKey).length,
      beforeBySeverity: count(b),
      afterBySeverity: count(a),
    );
  }

  /// `CVE-2024-1` à partir d'une clé `id\0paquet`.
  static String idOf(String key) => key.split('\u0000').first;
  static String packageOf(String key) {
    final i = key.indexOf('\u0000');
    return i < 0 ? '' : key.substring(i + 1);
  }
}

// ── (dé)sérialisation des modèles de vulnérabilité ──────────────────────────

String? _date(DateTime? d) => d?.toUtc().toIso8601String();
DateTime? _parse(Object? s) => s is String ? DateTime.tryParse(s) : null;

Map<String, dynamic> _grypeJson(GrypeVuln v) => {
  'id': v.id,
  'severity': v.severity,
  'package': v.packageName,
  'version': v.installedVersion,
  'fixed': v.fixedVersion,
  'type': v.packageType,
  'published': _date(v.publishedDate),
  'modified': _date(v.modifiedDate),
  'count': v.occurrenceCount,
};

GrypeVuln _grypeFrom(Map<String, dynamic> j) => GrypeVuln(
  id: '${j['id']}',
  severity: '${j['severity']}',
  packageName: '${j['package']}',
  installedVersion: '${j['version']}',
  fixedVersion: '${j['fixed']}',
  packageType: '${j['type'] ?? ''}',
  publishedDate: _parse(j['published']),
  modifiedDate: _parse(j['modified']),
  occurrenceCount: (j['count'] as int?) ?? 1,
);

Map<String, dynamic> _osvJson(OsvVuln v) => {
  'id': v.id,
  'severity': v.severity,
  'package': v.packageName,
  'version': v.installedVersion,
  'fixed': v.fixedVersion,
  'ecosystem': v.ecosystem,
  'published': _date(v.publishedDate),
  'modified': _date(v.modifiedDate),
  'count': v.occurrenceCount,
};

OsvVuln _osvFrom(Map<String, dynamic> j) => OsvVuln(
  id: '${j['id']}',
  severity: '${j['severity']}',
  packageName: '${j['package']}',
  installedVersion: '${j['version']}',
  fixedVersion: '${j['fixed']}',
  ecosystem: '${j['ecosystem'] ?? ''}',
  publishedDate: _parse(j['published']),
  modifiedDate: _parse(j['modified']),
  occurrenceCount: (j['count'] as int?) ?? 1,
);

Map<String, dynamic> _trivyJson(TrivyVuln v) => {
  'id': v.id,
  'severity': v.severity,
  'package': v.packageName,
  'version': v.installedVersion,
  'fixed': v.fixedVersion,
  'title': v.title,
  'published': _date(v.publishedDate),
  'modified': _date(v.modifiedDate),
  'count': v.occurrenceCount,
};

TrivyVuln _trivyFrom(Map<String, dynamic> j) => TrivyVuln(
  id: '${j['id']}',
  severity: '${j['severity']}',
  packageName: '${j['package']}',
  installedVersion: '${j['version']}',
  fixedVersion: '${j['fixed']}',
  title: '${j['title'] ?? ''}',
  publishedDate: _parse(j['published']),
  modifiedDate: _parse(j['modified']),
  occurrenceCount: (j['count'] as int?) ?? 1,
);

Map<String, dynamic> _exploitJson(ExploitInfo e) => {
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
  if (e.cvssExploitabilityScore != null) 'cvssExpl': e.cvssExploitabilityScore,
  if (e.cvssVector != null) 'vector': e.cvssVector,
  if (e.exploitMaturity != null) 'maturity': e.exploitMaturity,
};

ExploitInfo _exploitFrom(Map<String, dynamic> j) => ExploitInfo(
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
