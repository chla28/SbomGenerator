import 'dart:convert';
import 'dart:io';

// Lecture de l'historique écrit par `sbom_generator watch` (un fichier
// `<sbom>-<empreinte>.history.jsonl` par SBOM dans le dossier d'état). Le
// format est celui de `lib/watch_history.dart` du CLI — à garder cohérent.

/// Un passage de `watch` sur un SBOM.
class HistoryPoint {
  final DateTime at;
  final int total;
  final int added;
  final int resolved;

  /// Constats par sévérité (clés en minuscules).
  final Map<String, int> bySeverity;

  const HistoryPoint({
    required this.at,
    required this.total,
    this.added = 0,
    this.resolved = 0,
    this.bySeverity = const {},
  });

  static HistoryPoint? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final at = DateTime.tryParse('${raw['at']}');
    if (at == null) return null;
    int n(Object? v) => v is int ? v : 0;
    return HistoryPoint(
      at: at,
      total: n(raw['total']),
      added: n(raw['added']),
      resolved: n(raw['resolved']),
      bySeverity: {
        for (final e in ((raw['bySeverity'] as Map?) ?? const {}).entries)
          '${e.key}': n(e.value),
      },
    );
  }
}

/// Historique d'un SBOM, du plus ancien passage au plus récent.
class SbomHistory {
  /// Nom du SBOM suivi (nom de fichier, sans l'empreinte).
  final String name;
  final List<HistoryPoint> points;

  const SbomHistory(this.name, this.points);

  HistoryPoint? get last => points.isEmpty ? null : points.last;

  /// Variation du nombre de CVE depuis l'avant-dernier passage.
  int get delta => points.length < 2
      ? 0
      : points.last.total - points[points.length - 2].total;
}

/// Nom lisible d'un fichier d'historique.
String historyDisplayName(String path) => path
    .split('/')
    .last
    .replaceFirst(RegExp(r'-[0-9a-f]{8}\.history\.jsonl$'), '')
    .replaceFirst(RegExp(r'\.history\.jsonl$'), '');

/// Historiques présents dans [dir] (triés par nom ; fichiers vides ignorés).
List<SbomHistory> loadHistories(Directory dir) {
  if (!dir.existsSync()) return [];
  final files =
      dir
          .listSync()
          .whereType<File>()
          .where((f) => f.path.endsWith('.history.jsonl'))
          .toList()
        ..sort((a, b) => a.path.compareTo(b.path));
  final out = <SbomHistory>[];
  for (final f in files) {
    final points = <HistoryPoint>[];
    for (final line in f.readAsLinesSync()) {
      if (line.trim().isEmpty) continue;
      try {
        final p = HistoryPoint.fromJson(jsonDecode(line));
        if (p != null) points.add(p);
      } on FormatException {
        continue;
      }
    }
    if (points.isNotEmpty) {
      out.add(SbomHistory(historyDisplayName(f.path), points));
    }
  }
  return out;
}

/// Arguments de `sbom_generator verify` (cosign verify-blob).
List<String> verifyArgs({
  required String sbom,
  String? bundle,
  String? key,
  String? identity,
  String? issuer,
}) => [
  'verify',
  sbom,
  if (bundle != null && bundle.isNotEmpty) ...['--bundle', bundle],
  if (key != null && key.isNotEmpty) ...['--key', key],
  if (identity != null && identity.isNotEmpty) ...[
    '--certificate-identity',
    identity,
  ],
  if (issuer != null && issuer.isNotEmpty) ...[
    '--certificate-oidc-issuer',
    issuer,
  ],
];
