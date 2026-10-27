import 'dart:convert';
import 'dart:io';

/// Une ligne de l'historique d'un SBOM suivi par `watch`.
class HistoryEntry {
  final DateTime at;
  final int total;
  final int added;
  final int resolved;

  /// Constats par sévérité (clés en minuscules : critical, high…).
  final Map<String, int> bySeverity;

  const HistoryEntry({
    required this.at,
    required this.total,
    this.added = 0,
    this.resolved = 0,
    this.bySeverity = const {},
  });

  Map<String, dynamic> toJson() => {
        'at': at.toUtc().toIso8601String(),
        'total': total,
        'added': added,
        'resolved': resolved,
        'bySeverity': bySeverity,
      };

  static HistoryEntry? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final at = DateTime.tryParse('${raw['at']}');
    if (at == null) return null;
    int n(Object? v) => v is int ? v : 0;
    return HistoryEntry(
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

/// Entrée d'historique d'un rapport `scan --format json`.
HistoryEntry historyEntryFromScan(Map<String, dynamic> scan,
    {int added = 0, int resolved = 0, DateTime? now}) {
  final findings = (scan['findings'] as List? ?? const []).whereType<Map>();
  final bySeverity = <String, int>{};
  for (final f in findings) {
    final sev = '${f['severity'] ?? 'unknown'}'.toLowerCase();
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
  }
  return HistoryEntry(
    at: now ?? DateTime.now(),
    total: findings.length,
    added: added,
    resolved: resolved,
    bySeverity: bySeverity,
  );
}

/// Fichier d'historique associé au fichier d'état [stateFile].
String historyFileFor(String stateFile) =>
    stateFile.replaceFirst(RegExp(r'\.json$'), '') + '.history.jsonl';

/// Nombre maximal de lignes conservées par SBOM (les plus récentes).
const maxHistoryEntries = 1000;

void appendHistory(String stateFile, HistoryEntry entry) {
  final path = historyFileFor(stateFile);
  File(path).writeAsStringSync('${jsonEncode(entry.toJson())}\n',
      mode: FileMode.append);
  final lines = File(path).readAsLinesSync();
  if (lines.length > maxHistoryEntries) {
    File(path).writeAsStringSync(
        '${lines.sublist(lines.length - maxHistoryEntries).join('\n')}\n');
  }
}

/// Lit l'historique (lignes illisibles ignorées), du plus ancien au plus récent.
List<HistoryEntry> readHistory(String historyFile) {
  final f = File(historyFile);
  if (!f.existsSync()) return [];
  final out = <HistoryEntry>[];
  for (final line in f.readAsLinesSync()) {
    if (line.trim().isEmpty) continue;
    try {
      final e = HistoryEntry.fromJson(jsonDecode(line));
      if (e != null) out.add(e);
    } on FormatException {
      continue;
    }
  }
  return out;
}
