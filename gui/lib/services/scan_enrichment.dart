import 'dart:convert';

import 'vuln_enrichment.dart';

export 'vuln_enrichment.dart' show ExploitInfo, CveSeed;

final _distroCveRe = RegExp(r'^[A-Z]+-(CVE-\d{4}-\d+)$');

/// Retire un préfixe d'avis de distribution (`DEBIAN-CVE-2026-1` → `CVE-2026-1`)
/// pour dédupliquer entre scanners — même logique que le CLI et le tableau de
/// bord.
String normalizeCveId(String id) => _distroCveRe.firstMatch(id)?.group(1) ?? id;

/// Enrichit [ids] (identifiants normalisés) avec les signaux d'exploitabilité.
/// [online] `false` → cache local seulement, aucune requête réseau.
Future<Map<String, ExploitInfo>> enrichCves(
  Set<String> ids, {
  Map<String, CveSeed> seed = const {},
  bool online = true,
}) {
  final cves = ids.where((c) => c.isNotEmpty).toSet();
  if (cves.isEmpty) return Future.value(const {});
  return VulnEnricher(
    enableNetwork: online,
    enablePoc: online,
  ).enrich(cves, seed: seed);
}

// ── Extraction des graines depuis le JSON brut des scanners ────────────────

/// Grype expose nativement CISA KEV, EPSS et le vecteur CVSS dans sa base :
/// autant de requêtes réseau évitées.
Map<String, CveSeed> seedsFromGrypeJson(String raw) {
  final out = <String, CveSeed>{};
  try {
    final data = jsonDecode(raw) as Map<String, dynamic>;
    for (final m in (data['matches'] as List? ?? const [])) {
      final vuln = (m as Map)['vulnerability'] as Map<String, dynamic>? ?? {};
      final id = normalizeCveId(vuln['id'] as String? ?? '');
      if (id.isEmpty) continue;
      final (vector, base) = _cvssFromGrype(vuln['cvss'] as List?);
      final kev = (vuln['knownExploited'] as List?) ?? const [];
      final kev0 = kev.isNotEmpty ? kev.first as Map<String, dynamic> : null;
      final epss = (vuln['epss'] as List?) ?? const [];
      final epss0 = epss.isNotEmpty ? epss.first as Map<String, dynamic> : null;
      final seed = CveSeed(
        cvssVector: vector,
        cvssBaseScore: base,
        kev: kev0 != null,
        kevDateAdded: _tryDate(kev0?['dateAdded'] as String?),
        kevDueDate: _tryDate(kev0?['dueDate'] as String?),
        kevRansomware:
            ((kev0?['knownRansomwareCampaignUse'] as String?) ?? '')
                .toLowerCase() ==
            'known',
        epssScore: (epss0?['epss'] as num?)?.toDouble(),
        epssPercentile: (epss0?['percentile'] as num?)?.toDouble(),
      );
      out[id] = out.containsKey(id) ? out[id]!.merge(seed) : seed;
    }
  } catch (_) {
    // JSON déjà validé par le modèle : en cas de souci, pas de graine.
  }
  return out;
}

/// OSV-Scanner : seul le vecteur CVSS (`severity[].score`) est exploitable.
Map<String, CveSeed> seedsFromOsvJson(String raw) {
  final out = <String, CveSeed>{};
  try {
    final data = jsonDecode(raw) as Map<String, dynamic>;
    for (final result in (data['results'] as List? ?? const [])) {
      for (final pkg in ((result as Map)['packages'] as List? ?? const [])) {
        for (final v
            in ((pkg as Map)['vulnerabilities'] as List? ?? const [])) {
          final m = v as Map<String, dynamic>;
          final aliases = (m['aliases'] as List?)?.cast<String>() ?? const [];
          final cve = aliases.firstWhere(
            (a) => a.startsWith('CVE-'),
            orElse: () => m['id'] as String? ?? '',
          );
          final id = normalizeCveId(cve);
          if (id.isEmpty) continue;
          final vector = _cvssVectorFromList(m['severity'] as List?);
          if (vector == null) continue;
          final seed = CveSeed(cvssVector: vector);
          out[id] = out.containsKey(id) ? out[id]!.merge(seed) : seed;
        }
      }
    }
  } catch (_) {}
  return out;
}

/// Trivy : vecteur + score CVSS depuis la map `CVSS` (préférence NVD).
Map<String, CveSeed> seedsFromTrivyJson(String raw) {
  final out = <String, CveSeed>{};
  try {
    final data = jsonDecode(raw) as Map<String, dynamic>;
    for (final result in (data['Results'] as List? ?? const [])) {
      for (final v
          in ((result as Map)['Vulnerabilities'] as List? ?? const [])) {
        final m = v as Map<String, dynamic>;
        final id = normalizeCveId(m['VulnerabilityID'] as String? ?? '');
        if (id.isEmpty) continue;
        final (vector, base) = _cvssFromTrivy(m['CVSS'] as Map?);
        if (vector == null) continue;
        final seed = CveSeed(cvssVector: vector, cvssBaseScore: base);
        out[id] = out.containsKey(id) ? out[id]!.merge(seed) : seed;
      }
    }
  } catch (_) {}
  return out;
}

(String?, double?) _cvssFromGrype(List? cvss) {
  if (cvss == null || cvss.isEmpty) return (null, null);
  Map<String, dynamic>? best;
  for (final c in cvss) {
    final m = c as Map<String, dynamic>;
    if ((m['vector'] as String?)?.isNotEmpty != true) continue;
    best ??= m;
    if ((m['type'] as String?)?.toLowerCase() == 'primary') {
      best = m;
      break;
    }
  }
  if (best == null) return (null, null);
  final metrics = best['metrics'] as Map<String, dynamic>? ?? const {};
  return (
    best['vector'] as String?,
    (metrics['baseScore'] as num?)?.toDouble(),
  );
}

String? _cvssVectorFromList(List? severity) {
  if (severity == null) return null;
  String? pick;
  for (final s in severity) {
    final vec = (s as Map)['score'] as String?;
    if (vec == null || !vec.startsWith('CVSS:')) continue;
    if (pick == null || vec.compareTo(pick) > 0) pick = vec;
  }
  return pick;
}

(String?, double?) _cvssFromTrivy(Map? cvss) {
  if (cvss == null || cvss.isEmpty) return (null, null);
  Map<String, dynamic>? src = (cvss['nvd'] as Map?)?.cast<String, dynamic>();
  src ??= cvss.values.whereType<Map>().cast<Map<String, dynamic>>().firstWhere(
    (m) => (m['V3Vector'] as String?)?.isNotEmpty == true,
    orElse: () => const {},
  );
  final vec = src['V3Vector'] as String?;
  return (
    (vec?.isNotEmpty == true) ? vec : null,
    (src['V3Score'] as num?)?.toDouble(),
  );
}

DateTime? _tryDate(String? s) {
  if (s == null || s.isEmpty) return null;
  try {
    return DateTime.parse(s);
  } catch (_) {
    return null;
  }
}
