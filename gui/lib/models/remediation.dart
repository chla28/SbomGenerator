import '../services/scan_enrichment.dart' show ExploitInfo, normalizeCveId;

/// Une CVE vue sous l'angle de la remédiation : ce qu'il faut installer pour
/// la corriger et qui la voit.
class RemediationCve {
  final String id;
  final String severity;

  /// Versions corrigées proposées par les scanners (vide = pas de correctif).
  final List<String> fixedVersions;
  final bool inKev;
  final double epss;
  final Set<String> scanners;

  const RemediationCve({
    required this.id,
    required this.severity,
    required this.fixedVersions,
    required this.inKev,
    required this.epss,
    required this.scanners,
  });

  bool get hasFix => fixedVersions.isNotEmpty;
}

/// Mise à jour d'un paquet et gain de risque associé.
class RemediationItem {
  final String packageName;
  final String installedVersion;

  /// Version minimale qui corrige toutes les CVE corrigeables du paquet ;
  /// `null` si aucune CVE du paquet n'a de correctif.
  final String? targetVersion;

  /// CVE corrigées en passant à [targetVersion], triées par risque décroissant.
  final List<RemediationCve> fixed;

  /// CVE sans correctif connu : restent après la mise à jour.
  final List<RemediationCve> unfixed;

  const RemediationItem({
    required this.packageName,
    required this.installedVersion,
    required this.targetVersion,
    required this.fixed,
    required this.unfixed,
  });

  /// Gain de risque : somme des poids des CVE corrigées.
  double get gain => fixed.fold(0.0, (s, c) => s + cveRisk(c));

  /// Risque restant après la mise à jour (CVE sans correctif).
  double get remaining => unfixed.fold(0.0, (s, c) => s + cveRisk(c));

  int get kevFixed => fixed.where((c) => c.inKev).length;

  String get worstFixedSeverity => _worst(fixed.map((c) => c.severity));
}

String _worst(Iterable<String> severities) {
  var best = 'unknown';
  for (final s in severities) {
    if (severityRank(s) > severityRank(best)) best = s.toLowerCase();
  }
  return best;
}

/// 4 = critique … 1 = faible, 0 = inconnue/négligeable.
int severityRank(String s) => switch (s.toLowerCase()) {
  'critical' => 4,
  'high' => 3,
  'medium' || 'moderate' => 2,
  'low' => 1,
  _ => 0,
};

/// Poids d'une CVE : sévérité (10/5/2/1), +20 si exploitée activement (CISA
/// KEV), +10 × EPSS (probabilité d'exploitation).
double cveRisk(RemediationCve c) =>
    switch (severityRank(c.severity)) {
      4 => 10.0,
      3 => 5.0,
      2 => 2.0,
      1 => 1.0,
      _ => 0.0,
    } +
    (c.inKev ? 20.0 : 0.0) +
    10.0 * c.epss;

/// Comparaison de versions « au mieux » : segments numériques comparés comme
/// des entiers, les autres lexicographiquement ; une époque `1:` et un suffixe
/// de distribution (`-3.el9`) sont ignorés. Suffisante pour classer des
/// correctifs, pas pour remplacer le gestionnaire de paquets.
int compareVersions(String a, String b) {
  List<String> parts(String v) {
    var s = v.trim();
    final colon = s.indexOf(':');
    if (colon > 0 && int.tryParse(s.substring(0, colon)) != null) {
      s = s.substring(colon + 1);
    }
    final dash = s.indexOf('-');
    if (dash > 0) s = s.substring(0, dash);
    return RegExp(
      r'\d+|[A-Za-z]+',
    ).allMatches(s).map((m) => m.group(0)!).toList();
  }

  final pa = parts(a), pb = parts(b);
  for (var i = 0; i < pa.length || i < pb.length; i++) {
    if (i >= pa.length) return -1;
    if (i >= pb.length) return 1;
    final na = int.tryParse(pa[i]), nb = int.tryParse(pb[i]);
    final c = (na != null && nb != null)
        ? na.compareTo(nb)
        : pa[i].compareTo(pb[i]);
    if (c != 0) return c;
  }
  return 0;
}

/// États de correctif des scanners qui ne sont pas des versions.
const _notAVersion = {
  '',
  'unknown',
  'not-fixed',
  'not fixed',
  'wont-fix',
  "won't fix",
  'no fix',
  'none',
  'n/a',
  '-',
};

/// Versions corrigées contenues dans un champ « version corrigée » de
/// scanner (une version, une liste `a, b`, ou un état comme `not-fixed`).
List<String> fixedVersionsOf(String raw) {
  final out = <String>[];
  for (final p in raw.split(RegExp(r'[,;]'))) {
    final v = p.trim();
    if (_notAVersion.contains(v.toLowerCase())) continue;
    if (!RegExp(r'\d').hasMatch(v)) continue;
    out.add(v);
  }
  return out;
}

/// Entrée minimale d'un scanner pour la remédiation (évite de dépendre des
/// modèles de widget).
typedef RemediationInput = ({
  String scanner,
  String id,
  String severity,
  String packageName,
  String installedVersion,
  String fixedVersion,
});

/// Regroupe les CVE par paquet installé et calcule, pour chacun, la version
/// minimale qui les corrige toutes, triées par gain de risque décroissant.
///
/// Pour une CVE, on retient parmi ses versions corrigées la plus petite qui
/// dépasse la version installée (sinon la plus petite) ; le paquet doit être
/// porté à la plus grande de ces versions.
List<RemediationItem> buildRemediation(
  Iterable<RemediationInput> rows, {
  Map<String, ExploitInfo> exploitById = const {},
}) {
  // (paquet, version installée) → id normalisé → agrégat
  final byPkg = <String, Map<String, _CveAgg>>{};
  final names = <String, (String, String)>{};
  for (final r in rows) {
    final key = '${r.packageName}\u0000${r.installedVersion}';
    names[key] = (r.packageName, r.installedVersion);
    final id = normalizeCveId(r.id);
    final agg = (byPkg[key] ??= {})[id] ??= _CveAgg(id);
    agg.add(r.scanner, r.severity, fixedVersionsOf(r.fixedVersion));
  }

  final items = <RemediationItem>[];
  for (final e in byPkg.entries) {
    final (name, installed) = names[e.key]!;
    final fixed = <RemediationCve>[];
    final unfixed = <RemediationCve>[];
    String? target;
    for (final agg in e.value.values) {
      final ex = exploitById[agg.id];
      final cve = RemediationCve(
        id: agg.id,
        severity: agg.worstSeverity,
        fixedVersions: agg.fixed.toList(),
        inKev: ex?.inKev ?? false,
        epss: ex?.epssScore ?? 0,
        scanners: agg.scanners,
      );
      if (!cve.hasFix) {
        unfixed.add(cve);
        continue;
      }
      fixed.add(cve);
      final need = _minimalFix(cve.fixedVersions, installed);
      if (target == null || compareVersions(need, target) > 0) target = need;
    }
    int byRisk(RemediationCve a, RemediationCve b) =>
        cveRisk(b).compareTo(cveRisk(a));
    fixed.sort(byRisk);
    unfixed.sort(byRisk);
    items.add(
      RemediationItem(
        packageName: name,
        installedVersion: installed,
        targetVersion: target,
        fixed: fixed,
        unfixed: unfixed,
      ),
    );
  }
  items.sort((a, b) {
    final g = b.gain.compareTo(a.gain);
    if (g != 0) return g;
    final r = b.remaining.compareTo(a.remaining);
    return r != 0 ? r : a.packageName.compareTo(b.packageName);
  });
  return items;
}

String _minimalFix(List<String> candidates, String installed) {
  final sorted = [...candidates]..sort(compareVersions);
  for (final v in sorted) {
    if (compareVersions(v, installed) > 0) return v;
  }
  return sorted.first;
}

class _CveAgg {
  final String id;
  final scanners = <String>{};
  final fixed = <String>{};
  String worstSeverity = 'unknown';
  _CveAgg(this.id);

  void add(String scanner, String severity, List<String> fixes) {
    scanners.add(scanner);
    fixed.addAll(fixes);
    if (severityRank(severity) > severityRank(worstSeverity)) {
      worstSeverity = severity.toLowerCase();
    }
  }
}
