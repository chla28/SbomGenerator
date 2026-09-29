import 'dart:convert';

/// Catégorie de licence, telle que classée par le CLI
/// (`sbom_generator licenses --format json`).
enum LicenseCategory {
  permissive,
  weakCopyleft,
  strongCopyleft,
  unknown;

  static LicenseCategory fromCli(String? s) => switch (s) {
    'strong-copyleft' => strongCopyleft,
    'weak-copyleft' => weakCopyleft,
    'permissive' => permissive,
    _ => unknown,
  };
}

class LicensePackage {
  final String name;
  final String version;
  final String purl;
  const LicensePackage(this.name, this.version, this.purl);

  String get label => version.isEmpty ? name : '$name $version';
}

class LicenseGroup {
  /// Expression de licence ; vide pour les paquets sans licence détectée.
  final String license;
  final LicenseCategory category;
  final List<LicensePackage> packages;
  const LicenseGroup(this.license, this.category, this.packages);
}

/// Licences d'un SBOM, lues depuis la sortie JSON du CLI. La GUI ne
/// classifie rien elle-même : catégories et regroupements viennent du CLI.
class LicenseReportData {
  final String name;
  final int totalPackages;
  final int strongCopyleftPackages;
  final int weakCopyleftPackages;

  /// Groupes triés par licence, suivis du groupe « sans licence » (s'il existe).
  final List<LicenseGroup> groups;

  const LicenseReportData({
    required this.name,
    required this.totalPackages,
    required this.strongCopyleftPackages,
    required this.weakCopyleftPackages,
    required this.groups,
  });

  int get distinctLicenses =>
      groups.where((g) => g.category != LicenseCategory.unknown).length;

  int get unknownPackages => groups
      .where((g) => g.category == LicenseCategory.unknown)
      .fold(0, (n, g) => n + g.packages.length);

  static LicenseReportData? tryParse(String raw) {
    try {
      return parse(raw);
    } catch (_) {
      return null;
    }
  }

  static LicenseReportData parse(String raw) {
    final j = jsonDecode(raw) as Map<String, dynamic>;
    final summary = j['summary'] as Map<String, dynamic>;

    List<LicensePackage> pkgs(Object? l) => [
      for (final p in (l as List? ?? const []))
        LicensePackage(
          (p['name'] ?? '') as String,
          (p['version'] ?? '') as String,
          (p['purl'] ?? '') as String,
        ),
    ];

    final groups = <LicenseGroup>[
      for (final g in (j['licenses'] as List? ?? const []))
        LicenseGroup(
          g['license'] as String,
          LicenseCategory.fromCli(g['category'] as String?),
          pkgs(g['packages']),
        ),
    ];
    final unknown = pkgs(j['unknown']);
    if (unknown.isNotEmpty) {
      groups.add(LicenseGroup('', LicenseCategory.unknown, unknown));
    }

    return LicenseReportData(
      name: (j['name'] ?? '') as String,
      totalPackages: summary['packages'] as int,
      strongCopyleftPackages: summary['strongCopyleftPackages'] as int,
      weakCopyleftPackages: summary['weakCopyleftPackages'] as int,
      groups: groups,
    );
  }

  /// Groupes filtrés par [query] (insensible à la casse) : un groupe est
  /// conservé si sa licence correspond (tous ses paquets) ou, sinon,
  /// réduit aux paquets dont le nom correspond.
  List<LicenseGroup> filter(String query) {
    final q = query.trim().toLowerCase();
    if (q.isEmpty) return groups;
    final out = <LicenseGroup>[];
    for (final g in groups) {
      if (g.license.toLowerCase().contains(q)) {
        out.add(g);
        continue;
      }
      final hit = g.packages
          .where((p) => p.label.toLowerCase().contains(q))
          .toList();
      if (hit.isNotEmpty) out.add(LicenseGroup(g.license, g.category, hit));
    }
    return out;
  }
}
