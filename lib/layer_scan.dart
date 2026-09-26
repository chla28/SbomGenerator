/// Analyse de vulnérabilités par couche d'image (`scan --per-layer`).
///
/// S'appuie sur un jeu de SBOM produit par `--per-layer` : le SBOM global,
/// dont chaque composant porte sa couche d'origine
/// (`sbom_generator:layer:index`), et un SBOM par couche
/// (`<base>.layer-NN-<digest12><ext>`, delta de la couche). Deux méthodes
/// (`--layer-scan`) :
///
/// * `attribute` — un seul scan du SBOM global ; chaque vulnérabilité est
///   rattachée à la couche d'origine de son paquet ([LayeredSbomSet.layerOf]).
///   Ne montre que les CVE présentes dans l'image finale.
/// * `each` — le SBOM de chaque couche est scanné séparément ; une CVE est
///   attribuée à chaque couche qui apporte le paquet vulnérable, y compris
///   une version remplacée plus haut dans la pile (mode `rootfs`).
library;

import 'dart:convert';
import 'dart:io';

/// Méthodes acceptées par `scan --layer-scan`.
const validLayerScanModes = {'attribute', 'each'};

const _prefix = 'sbom_generator:layer:';
final _layerFileRe = RegExp(r'^(.+)\.layer-(\d+)-([0-9a-f]{6,64})(\..+)?$');
const _sbomExtensions = ['.cdx.json', '.spdx.json', '.spdx3.jsonld'];

/// Une couche d'un jeu de SBOM par couche.
class LayerRef {
  const LayerRef({
    required this.index,
    required this.digest,
    this.createdBy,
    this.path,
  });

  final int index;

  /// Digest complet (`sha256:…`) si connu, sinon les 12 premiers caractères
  /// lus dans le nom de fichier.
  final String digest;
  final String? createdBy;

  /// SBOM de la couche (même format que le global), s'il existe sur disque.
  final String? path;

  String get shortDigest {
    final hex = digest.contains(':') ? digest.split(':').last : digest;
    return hex.length > 12 ? hex.substring(0, 12) : hex;
  }

  String get label => 'couche $index ($shortDigest)';
}

/// SBOM global et SBOM de couche relus depuis le disque.
class LayeredSbomSet {
  LayeredSbomSet({
    required this.globalPath,
    required this.layers,
    required this.layerByPackage,
    this.mode,
  });

  final String globalPath;
  final List<LayerRef> layers;

  /// `nom@version` → index de la couche d'origine (composants du global).
  final Map<String, int> layerByPackage;

  /// Méthode de calcul des couches (`metadata` / `rootfs`), si indiquée.
  final String? mode;

  late final Map<String, List<int>> _byName = () {
    final m = <String, List<int>>{};
    layerByPackage.forEach((k, v) {
      final at = k.lastIndexOf('@');
      final name = at > 0 ? k.substring(0, at) : k;
      (m[name] ??= []).add(v);
    });
    return m;
  }();

  /// Couche d'origine du paquet `nom@version` : correspondance exacte, puis
  /// par nom seul quand toutes les versions de ce nom viennent de la même
  /// couche (les scanners normalisent parfois la version — époque RPM…).
  int? layerOf(String packageAtVersion) {
    final exact = layerByPackage[packageAtVersion];
    if (exact != null) return exact;
    final at = packageAtVersion.lastIndexOf('@');
    final name = at > 0 ? packageAtVersion.substring(0, at) : packageAtVersion;
    final candidates = _byName[name]?.toSet();
    return candidates != null && candidates.length == 1 ? candidates.first : null;
  }

  LayerRef? layer(int index) {
    for (final l in layers) {
      if (l.index == index) return l;
    }
    return null;
  }

  /// Relit le jeu dont [globalPath] est le SBOM global (CycloneDX, SPDX 2.3
  /// ou SPDX 3.0 produit avec `--per-layer`). `null` si le fichier ne porte
  /// aucune information de couche.
  static LayeredSbomSet? load(String globalPath) {
    final Object? json;
    try {
      json = jsonDecode(File(globalPath).readAsStringSync());
    } on FormatException {
      return null;
    }
    if (json is! Map<String, dynamic>) return null;

    final byPkg = <String, int>{};
    void take(String? name, String? version, Map<String, String> fields) {
      final i = int.tryParse(fields['index'] ?? '');
      if (name == null || name.isEmpty || i == null) return;
      byPkg['$name@${version ?? ''}'] = i;
    }

    final summaries = <int, Map<String, dynamic>>{};
    String? mode;
    if (json['bomFormat'] == 'CycloneDX') {
      for (final c in json['components'] as List? ?? const []) {
        if (c is Map) {
          take(c['name'] as String?, c['version'] as String?, _fields(c));
        }
      }
      final root = (json['metadata'] as Map?)?['component'] as Map?;
      for (final p in root?['properties'] as List? ?? const []) {
        if (p is! Map) continue;
        final name = p['name'] as String? ?? '';
        if (name == 'sbom_generator:layers:mode') mode = p['value'] as String?;
        if (!name.startsWith('sbom_generator:layers:')) continue;
        try {
          final s = jsonDecode(p['value'] as String? ?? '');
          if (s is Map<String, dynamic> && s['index'] is int) {
            summaries[s['index'] as int] = s;
          }
        } on FormatException {
          continue;
        }
      }
    } else if (json.containsKey('spdxVersion')) {
      for (final p in json['packages'] as List? ?? const []) {
        if (p is Map) {
          take(p['name'] as String?, p['versionInfo'] as String?, _fields(p));
        }
      }
    } else if (json['@graph'] is List) {
      for (final e in json['@graph'] as List) {
        if (e is Map && e['type'] == 'software:Package') {
          take(e['name'] as String?, e['software:packageVersion'] as String?,
              _fields(e));
        }
      }
    }

    final files = layerFilesOf(globalPath);
    if (byPkg.isEmpty && files.isEmpty) return null;
    final indexes = {...summaries.keys, ...files.keys}.toList()..sort();
    return LayeredSbomSet(
      globalPath: globalPath,
      mode: mode,
      layerByPackage: byPkg,
      layers: [
        for (final i in indexes)
          LayerRef(
            index: i,
            digest: summaries[i]?['digest'] as String? ??
                files[i]?.shortDigest ??
                '?',
            createdBy: summaries[i]?['createdBy'] as String?,
            path: files[i]?.path,
          ),
      ],
    );
  }
}

/// Champs `sbom_generator:layer:*` d'un composant : propriétés CycloneDX,
/// `annotations[].comment` (SPDX 2.3) ou `annotation[].statement` (SPDX 3.0).
Map<String, String> _fields(Map component) {
  final out = <String, String>{};
  for (final p in component['properties'] as List? ?? const []) {
    if (p is Map && (p['name'] as String? ?? '').startsWith(_prefix)) {
      out[(p['name'] as String).substring(_prefix.length)] = '${p['value']}';
    }
  }
  final re = RegExp('${RegExp.escape(_prefix)}(\\w+)=([^;]*)');
  for (final list in [component['annotations'], component['annotation']]) {
    for (final a in list as List? ?? const []) {
      if (a is! Map) continue;
      final text = (a['comment'] ?? a['statement']) as String? ?? '';
      for (final m in re.allMatches(text)) {
        out[m.group(1)!] = m.group(2)!.trim();
      }
    }
  }
  return out;
}

/// SBOM de couche du même jeu que [globalPath] (même base, même extension),
/// par index de couche.
Map<int, ({String path, String shortDigest})> layerFilesOf(String globalPath) {
  final slash = globalPath.lastIndexOf('/');
  final dir = slash < 0 ? '.' : globalPath.substring(0, slash);
  final name = globalPath.substring(slash + 1);
  final ext = _sbomExtensions.firstWhere(name.endsWith, orElse: () => '');
  final base = name.substring(0, name.length - ext.length);
  final out = <int, ({String path, String shortDigest})>{};
  final List<FileSystemEntity> entries;
  try {
    entries = Directory(dir).listSync(followLinks: false);
  } on FileSystemException {
    return out;
  }
  for (final e in entries) {
    if (e is! File) continue;
    final f = e.path.split('/').last;
    final m = _layerFileRe.firstMatch(f);
    if (m == null || m.group(1) != base) continue;
    final lext = m.group(4) ?? '';
    // Global sans extension (sortie à format unique) : couches CycloneDX.
    if (ext.isEmpty ? lext != '.cdx.json' : lext != ext) continue;
    out[int.parse(m.group(2)!)] =
        (path: '$dir/$f', shortDigest: m.group(3)!);
  }
  return out;
}

/// Rattache chaque vulnérabilité de [vulns] (clé `package` = `nom@version`)
/// à la couche d'origine de son paquet : clé `layer` (index), absente si la
/// couche est inconnue. Renvoie le nombre de vulnérabilités non rattachées.
int attributeLayers(List<Map<String, dynamic>> vulns, LayeredSbomSet set) {
  var unknown = 0;
  for (final v in vulns) {
    final i = set.layerOf((v['package'] as String?) ?? '');
    if (i == null) {
      unknown++;
    } else {
      v['layer'] = i;
    }
  }
  return unknown;
}

// ── Synthèse par couche ───────────────────────────────────────────────────

final _distroCveRe = RegExp(r'^[A-Z]+-(CVE-\d{4}-\d+)$');
String _normId(String id) => _distroCveRe.firstMatch(id)?.group(1) ?? id;

int _sevOrd(String s) => switch (s.toLowerCase()) {
      'critical' => 0,
      'high' => 1,
      'medium' => 2,
      'low' => 3,
      _ => 4,
    };

/// CVE d'une couche, dédupliquées entre scanners.
class LayerCveSummary {
  LayerCveSummary(this.layer, this.worstById);

  final LayerRef layer;

  /// Identifiant normalisé → pire sévérité rapportée par un scanner.
  final Map<String, String> worstById;

  int get total => worstById.length;

  int count(String severity) => worstById.values
      .where((s) => s.toLowerCase() == severity.toLowerCase())
      .length;
}

/// Une synthèse par couche de [layers] (dans l'ordre), à partir de la clé
/// `layer` des résultats de chaque scanner.
List<LayerCveSummary> summarizeByLayer(
  Map<String, List<Map<String, dynamic>>?> resultsByScanner,
  List<LayerRef> layers,
) {
  final byLayer = <int, Map<String, String>>{};
  for (final vulns in resultsByScanner.values) {
    for (final v in vulns ?? const <Map<String, dynamic>>[]) {
      final i = v['layer'];
      final id = _normId((v['id'] as String?) ?? '');
      if (i is! int || id.isEmpty) continue;
      final sev = (v['severity'] as String?) ?? '';
      final m = byLayer[i] ??= {};
      final prev = m[id];
      if (prev == null || _sevOrd(sev) < _sevOrd(prev)) m[id] = sev;
    }
  }
  return [
    for (final l in layers) LayerCveSummary(l, byLayer[l.index] ?? const {}),
  ];
}
