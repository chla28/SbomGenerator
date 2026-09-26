import 'dart:convert';
import 'dart:io';

// Navigation entre le SBOM global d'une image et ses SBOM de couche
// (`sbom-generator --per-layer`). Les fichiers sont reliés par leur nom :
// global `<base><ext>`, couches `<base>.layer-NN-<digest12><ext>` dans le
// même répertoire ; le contenu (propriétés `sbom_generator:layer:*` en
// CycloneDX, annotations en SPDX) ne sert qu'à enrichir l'affichage.

final _layerFileRe = RegExp(r'^(.+)\.layer-(\d+)-([0-9a-f]{6,64})(\..+)?$');

/// Extensions des SBOM que la GUI sait ouvrir, par ordre de préférence.
const _sbomExtensions = ['.cdx.json', '.spdx.json', '.spdx3.jsonld'];

/// `true` si [path] est un SBOM de couche produit par `--per-layer`.
bool isLayerSbomFile(String path) =>
    _layerFileRe.hasMatch(path.split('/').last);

/// Un SBOM de couche trouvé sur disque.
class LayerFile {
  final int index;
  final String shortDigest;
  final String path;

  const LayerFile({
    required this.index,
    required this.shortDigest,
    required this.path,
  });
}

/// SBOM global et SBOM de couche apparentés à un fichier ouvert.
class LayerNav {
  /// SBOM global, s'il existe.
  final String? globalPath;
  final List<LayerFile> layers;

  /// Couche du fichier ouvert (`null` : c'est le SBOM global).
  final int? currentIndex;

  const LayerNav({
    required this.globalPath,
    required this.layers,
    required this.currentIndex,
  });

  bool get isLayer => currentIndex != null;

  /// Cherche, dans le répertoire de [path], le SBOM global et les SBOM de
  /// couche du même jeu. `null` si le fichier n'appartient à aucun jeu.
  static LayerNav? discover(String path) {
    final slash = path.lastIndexOf('/');
    final dir = slash < 0 ? '.' : path.substring(0, slash);
    final name = path.substring(slash + 1);

    String base;
    String ext;
    int? current;
    final m = _layerFileRe.firstMatch(name);
    if (m != null) {
      base = m.group(1)!;
      ext = m.group(4) ?? '';
      current = int.parse(m.group(2)!);
    } else {
      ext = _sbomExtensions.firstWhere(name.endsWith, orElse: () => '');
      base = name.substring(0, name.length - ext.length);
    }

    final List<FileSystemEntity> entries;
    try {
      entries = Directory(dir).listSync(followLinks: false);
    } on FileSystemException {
      return null;
    }

    // Couches du même jeu. Un global sans extension (sortie à format unique
    // nommée sans suffixe) accepte les couches de n'importe quel format
    // lisible, la première extension préférée l'emportant.
    final byIndex = <int, LayerFile>{};
    final rank = <int, int>{};
    for (final e in entries) {
      if (e is! File) continue;
      final f = e.path.split('/').last;
      final lm = _layerFileRe.firstMatch(f);
      if (lm == null || lm.group(1) != base) continue;
      final lext = lm.group(4) ?? '';
      final int r;
      if (ext.isNotEmpty) {
        if (lext != ext) continue;
        r = 0;
      } else {
        r = _sbomExtensions.indexOf(lext);
        if (r < 0) continue;
      }
      final idx = int.parse(lm.group(2)!);
      if (rank[idx] == null || r < rank[idx]!) {
        rank[idx] = r;
        byIndex[idx] = LayerFile(
            index: idx, shortDigest: lm.group(3)!, path: '$dir/$f');
      }
    }
    if (byIndex.isEmpty) return null;

    String? global;
    if (current == null) {
      global = path;
    } else {
      for (final candidate in [
        '$dir/$base$ext',
        for (final x in _sbomExtensions) '$dir/$base$x',
        '$dir/$base',
      ]) {
        if (File(candidate).existsSync()) {
          global = candidate;
          break;
        }
      }
    }

    final layers = byIndex.values.toList()
      ..sort((a, b) => a.index.compareTo(b.index));
    return LayerNav(globalPath: global, layers: layers, currentIndex: current);
  }
}

/// Informations de couche lues dans le contenu d'un SBOM.
class LayerDocInfo {
  /// Lignes descriptives (couche décrite, ou résumé des couches).
  final List<String> lines;

  /// Résumé de chaque couche (SBOM global CycloneDX), par index : instruction
  /// de build et compteurs, pour libeller le sélecteur de couche.
  final Map<int, String> layerLabels;

  /// Composants supprimés par la couche (SBOM de couche).
  final List<String> removed;

  const LayerDocInfo({
    this.lines = const [],
    this.layerLabels = const {},
    this.removed = const [],
  });

  bool get isEmpty => lines.isEmpty && layerLabels.isEmpty && removed.isEmpty;

  static const empty = LayerDocInfo();

  static LayerDocInfo fromSbom(Map<String, dynamic> json) {
    if (json['bomFormat'] == 'CycloneDX') return _fromCdx(json);
    // SPDX 2.3 / 3.0 : description en commentaire du document.
    String? comment;
    if (json.containsKey('spdxVersion')) {
      comment = json['comment'] as String?;
    } else if (json['@graph'] is List) {
      for (final e in json['@graph'] as List) {
        if (e is Map && e['type'] == 'SpdxDocument') {
          comment = e['comment'] as String?;
        }
      }
    }
    if (comment == null || !comment.contains('couche')) return empty;
    return LayerDocInfo(
        lines: comment.split('\n').where((l) => l.isNotEmpty).toList());
  }

  static LayerDocInfo _fromCdx(Map<String, dynamic> json) {
    final root = (json['metadata'] as Map?)?['component'] as Map?;
    if (root == null) return empty;
    final props = <String, List<String>>{};
    for (final p in root['properties'] as List? ?? const []) {
      if (p is! Map) continue;
      final name = p['name'] as String? ?? '';
      if (!name.startsWith('sbom_generator:layer')) continue;
      (props[name] ??= []).add(p['value']?.toString() ?? '');
    }
    if (props.isEmpty) return empty;

    String? one(String k) => props['sbom_generator:layer:$k']?.first;
    final index = one('index');
    if (index != null) {
      final desc = root['description'] as String?;
      return LayerDocInfo(
        lines: [
          'Couche $index/${one('total') ?? '?'} — mode ${one('mode') ?? '?'}',
          if (one('digest') != null) 'Digest : ${one('digest')}',
          if (desc != null && desc.isNotEmpty) 'Instruction : $desc',
          'Ajoutés : ${one('added') ?? '0'} — modifiés : '
              '${one('modified') ?? '0'} — supprimés : '
              '${one('removedCount') ?? '0'}',
        ],
        removed: props['sbom_generator:layer:removed'] ?? const [],
      );
    }

    final labels = <int, String>{};
    for (final e in props.entries) {
      if (!e.key.startsWith('sbom_generator:layers:')) continue;
      try {
        final s = jsonDecode(e.value.first);
        if (s is! Map || s['index'] is! int) continue;
        final by = (s['createdBy'] as String?)?.trim() ?? '';
        labels[s['index'] as int] = '+${s['added']} ~${s['modified']} '
            '-${s['removed']}${by.isEmpty ? '' : ' — $by'}';
      } on FormatException {
        continue;
      }
    }
    final mode = props['sbom_generator:layers:mode']?.first;
    return LayerDocInfo(
      lines: [
        '${labels.length} couche(s) analysée(s)'
            '${mode != null ? ' — mode $mode' : ''}',
      ],
      layerLabels: labels,
    );
  }
}

/// Libellés des couches (voir [LayerDocInfo.layerLabels]) relus dans le SBOM
/// global [globalPath] — vide s'il est absent ou illisible.
Future<Map<int, String>> readLayerLabels(String? globalPath) async {
  if (globalPath == null) return const {};
  try {
    final json = jsonDecode(await File(globalPath).readAsString());
    if (json is Map<String, dynamic>) {
      return LayerDocInfo.fromSbom(json).layerLabels;
    }
  } catch (_) {
    // Global illisible : sélecteur sans instruction de build.
  }
  return const {};
}

/// Champs de couche d'un composant (clé sans préfixe → valeur) : `index`,
/// `digest`, `modifiedBy` (SBOM global) ou `change`, `previousVersion` (SBOM
/// de couche). Lus dans les propriétés CycloneDX, l'annotation SPDX 2.3
/// (`annotations[].comment`) ou SPDX 3.0 (`annotation[].statement`).
Map<String, String> layerFieldsOf(Map<String, dynamic> component) {
  const prefix = 'sbom_generator:layer:';
  final out = <String, String>{};
  for (final p in component['properties'] as List? ?? const []) {
    if (p is Map && (p['name'] as String? ?? '').startsWith(prefix)) {
      out[(p['name'] as String).substring(prefix.length)] =
          p['value']?.toString() ?? '';
    }
  }
  final texts = [
    for (final a in component['annotations'] as List? ?? const [])
      if (a is Map) a['comment'],
    for (final a in component['annotation'] as List? ?? const [])
      if (a is Map) a['statement'],
  ];
  final re = RegExp('${RegExp.escape(prefix)}(\\w+)=([^;]*)');
  for (final t in texts.whereType<String>()) {
    for (final m in re.allMatches(t)) {
      out[m.group(1)!] = m.group(2)!.trim();
    }
  }
  return out;
}

/// Libellé court d'un composant vis-à-vis des couches (colonne « Couche » ou
/// « Changement »), vide si le SBOM n'en porte pas.
String layerColumnLabel(Map<String, String> f) {
  final change = f['change'];
  if (change != null) {
    if (change == 'added') return 'ajouté';
    final prev = f['previousVersion'];
    return prev != null ? 'modifié (était $prev)' : 'modifié';
  }
  final index = f['index'];
  if (index == null) return '';
  final by = f['modifiedBy'];
  return by == null || by.isEmpty
      ? 'couche $index'
      : 'couche $index (modifié : $by)';
}

/// Clé de regroupement par couche (tri naturel des index).
String layerGroupKey(Map<String, String> f) {
  final change = f['change'];
  if (change != null) return change == 'added' ? 'Ajoutés' : 'Modifiés';
  final index = int.tryParse(f['index'] ?? '');
  return index == null
      ? '(couche inconnue)'
      : 'Couche ${index.toString().padLeft(2, '0')}';
}
