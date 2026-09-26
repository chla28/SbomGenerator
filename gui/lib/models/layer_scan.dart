import 'dart:convert';

import 'layer_nav.dart';

// Analyse de vulnérabilités par couche d'image (onglets Grype, OSV-Scanner,
// Trivy, source « Image de conteneur »). Le jeu de SBOM par couche est
// produit par `sbom-generator --image … --per-layer` (voir
// LayeredSbomService) ; deux méthodes :
//
// * rattachement — un seul scan de l'image, chaque vulnérabilité rattachée à
//   la couche d'origine de son paquet (lue dans le SBOM global) ; ne montre
//   que les CVE de l'image finale ;
// * chaque couche — le SBOM de chaque couche est scanné séparément ; une CVE
//   est attribuée à chaque couche qui apporte le paquet vulnérable, y compris
//   une version remplacée plus haut dans la pile.

/// Méthode d'analyse par couche.
enum LayerScanMode { attribute, each }

/// Réglages de l'analyse par couche d'un onglet de scan.
class LayerScanSettings {
  final bool enabled;
  final LayerScanMode mode;

  /// Calcul des couches transmis à `--layer-mode` : `metadata` ou `rootfs`.
  final String layerMode;

  const LayerScanSettings({
    this.enabled = false,
    this.mode = LayerScanMode.attribute,
    this.layerMode = 'metadata',
  });

  LayerScanSettings copyWith(
          {bool? enabled, LayerScanMode? mode, String? layerMode}) =>
      LayerScanSettings(
        enabled: enabled ?? this.enabled,
        mode: mode ?? this.mode,
        layerMode: layerMode ?? this.layerMode,
      );
}

/// Une couche d'image.
class LayerInfo {
  final int index;

  /// Digest complet (`sha256:…`) si connu, sinon les 12 premiers caractères
  /// lus dans le nom du fichier de couche.
  final String digest;
  final String? createdBy;

  /// SBOM de la couche (CycloneDX), s'il existe.
  final String? path;

  const LayerInfo({
    required this.index,
    required this.digest,
    this.createdBy,
    this.path,
  });

  String get shortDigest {
    final hex = digest.contains(':') ? digest.split(':').last : digest;
    return hex.length > 12 ? hex.substring(0, 12) : hex;
  }
}

/// Jeu de SBOM par couche : SBOM global + un SBOM par couche.
class LayeredSbomSet {
  final String globalPath;
  final List<LayerInfo> layers;

  /// `nom@version` → couche d'origine (composants du SBOM global).
  final Map<String, int> layerByPackage;

  LayeredSbomSet({
    required this.globalPath,
    required this.layers,
    required this.layerByPackage,
  });

  late final Map<String, Set<int>> _byName = () {
    final m = <String, Set<int>>{};
    layerByPackage.forEach((k, v) {
      final at = k.lastIndexOf('@');
      (m[at > 0 ? k.substring(0, at) : k] ??= {}).add(v);
    });
    return m;
  }();

  /// Couche d'origine du paquet [name]@[version] : correspondance exacte,
  /// puis par nom seul quand toutes ses versions viennent de la même couche.
  int? layerOf(String name, String version) {
    final exact = layerByPackage['$name@$version'];
    if (exact != null) return exact;
    final c = _byName[name];
    return c != null && c.length == 1 ? c.first : null;
  }

  /// Couche d'un digest complet (`sha256:…`), ex. `Layer.DiffID` de trivy.
  int? layerOfDigest(String digest) {
    for (final l in layers) {
      if (l.digest == digest) return l.index;
    }
    final short = digest.contains(':') ? digest.split(':').last : digest;
    for (final l in layers) {
      if (short.startsWith(l.shortDigest)) return l.index;
    }
    return null;
  }

  /// Construit le jeu depuis le SBOM global CycloneDX ([globalJson], chemin
  /// [globalPath]) ; les SBOM de couche sont retrouvés par leur nom.
  static LayeredSbomSet parse(String globalPath, Map<String, dynamic> globalJson) {
    final byPkg = <String, int>{};
    for (final c in globalJson['components'] as List? ?? const []) {
      if (c is! Map<String, dynamic>) continue;
      final i = int.tryParse(layerFieldsOf(c)['index'] ?? '');
      final name = c['name'] as String? ?? '';
      if (i != null && name.isNotEmpty) {
        byPkg['$name@${c['version'] ?? ''}'] = i;
      }
    }
    final summaries = <int, Map>{};
    final root = (globalJson['metadata'] as Map?)?['component'] as Map?;
    for (final p in root?['properties'] as List? ?? const []) {
      if (p is! Map ||
          !(p['name'] as String? ?? '').startsWith('sbom_generator:layers:')) {
        continue;
      }
      try {
        final s = jsonDecode(p['value'] as String? ?? '');
        if (s is Map && s['index'] is int) summaries[s['index'] as int] = s;
      } on FormatException {
        continue;
      }
    }
    final files = {
      for (final f in LayerNav.discover(globalPath)?.layers ?? const <LayerFile>[])
        f.index: f,
    };
    final indexes = {...summaries.keys, ...files.keys}.toList()..sort();
    return LayeredSbomSet(
      globalPath: globalPath,
      layerByPackage: byPkg,
      layers: [
        for (final i in indexes)
          LayerInfo(
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

/// Clé d'une vulnérabilité (identifiant, paquet, version) — commune aux
/// lignes affichées et aux lignes dédupliquées (voir `dedupeVulns`).
String vulnLayerKey(String id, String packageName, String version) =>
    '$id\u0000$packageName\u0000$version';

/// Résultat d'une analyse par couche : couches de l'image et couches de
/// chaque vulnérabilité (par [vulnLayerKey]).
class LayerScanResult {
  final LayerScanMode mode;
  final List<LayerInfo> layers;
  final Map<String, Set<int>> layersByKey;

  /// Vulnérabilités sans couche connue (mode rattachement : paquet absent
  /// du SBOM global).
  final int unattributed;

  const LayerScanResult({
    required this.mode,
    required this.layers,
    required this.layersByKey,
    this.unattributed = 0,
  });

  List<int> layersOf(String id, String packageName, String version) =>
      (layersByKey[vulnLayerKey(id, packageName, version)]?.toList() ??
          <int>[])
        ..sort();

  /// Libellé de colonne : `2`, `1, 3`, ou `?`.
  String label(String id, String packageName, String version) {
    final l = layersOf(id, packageName, version);
    return l.isEmpty ? '?' : l.join(', ');
  }

  LayerInfo? layer(int index) {
    for (final l in layers) {
      if (l.index == index) return l;
    }
    return null;
  }

  String get modeLabel => mode == LayerScanMode.each
      ? 'SBOM de chaque couche scanné'
      : 'rattachement à la couche d\'origine du paquet';
}

// ── Fusion des sorties JSON (mode « chaque couche ») ────────────────────────
//
// Un scan par couche produit une sortie par couche ; on les fusionne en un
// seul document au format natif de l'outil, pour que les parseurs, la vue
// JSON et l'enrichissement existants s'appliquent sans changement.

Map<String, dynamic> _decode(String raw) {
  final v = jsonDecode(raw);
  return v is Map<String, dynamic> ? v : <String, dynamic>{};
}

/// Fusionne des sorties `grype -o json` (tableaux `matches`).
String mergeGrypeJson(List<String> outputs) {
  final docs = [for (final o in outputs) _decode(o)];
  return jsonEncode({
    ...docs.isEmpty ? const <String, dynamic>{} : docs.first,
    'matches': [for (final d in docs) ...d['matches'] as List? ?? const []],
  });
}

/// Fusionne des sorties `osv-scanner --format json` (tableaux `results`).
String mergeOsvJson(List<String> outputs) {
  final docs = [for (final o in outputs) _decode(o)];
  return jsonEncode({
    ...docs.isEmpty ? const <String, dynamic>{} : docs.first,
    'results': [for (final d in docs) ...d['results'] as List? ?? const []],
  });
}

/// Fusionne des sorties `trivy … --format json` (tableaux `Results`).
String mergeTrivyJson(List<String> outputs) {
  final docs = [for (final o in outputs) _decode(o)];
  return jsonEncode({
    ...docs.isEmpty ? const <String, dynamic>{} : docs.first,
    'Results': [for (final d in docs) ...d['Results'] as List? ?? const []],
  });
}

/// Couche native de chaque vulnérabilité d'une sortie `trivy image` :
/// [vulnLayerKey] → `Layer.DiffID`.
Map<String, String> trivyLayerDigests(String raw) {
  final out = <String, String>{};
  for (final r in _decode(raw)['Results'] as List? ?? const []) {
    for (final v in (r as Map)['Vulnerabilities'] as List? ?? const []) {
      final m = v as Map;
      final d = (m['Layer'] as Map?)?['DiffID'] as String?;
      if (d == null || d.isEmpty) continue;
      out[vulnLayerKey('${m['VulnerabilityID'] ?? ''}', '${m['PkgName'] ?? ''}',
          '${m['InstalledVersion'] ?? ''}')] = d;
    }
  }
  return out;
}

/// Couche native de chaque vulnérabilité d'une sortie `osv-scanner scan
/// image` : [vulnLayerKey] → `diff_id`. osv-scanner rattache chaque paquet à
/// une entrée de `image_metadata.layer_metadata` (historique de l'image,
/// instructions sans couche comprises) via `image_origin_details.index`. La
/// clé reprend l'identifiant affiché par l'onglet (alias CVE, sinon id OSV)
/// et le nom de paquet rapporté (paquet *source*, ex. `expat` pour
/// `libexpat`, que le SBOM de l'image ne contient pas toujours).
Map<String, String> osvLayerDigests(String raw) {
  final data = _decode(raw);
  final meta = (data['image_metadata'] as Map?)?['layer_metadata'] as List?;
  if (meta == null) return const {};
  final out = <String, String>{};
  for (final r in data['results'] as List? ?? const []) {
    for (final p in (r as Map)['packages'] as List? ?? const []) {
      final pkg = ((p as Map)['package'] as Map?) ?? const {};
      final idx = (pkg['image_origin_details'] as Map?)?['index'];
      if (idx is! int || idx < 0 || idx >= meta.length) continue;
      final diffId = (meta[idx] as Map?)?['diff_id'] as String? ?? '';
      if (diffId.isEmpty) continue;
      for (final v in p['vulnerabilities'] as List? ?? const []) {
        final m = v as Map;
        final aliases = (m['aliases'] as List?)?.cast<String>() ?? const [];
        final cve = aliases.firstWhere((a) => a.startsWith('CVE-'),
            orElse: () => '');
        out[vulnLayerKey(cve.isNotEmpty ? cve : '${m['id'] ?? ''}',
            '${pkg['name'] ?? ''}', '${pkg['version'] ?? ''}')] = diffId;
      }
    }
  }
  return out;
}
