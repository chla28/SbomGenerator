/// Analyse couche par couche d'une image de conteneur (`--per-layer`).
///
/// Le SBOM d'une couche N décrit son **delta** : les composants ajoutés ou
/// modifiés par cette couche (les composants supprimés sont listés à part).
/// Deux méthodes de calcul (`--layer-mode`) :
///
/// * `metadata` — attribution par le backend lui-même : `Layer.DiffID` de
///   trivy, ou couche la plus basse où syft (`--scope all-layers`) voit le
///   paquet. Une seule analyse de l'image (deux pour syft) ; seuls les
///   ajouts sont connus.
/// * `rootfs` — les couches sont appliquées une à une sur un rootfs cumulé
///   (sémantique overlayfs, *whiteouts* compris, voir [mergeLayerDir]), le
///   rootfs est réanalysé après chaque couche et le delta est la différence
///   avec l'état précédent ([diffPackages]) : ajouts, modifications (montée de
///   version…) et suppressions.
library;

import 'dart:convert';
import 'dart:io';

import 'models.dart';
import 'i18n.dart';

/// Préfixe des propriétés CycloneDX ajoutées par `--per-layer`.
const layerPropertyPrefix = 'sbom_generator:layer:';

/// Préfixe des propriétés du composant racine d'un SBOM global résumant
/// chaque couche (`sbom_generator:layers:001`… — valeur JSON, voir
/// [LayerSummary.toJson]).
const layerSummaryPrefix = 'sbom_generator:layers:';

/// Modes de calcul acceptés par `--layer-mode`.
const validLayerModes = {'metadata', 'rootfs'};

/// Backends capables du mode `metadata` (ils exposent la couche d'origine de
/// chaque paquet) ; les autres passent automatiquement en `rootfs`.
const metadataLayerTools = {'syft', 'trivy'};

// ── Couches ───────────────────────────────────────────────────────────────

/// Une couche d'image.
class ImageLayer {
  const ImageLayer({
    required this.index,
    required this.diffId,
    this.blobPath,
    this.createdBy,
    this.created,
  });

  /// Position dans la pile (1 = couche de base).
  final int index;

  /// `sha256:<hex>` du tar non compressé (`rootfs.diff_ids` de la config).
  final String diffId;

  /// Chemin du tar de la couche sur disque (mode `rootfs` uniquement).
  final String? blobPath;

  /// Instruction de build (`history[].created_by`), si connue.
  final String? createdBy;
  final String? created;

  /// 12 premiers caractères hexadécimaux du digest.
  String get shortDigest => shortHex(diffId);
}

String shortHex(String digest) {
  final hex = digest.contains(':') ? digest.split(':').last : digest;
  return hex.length > 12 ? hex.substring(0, 12) : hex;
}

/// Construit la liste des couches depuis les `diff_ids` et l'`history` d'une
/// config d'image OCI/Docker. Les entrées `history` marquées `empty_layer`
/// (ENV, CMD, LABEL…) ne produisent pas de couche et sont ignorées ;
/// l'instruction n'est rattachée que si le nombre d'entrées restantes
/// correspond au nombre de couches.
List<ImageLayer> layersFromConfig(
  List<String> diffIds,
  Object? history, {
  List<String>? blobPaths,
}) {
  final hist = [
    if (history is List)
      for (final h in history)
        if (h is Map && h['empty_layer'] != true) h,
  ];
  final withHistory = hist.length == diffIds.length;
  return [
    for (var i = 0; i < diffIds.length; i++)
      ImageLayer(
        index: i + 1,
        diffId: diffIds[i],
        blobPath:
            blobPaths != null && i < blobPaths.length ? blobPaths[i] : null,
        createdBy: withHistory ? hist[i]['created_by']?.toString() : null,
        created: withHistory ? hist[i]['created']?.toString() : null,
      ),
  ];
}

/// Digest déduit du nom de fichier d'une couche quand la config ne fournit
/// pas de `diff_ids` exploitable (`<hex>.tar`, `<hex>/layer.tar`,
/// `blobs/sha256/<hex>`).
String _digestFromPath(String path) {
  final m = RegExp(r'([0-9a-f]{64})').firstMatch(path);
  return m != null ? 'sha256:${m.group(1)}' : path;
}

List<String> _diffIdsOf(Map<String, dynamic>? config) {
  final rootfs = config?['rootfs'];
  if (rootfs is Map && rootfs['diff_ids'] is List) {
    return [for (final d in rootfs['diff_ids'] as List) d.toString()];
  }
  return const [];
}

Map<String, dynamic>? _readJson(File f) {
  if (!f.existsSync()) return null;
  try {
    final v = jsonDecode(f.readAsStringSync());
    return v is Map<String, dynamic> ? v : null;
  } on FormatException {
    return null;
  }
}

/// Couches d'une archive `docker save` / `podman save` déjà extraite dans
/// [dir] (`manifest.json` + config + un tar par couche).
List<ImageLayer> readDockerArchiveLayers(String dir) {
  final manifest = jsonDecode(File('$dir/manifest.json').readAsStringSync());
  if (manifest is! List || manifest.isEmpty || manifest.first is! Map) {
    throw FormatException(tr('manifest.json inattendu (tableau attendu)',
        'unexpected manifest.json (array expected)'));
  }
  final entry = manifest.first as Map;
  final paths = [
    for (final l in entry['Layers'] as List? ?? const []) '$dir/$l',
  ];
  final cfgPath = entry['Config'];
  final config = cfgPath == null ? null : _readJson(File('$dir/$cfgPath'));
  var diffIds = _diffIdsOf(config);
  if (diffIds.length != paths.length) {
    diffIds = [for (final p in paths) _digestFromPath(p)];
  }
  return layersFromConfig(diffIds, config?['history'], blobPaths: paths);
}

/// Couches d'un répertoire au format OCI Image Layout ([dir] contient
/// `index.json`). Un index multi-plateforme est résolu vers le manifeste
/// `linux/amd64` s'il existe, sinon le premier.
List<ImageLayer> readOciLayoutLayers(String dir) {
  String blob(String digest) => '$dir/blobs/${digest.replaceFirst(':', '/')}';

  var node = _readJson(File('$dir/index.json'));
  // Descend les index imbriqués jusqu'à un manifeste d'image.
  for (var depth = 0;
      depth < 4 && node != null && node['layers'] == null;
      depth++) {
    final manifests = [
      for (final m in node['manifests'] as List? ?? const [])
        if (m is Map<String, dynamic>) m,
    ];
    if (manifests.isEmpty) break;
    final pick = manifests.firstWhere(
      (m) {
        final p = m['platform'];
        return p is Map && p['os'] == 'linux' && p['architecture'] == 'amd64';
      },
      orElse: () => manifests.first,
    );
    node = _readJson(File(blob(pick['digest'] as String)));
  }
  if (node == null || node['layers'] is! List) {
    throw StateError(tr('layout OCI sans manifeste d\'image exploitable : $dir',
        'OCI layout without a usable image manifest: $dir'));
  }
  final paths = [
    for (final l in node['layers'] as List)
      blob((l as Map)['digest'] as String),
  ];
  final cfgDigest = (node['config'] as Map?)?['digest'] as String?;
  final config = cfgDigest == null ? null : _readJson(File(blob(cfgDigest)));
  var diffIds = _diffIdsOf(config);
  if (diffIds.length != paths.length) {
    diffIds = [for (final p in paths) _digestFromPath(p)];
  }
  return layersFromConfig(diffIds, config?['history'], blobPaths: paths);
}

// ── Application d'une couche (overlayfs) ──────────────────────────────────

const _opaqueMarker = '.wh..wh..opq';
const _whiteoutPrefix = '.wh.';

FileSystemEntityType _typeOf(String path) =>
    FileSystemEntity.typeSync(path, followLinks: false);

/// Supprime [path] sans jamais suivre de lien symbolique.
void _removeNoFollow(String path) {
  switch (_typeOf(path)) {
    case FileSystemEntityType.notFound:
      return;
    case FileSystemEntityType.link:
      Link(path).deleteSync();
    case FileSystemEntityType.directory:
      Directory(path).deleteSync(recursive: true);
    default:
      File(path).deleteSync();
  }
}

/// Applique la couche extraite dans [layerDir] sur le rootfs cumulé
/// [rootDir], selon la sémantique overlayfs des images OCI :
///
/// * `.wh.<nom>` supprime `<nom>` des couches inférieures ;
/// * `.wh..wh..opq` vide le répertoire de son contenu inférieur ;
/// * un répertoire fusionne avec un répertoire existant, toute autre entrée
///   (fichier, lien, répertoire sur un non-répertoire) remplace l'existant.
///
/// Les entrées sont **déplacées** (`rename`, même système de fichiers) depuis
/// [layerDir]. La descente dans [rootDir] ne passe que par de vrais
/// répertoires, jamais par un lien symbolique : une couche malveillante (lien
/// `x -> /` dans une couche, `x/…` dans la suivante) ne peut donc rien écrire
/// ni supprimer hors de [rootDir] — contrairement à des `tar -x` successifs
/// dans le même répertoire.
void mergeLayerDir(String layerDir, String rootDir) {
  final entries = Directory(layerDir).listSync(followLinks: false);
  final names = {for (final e in entries) e.path.split('/').last};

  // 1. Whiteouts : ils ne visent que les couches inférieures, donc avant tout
  //    déplacement du contenu de cette couche.
  if (names.contains(_opaqueMarker)) {
    for (final e in Directory(rootDir).listSync(followLinks: false)) {
      _removeNoFollow(e.path);
    }
  }
  for (final name in names) {
    if (name == _opaqueMarker || !name.startsWith(_whiteoutPrefix)) continue;
    final target = name.substring(_whiteoutPrefix.length);
    if (target.isEmpty || target == '.' || target == '..') continue;
    _removeNoFollow('$rootDir/$target');
  }

  // 2. Contenu de la couche.
  for (final e in entries) {
    final name = e.path.split('/').last;
    if (name.startsWith(_whiteoutPrefix)) continue;
    final dst = '$rootDir/$name';
    final srcType = _typeOf(e.path);
    final dstType = _typeOf(dst);
    if (srcType == FileSystemEntityType.directory) {
      // Fusion récursive, jamais un déplacement d'un bloc : les whiteouts
      // qu'il contient doivent être interprétés, pas copiés.
      if (dstType != FileSystemEntityType.directory) {
        if (dstType != FileSystemEntityType.notFound) _removeNoFollow(dst);
        Directory(dst).createSync();
      }
      mergeLayerDir(e.path, dst);
      continue;
    }
    if (dstType != FileSystemEntityType.notFound) _removeNoFollow(dst);
    if (srcType == FileSystemEntityType.link) {
      Link(e.path).renameSync(dst);
    } else {
      File(e.path).renameSync(dst);
    }
  }
}

// ── Delta entre deux états ────────────────────────────────────────────────

/// Changement apporté par une couche à un composant.
enum LayerChange { added, modified }

/// Composant modifié par une couche : [after] remplace [before] (montée de
/// version, licence ou empreinte différente…).
typedef PackageChange = ({Package before, Package after});

/// Différence entre l'état après la couche N-1 et après N.
class LayerDelta {
  LayerDelta({
    required this.added,
    required this.modified,
    required this.removed,
  });

  /// Delta d'une couche en mode `metadata` : seuls les ajouts sont connus.
  LayerDelta.addedOnly(List<Package> added)
      : this(added: added, modified: const [], removed: const []);

  final List<Package> added;
  final List<PackageChange> modified;

  /// Composants présents avant la couche et absents après (état N-1).
  final List<Package> removed;

  bool get isEmpty => added.isEmpty && modified.isEmpty && removed.isEmpty;

  /// Composants décrits par le SBOM de la couche (ajoutés puis modifiés).
  List<Package> get packages => [...added, for (final m in modified) m.after];

  /// Même delta, chaque composant transformé par [f] (surcharges de
  /// licence, fournisseur de repli…).
  LayerDelta map(Package Function(Package) f) => LayerDelta(
        added: [for (final p in added) f(p)],
        modified: [
          for (final m in modified) (before: f(m.before), after: f(m.after)),
        ],
        removed: [for (final p in removed) f(p)],
      );
}

/// Identité « logique » d'un composant, indépendante de sa version : sert à
/// reconnaître une montée de version comme une modification plutôt qu'un
/// couple suppression + ajout.
String _identity(Package p) =>
    '${p.packageType}|${p.name.toLowerCase()}|${p.arch}';

String _fingerprint(Package p) => [
      p.bomRef,
      p.purl,
      p.license,
      p.vendor,
      for (final h in p.hashes) '${h.alg}:${h.content}',
    ].join('\u0000');

/// Compare deux états successifs du rootfs.
///
/// Rapprochement par `bomRef` d'abord (composant inchangé ou dont seules les
/// métadonnées ont changé), puis, pour les restes, par identité logique
/// (type + nom + architecture) quand elle est univoque des deux côtés — une
/// montée de version d'un paquet unique apparaît alors comme « modifiée ».
/// Plusieurs versions d'un même nom (ex. `node_modules` imbriqués) ne sont
/// pas appariées entre elles : ajouts et suppressions distincts.
LayerDelta diffPackages(List<Package> before, List<Package> after) {
  final beforeByRef = {for (final p in before) p.bomRef: p};
  final afterRefs = {for (final p in after) p.bomRef};

  final modified = <PackageChange>[];
  final addedRest = <Package>[];
  for (final p in after) {
    final prev = beforeByRef[p.bomRef];
    if (prev == null) {
      addedRest.add(p);
    } else if (_fingerprint(prev) != _fingerprint(p)) {
      modified.add((before: prev, after: p));
    }
  }
  final removedRest = [
    for (final p in before)
      if (!afterRefs.contains(p.bomRef)) p,
  ];

  Map<String, List<Package>> group(List<Package> l) {
    final m = <String, List<Package>>{};
    for (final p in l) {
      (m[_identity(p)] ??= []).add(p);
    }
    return m;
  }

  final addedById = group(addedRest);
  final removedById = group(removedRest);
  final paired = <Package>{};
  for (final e in addedById.entries) {
    final r = removedById[e.key];
    if (e.value.length == 1 && r != null && r.length == 1) {
      modified.add((before: r.single, after: e.value.single));
      paired
        ..add(r.single)
        ..add(e.value.single);
    }
  }

  return LayerDelta(
    added: [
      for (final p in addedRest)
        if (!paired.contains(p)) p,
    ],
    modified: modified,
    removed: [
      for (final p in removedRest)
        if (!paired.contains(p)) p,
    ],
  );
}

// ── Mode rootfs : application successive des couches ─────────────────────

/// Applique [layers] une à une sur un rootfs cumulé créé dans [workDir],
/// analyse ce rootfs après chaque couche avec [scan] et renvoie le delta de
/// chaque couche. [workDir] doit être un répertoire temporaire vide (le
/// nettoyage incombe à l'appelant).
Future<LayerAnalysis> analyzeRootfsLayers({
  required List<ImageLayer> layers,
  required String workDir,
  required Future<List<Package>> Function(String rootDir) scan,
  void Function(String message)? log,
}) async {
  final rootDir = Directory('$workDir/rootfs')..createSync(recursive: true);
  final deltas = <LayerDelta>[];
  var previous = <Package>[];
  for (final layer in layers) {
    final blob = layer.blobPath;
    if (blob == null || !File(blob).existsSync()) {
      throw StateError(tr('tar de la couche ${layer.index} introuvable : $blob',
          'tar of layer ${layer.index} not found: $blob'));
    }
    log?.call('  ${tr('couche', 'layer')} ${layer.index}/${layers.length} '
        '(${layer.shortDigest})'
        '${layer.createdBy != null ? ' — ${_truncate(layer.createdBy!, 70)}' : ''}');
    final layerDir = Directory('$workDir/layer')..createSync();
    // tar détecte seul la compression (gzip, zstd…) des blobs OCI. Les
    // entrées impossibles à créer sans privilèges (périphériques) sont
    // ignorées : tar poursuit et renvoie un code d'erreur non bloquant.
    final x = await Process.run('tar', [
      '-C',
      layerDir.path,
      '--no-same-owner',
      '--no-same-permissions',
      '--delay-directory-restore',
      '--warning=none',
      '-xf',
      blob,
    ]);
    if (x.exitCode != 0) {
      final first = (x.stderr as String).split('\n').first.trim();
      if (first.isNotEmpty) {
        log?.call(
            tr('    avertissement tar : $first', '    tar warning: $first'));
      }
    }
    // Rend tout déplaçable/supprimable (répertoires 0555 d'une image…).
    await Process.run('chmod', ['-R', 'u+rwX', layerDir.path]);
    mergeLayerDir(layerDir.path, rootDir.path);
    layerDir.deleteSync(recursive: true);

    final seen = <String>{};
    final current = [
      for (final p in await scan(rootDir.path))
        if (seen.add(p.bomRef)) p,
    ];
    final delta = diffPackages(previous, current);
    log?.call('    +${delta.added.length} ~${delta.modified.length} '
        '-${delta.removed.length} (${current.length} ${tr('au total', 'in total')})');
    deltas.add(delta);
    previous = current;
  }
  return LayerAnalysis(mode: 'rootfs', layers: layers, deltas: deltas);
}

/// Mode `metadata` : delta de chaque couche déduit de la couche d'origine
/// indiquée par le backend ([layerOf] : `bomRef` → index de couche) pour les
/// composants [packages] de l'image. Les composants sans couche connue ne
/// figurent dans aucun SBOM de couche.
LayerAnalysis metadataLayerAnalysis(
    List<ImageLayer> layers, Map<String, int> layerOf, List<Package> packages) {
  final byLayer = <int, List<Package>>{};
  for (final p in packages) {
    final i = layerOf[p.bomRef];
    if (i != null) (byLayer[i] ??= []).add(p);
  }
  return LayerAnalysis(
    mode: 'metadata',
    layers: layers,
    deltas: [
      for (final l in layers)
        LayerDelta.addedOnly(byLayer[l.index] ?? const []),
    ],
  );
}

// ── Résultat global ───────────────────────────────────────────────────────

/// Couche d'origine d'un composant du SBOM global.
class LayerOrigin {
  const LayerOrigin({
    required this.index,
    required this.digest,
    this.modifiedBy = const [],
  });

  /// Couche qui a introduit le composant (la dernière, s'il a été supprimé
  /// puis réintroduit).
  final int index;
  final String digest;

  /// Index des couches suivantes qui l'ont modifié (mode `rootfs`).
  final List<int> modifiedBy;
}

/// Résultat de l'analyse par couche d'une image.
class LayerAnalysis {
  LayerAnalysis({
    required this.mode,
    required this.layers,
    required this.deltas,
  });

  /// `metadata` ou `rootfs`.
  final String mode;
  final List<ImageLayer> layers;

  /// Delta de chaque couche, dans l'ordre de [layers].
  final List<LayerDelta> deltas;

  /// Même analyse, chaque composant transformé par [f].
  LayerAnalysis map(Package Function(Package) f) => LayerAnalysis(
        mode: mode,
        layers: layers,
        deltas: [for (final d in deltas) d.map(f)],
      );

  /// Couche d'origine de chaque composant, par `bomRef` (état final).
  Map<String, LayerOrigin> origins() {
    final out = <String, LayerOrigin>{};
    final modifiedBy = <String, List<int>>{};
    for (var i = 0; i < layers.length; i++) {
      final layer = layers[i];
      for (final p in deltas[i].added) {
        out[p.bomRef] = LayerOrigin(index: layer.index, digest: layer.diffId);
        modifiedBy.remove(p.bomRef);
      }
      for (final m in deltas[i].modified) {
        // Nouvelle version : le composant final est rattaché à la couche qui
        // a introduit le nom, avec la trace des couches qui l'ont modifié.
        final prev = out.remove(m.before.bomRef);
        final hist = modifiedBy.remove(m.before.bomRef) ?? <int>[];
        out[m.after.bomRef] = LayerOrigin(
            index: prev?.index ?? layer.index,
            digest: prev?.digest ?? layer.diffId);
        modifiedBy[m.after.bomRef] = [...hist, layer.index];
      }
      for (final p in deltas[i].removed) {
        out.remove(p.bomRef);
        modifiedBy.remove(p.bomRef);
      }
    }
    return {
      for (final e in out.entries)
        e.key: LayerOrigin(
          index: e.value.index,
          digest: e.value.digest,
          modifiedBy: modifiedBy[e.key] ?? const [],
        ),
    };
  }
}

// ── Annotations transmises aux générateurs ───────────────────────────────

/// Résumé d'une couche, tel qu'il apparaît dans le SBOM global et en tête du
/// SBOM de la couche.
class LayerSummary {
  const LayerSummary({
    required this.layer,
    required this.total,
    required this.added,
    required this.modified,
    required this.removed,
    required this.fileBase,
    required this.documentUuid,
  });

  final ImageLayer layer;
  final int total;
  final int added;
  final int modified;
  final int removed;

  /// Nom de fichier du SBOM de la couche, sans répertoire ni extension de
  /// format (`app.layer-02-b676b687f0f5`).
  final String fileBase;

  /// UUID du document de la couche (numéro de série CycloneDX, espace de
  /// noms SPDX) — permet les liens croisés avec le SBOM global.
  final String documentUuid;

  Map<String, dynamic> toJson() => {
        'index': layer.index,
        'total': total,
        'digest': layer.diffId,
        if (layer.createdBy != null)
          'createdBy': _truncate(layer.createdBy!, 300),
        'added': added,
        'modified': modified,
        'removed': removed,
        'file': fileBase,
        'bomLink': bomLink(documentUuid),
      };
}

String _truncate(String s, int max) =>
    s.length <= max ? s : '${s.substring(0, max - 1)}…';

/// URL BOM-Link CycloneDX d'un document : `urn:cdx:<uuid>/1`.
String bomLink(String uuid) => 'urn:cdx:$uuid/1';

/// Informations de couche transmises aux générateurs de SBOM. Deux usages :
///
/// * SBOM **d'une couche** ([LayerAnnotations.forLayer]) : la couche décrite
///   ([self]), le changement de chaque composant, les composants supprimés et
///   le lien vers le SBOM global ;
/// * SBOM **global** ([LayerAnnotations.forGlobal]) : la couche d'origine de
///   chaque composant et le résumé de toutes les couches.
class LayerAnnotations {
  LayerAnnotations.forLayer({
    required this.mode,
    required LayerSummary this.self,
    required LayerDelta delta,
    required this.documentUuid,
    required this.globalUuid,
    required this.globalFileBase,
  })  : removed = delta.removed,
        changeByRef = {
          for (final p in delta.added) p.bomRef: LayerChange.added,
          for (final m in delta.modified) m.after.bomRef: LayerChange.modified,
        },
        previousVersionByRef = {
          for (final m in delta.modified)
            if (m.before.fullVersion != m.after.fullVersion)
              m.after.bomRef: m.before.fullVersion,
        },
        layers = const [],
        originByRef = const {};

  LayerAnnotations.forGlobal({
    required this.mode,
    required this.layers,
    required this.originByRef,
    required this.documentUuid,
  })  : self = null,
        globalUuid = null,
        globalFileBase = null,
        removed = const [],
        changeByRef = const {},
        previousVersionByRef = const {};

  /// `metadata` ou `rootfs`.
  final String mode;

  /// UUID de ce document (numéro de série CycloneDX, espace de noms SPDX).
  final String documentUuid;

  // SBOM d'une couche
  final LayerSummary? self;
  final String? globalUuid;
  final String? globalFileBase;
  final Map<String, LayerChange> changeByRef;
  final Map<String, String> previousVersionByRef;
  final List<Package> removed;

  // SBOM global
  final List<LayerSummary> layers;
  final Map<String, LayerOrigin> originByRef;

  bool get isLayerDocument => self != null;

  /// Libellé court de la couche décrite (`couche 2/9 (b676b687f0f5)`).
  String get layerLabel => self == null
      ? ''
      : 'couche ${self!.layer.index}/${self!.total} (${self!.layer.shortDigest})';

  /// Paires clé/valeur décrivant un composant vis-à-vis des couches
  /// (sans préfixe) — utilisées par tous les formats.
  Map<String, String> componentFields(Package pkg) {
    if (isLayerDocument) {
      final change = changeByRef[pkg.bomRef];
      return {
        if (change != null) 'change': change.name,
        if (previousVersionByRef[pkg.bomRef] case final v?)
          'previousVersion': v,
      };
    }
    final o = originByRef[pkg.bomRef];
    if (o == null) return const {};
    return {
      'index': '${o.index}',
      'digest': o.digest,
      if (o.modifiedBy.isNotEmpty) 'modifiedBy': o.modifiedBy.join(','),
    };
  }

  /// Valeur de la colonne « couche » des formats tabulaires : index de la
  /// couche d'origine (SBOM global) ou nature du changement (SBOM de couche).
  String columnValue(Package pkg) {
    if (isLayerDocument) {
      final change = changeByRef[pkg.bomRef];
      if (change == null) return '';
      final prev = previousVersionByRef[pkg.bomRef];
      return change == LayerChange.added
          ? 'ajouté'
          : prev != null
              ? 'modifié (était $prev)'
              : 'modifié';
    }
    final o = originByRef[pkg.bomRef];
    if (o == null) return '';
    return o.modifiedBy.isEmpty
        ? '${o.index}'
        : '${o.index} (modifié : ${o.modifiedBy.join(', ')})';
  }

  /// En-tête de la colonne correspondant à [columnValue].
  String get columnTitle => isLayerDocument ? 'Changement' : 'Couche';

  /// Description textuelle du document (commentaire SPDX, en-têtes des
  /// formats lisibles).
  List<String> describe() {
    if (isLayerDocument) {
      final s = self!;
      return [
        'SBOM de la $layerLabel — delta de la couche (mode $mode).',
        'Digest : ${s.layer.diffId}',
        if (s.layer.createdBy != null)
          'Instruction : ${_truncate(s.layer.createdBy!, 500)}',
        'Ajoutés : ${s.added} — modifiés : ${s.modified} — supprimés : ${s.removed}',
        'SBOM global : $globalFileBase',
      ];
    }
    return [
      'Image analysée couche par couche (mode $mode) : ${layers.length} couche(s).',
      for (final l in layers)
        'Couche ${l.layer.index} (${l.layer.shortDigest}) : +${l.added} '
            '~${l.modified} -${l.removed}'
            '${l.layer.createdBy != null ? ' — ${_truncate(l.layer.createdBy!, 120)}' : ''}'
            ' → ${l.fileBase}',
    ];
  }
}

// ── Nommage des fichiers ──────────────────────────────────────────────────

/// Nom de base (sans extension de format) du SBOM d'une couche :
/// `<base>.layer-NN-<digest12>` — `NN` sur deux chiffres au moins, pour que
/// l'ordre alphabétique suive l'ordre des couches.
String layerFileBase(String base, ImageLayer layer, int total) {
  final width = total < 10 ? 2 : total.toString().length;
  return '$base.layer-${layer.index.toString().padLeft(width, '0')}'
      '-${layer.shortDigest}';
}
