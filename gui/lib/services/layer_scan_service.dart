import 'dart:convert';
import 'dart:io';

import '../models/layer_scan.dart';
import '../widgets/vuln_shared.dart' show VulnRow;
import 'settings_service.dart';

/// Sortie d'une exécution de scanner.
typedef ScanOutput = ({String json, int exitCode, String? stderr});

/// Résultat d'une analyse par couche : sortie JSON (fusionnée en mode
/// « chaque couche ») et couches de chaque vulnérabilité.
typedef LayeredScanOutcome = ({
  String json,
  int exitCode,
  String? stderr,
  LayerScanResult layerScan,
});

/// Étape en cours d'une analyse par couche (libellé fourni par l'interface,
/// dans sa langue — voir `layerScanStepLabel`).
sealed class LayerScanStep {
  const LayerScanStep();
}

/// Génération du jeu de SBOM par couche.
class LayerScanPreparing extends LayerScanStep {
  const LayerScanPreparing();
}

/// Scan de l'image (méthode « rattachement »).
class LayerScanScanningImage extends LayerScanStep {
  const LayerScanScanningImage();
}

/// Scan du SBOM de la couche [index] sur [total] (méthode « chaque couche »).
class LayerScanScanningLayer extends LayerScanStep {
  final int index;
  final int total;
  const LayerScanScanningLayer(this.index, this.total);
}

/// Prépare les jeux de SBOM par couche (`sbom-generator --per-layer`) et
/// orchestre l'analyse par couche des onglets de scan.
class LayerScanService {
  LayerScanService._();

  /// Jeux déjà générés dans la session, par (image, mode de calcul) : les
  /// trois onglets de scan réutilisent le même jeu.
  static final Map<String, Future<LayeredSbomSet>> _cache = {};
  static Process? _process;

  /// Jeu de SBOM par couche de [image], généré au besoin dans un répertoire
  /// temporaire (CycloneDX, `--oci-tool syft`).
  static Future<LayeredSbomSet> prepare(String image, String layerMode) {
    final key = '$image\u0000$layerMode';
    final pending = _cache[key] ??= _generate(image, layerMode);
    // Un échec n'est pas mis en cache : l'utilisateur peut relancer.
    pending.then((_) {}, onError: (Object _) {
      _cache.remove(key);
    });
    return pending;
  }

  static Future<LayeredSbomSet> _generate(String image, String layerMode) async {
    final dir = await Directory.systemTemp.createTemp('sbomgen_gui_layers_');
    final out = '${dir.path}/image.cdx.json';
    final p = await Process.start(
        SettingsService.cliBinary, prepareArgs(image, layerMode, out));
    _process = p;
    final err = StringBuffer();
    await Future.wait([
      p.stdout.drain<void>(),
      p.stderr.transform(const Utf8Decoder(allowMalformed: true)).forEach(err.write),
    ]);
    final code = await p.exitCode;
    _process = null;
    if (code != 0 || !File(out).existsSync()) {
      throw Exception('génération des SBOM de couche impossible '
          '(code $code) : ${err.toString().trim()}');
    }
    final json = jsonDecode(await File(out).readAsString());
    final set = LayeredSbomSet.parse(out, json as Map<String, dynamic>);
    if (set.layers.isEmpty) {
      throw Exception('aucune couche trouvée dans $image');
    }
    return set;
  }

  /// Arguments de `sbom-generator` qui produisent le jeu de SBOM par couche
  /// de [image] dans [output] (partagés avec l'aperçu « CLI Commande »).
  static List<String> prepareArgs(
          String image, String layerMode, String output) =>
      [
        '--image', image,
        '--oci-tool', 'syft',
        '--per-layer', '--layer-mode', layerMode,
        '-f', 'cyclonedx',
        '-o', output,
      ];

  /// Interrompt la génération en cours, s'il y en a une.
  static void kill() {
    _process?.kill(ProcessSignal.sigterm);
    _process = null;
  }

  /// Vide le cache (tests).
  static void clearCache() => _cache.clear();

  /// Analyse par couche de [image] :
  ///
  /// * [scanOnce] lance le scanner sur une cible (image si `useImage`, sinon
  ///   fichier SBOM) et renvoie sa sortie ;
  /// * [parse] lit une sortie en lignes de vulnérabilité ;
  /// * [merge] fusionne plusieurs sorties (mode « chaque couche ») ;
  /// * [nativeDigests] (trivy) : couche indiquée par le scanner lui-même,
  ///   prioritaire sur le rattachement par nom de paquet.
  ///
  /// [isCancelled] est consulté entre deux scans de couche.
  static Future<LayeredScanOutcome> run({
    required String image,
    required LayerScanSettings settings,
    required Future<ScanOutput> Function(String target, bool useImage) scanOnce,
    required List<VulnRow> Function(String json) parse,
    required String Function(List<String> outputs) merge,
    Map<String, String> Function(String json)? nativeDigests,
    void Function(LayerScanStep step)? onStatus,
    bool Function()? isCancelled,

    /// Remplace [prepare] (tests).
    Future<LayeredSbomSet> Function(String image, String layerMode)? prepareSet,
  }) async {
    onStatus?.call(const LayerScanPreparing());
    final set = await (prepareSet ?? prepare)(image, settings.layerMode);

    if (settings.mode == LayerScanMode.each) {
      final byKey = <String, Set<int>>{};
      final outputs = <String>[];
      var exitCode = 0;
      final errors = <String>[];
      for (final l in set.layers) {
        if (isCancelled?.call() ?? false) break;
        final path = l.path;
        if (path == null) continue;
        onStatus?.call(LayerScanScanningLayer(l.index, set.layers.length));
        final out = await scanOnce(path, false);
        if (out.exitCode > exitCode) exitCode = out.exitCode;
        if (out.stderr != null && out.json.isEmpty) {
          errors.add('couche ${l.index} : ${out.stderr}');
        }
        if (out.json.isEmpty) continue;
        outputs.add(out.json);
        for (final v in parse(out.json)) {
          (byKey[vulnLayerKey(v.id, v.packageName, v.installedVersion)] ??= {})
              .add(l.index);
        }
      }
      return (
        json: outputs.isEmpty ? '' : merge(outputs),
        exitCode: exitCode,
        stderr: errors.isEmpty ? null : errors.join('\n'),
        layerScan: LayerScanResult(
            mode: LayerScanMode.each, layers: set.layers, layersByKey: byKey),
      );
    }

    onStatus?.call(const LayerScanScanningImage());
    final out = await scanOnce(image, true);
    final byKey = <String, Set<int>>{};
    var unknown = 0;
    if (out.json.isNotEmpty) {
      final native = nativeDigests?.call(out.json) ?? const {};
      for (final v in parse(out.json)) {
        final key = vulnLayerKey(v.id, v.packageName, v.installedVersion);
        final d = native[key];
        final i = (d != null ? set.layerOfDigest(d) : null) ??
            set.layerOf(v.packageName, v.installedVersion);
        if (i == null) {
          unknown++;
        } else {
          (byKey[key] ??= {}).add(i);
        }
      }
    }
    return (
      json: out.json,
      exitCode: out.exitCode,
      stderr: out.stderr,
      layerScan: LayerScanResult(
        mode: LayerScanMode.attribute,
        layers: set.layers,
        layersByKey: byKey,
        unattributed: unknown,
      ),
    );
  }
}
