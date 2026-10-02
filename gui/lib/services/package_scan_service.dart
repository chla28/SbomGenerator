import 'dart:convert';
import 'dart:io';

import 'settings_service.dart';

/// Profondeurs proposées pour `--depth` (valeurs transmises telles quelles au
/// CLI) : 0 = l'objet seul, N niveaux, `all` = sans limite.
const packageScanDepths = ['0', '1', '2', '3', 'all'];

/// Échec de la génération du SBOM d'un paquet/archive.
class PackageScanException implements Exception {
  final int exitCode;
  final String details;
  const PackageScanException(this.exitCode, this.details);

  @override
  String toString() => details.isEmpty ? 'code $exitCode' : details;
}

/// Prépare le SBOM d'un paquet ou d'une archive locale (rpm, deb, tar/tgz,
/// zip, jar…) avant son analyse par Grype / OSV-Scanner / Trivy : la GUI
/// n'implémente aucune logique métier, elle lance
/// `sbom-generator --input … --depth N` puis scanne le SBOM CycloneDX produit
/// comme n'importe quel fichier SBOM.
class PackageScanService {
  PackageScanService._();

  /// SBOM déjà générés dans la session, par (fichier, date de modification,
  /// profondeur) : les trois onglets de scan partagent le même SBOM.
  static final Map<String, Future<String>> _cache = {};
  static Process? _process;

  /// Arguments de `sbom-generator` pour produire le SBOM CycloneDX de
  /// [packagePath] dans [outputPath] (profondeur [depth]).
  static List<String> prepareArgs(
          String packagePath, String depth, String outputPath) =>
      [
        '--input',
        packagePath,
        '--depth',
        depth,
        '--no-nested-files',
        '--format',
        'cyclonedx',
        '--output',
        outputPath,
      ];

  /// Chemin du SBOM CycloneDX de [packagePath] à la profondeur [depth],
  /// généré au besoin dans un répertoire temporaire. Lève une
  /// [PackageScanException] si la génération échoue.
  static Future<String> prepare(String packagePath, String depth) {
    final mtime = File(packagePath).statSync().modified.millisecondsSinceEpoch;
    final key = '$packagePath\u0000$mtime\u0000$depth';
    final pending = _cache[key] ??= _generate(packagePath, depth);
    // Un échec n'est pas mis en cache : l'utilisateur peut relancer.
    pending.then((_) {}, onError: (Object _) {
      _cache.remove(key);
    });
    return pending;
  }

  static Future<String> _generate(String packagePath, String depth) async {
    final dir = await Directory.systemTemp.createTemp('sbomgen_gui_package_');
    final out = '${dir.path}/package.cdx.json';
    final p = await Process.start(
        SettingsService.cliBinary, prepareArgs(packagePath, depth, out));
    _process = p;
    final err = StringBuffer();
    await Future.wait([
      p.stdout.drain<void>(),
      p.stderr
          .transform(const Utf8Decoder(allowMalformed: true))
          .forEach(err.write),
    ]);
    final code = await p.exitCode;
    _process = null;
    if (code != 0 || !File(out).existsSync()) {
      try {
        await dir.delete(recursive: true);
      } on FileSystemException {
        // Nettoyage best-effort.
      }
      throw PackageScanException(code, err.toString().trim());
    }
    return out;
  }

  /// Interrompt la génération en cours (bouton Arrêter des onglets de scan).
  static void kill() => _process?.kill();
}
