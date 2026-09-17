/// Integration test for `--binary`, alias explicite pour `--image <fichier>`
/// forçant le backend syft (seul capable d'analyser un binaire autonome).
///
/// Le chemin analysé est `Platform.resolvedExecutable` (le binaire `dart`
/// lui-même) : toujours présent, réel fichier ELF/Mach-O local — le test
/// vérifie le câblage CLI (validation, forçage du backend, sortie valide),
/// pas la précision du classifieur syft (couverte par les tests unitaires
/// de `oci_parser_test.dart` sur du JSON syft simulé).
///
/// Se saute automatiquement si `syft` est absent.
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

Future<bool> _hasSyft() async {
  try {
    final r = await Process.run('syft', ['--version']);
    return r.exitCode == 0;
  } on ProcessException {
    return false;
  }
}

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('binary_input_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  test('--binary <fichier> produit un SBOM (backend syft forcé)', () async {
    if (!await _hasSyft()) {
      markTestSkipped('syft indisponible');
      return;
    }
    final outPath = '${tmp.path}/out.cdx.json';
    final r = await Process.run('dart', [
      'run', 'bin/sbom_generator.dart',
      '--binary', Platform.resolvedExecutable,
      '-o', outPath,
    ], workingDirectory: Directory.current.path);
    expect(r.exitCode, 0, reason: '${r.stdout}\n${r.stderr}');
    final doc = jsonDecode(File(outPath).readAsStringSync());
    expect(doc, isA<Map>());
    expect((doc as Map)['components'], isA<List>());
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('--binary sur un fichier inexistant → erreur claire, exit != 0',
      () async {
    final r = await Process.run('dart', [
      'run', 'bin/sbom_generator.dart',
      '--binary', '${tmp.path}/nexistepas',
      '-o', '${tmp.path}/out.cdx.json',
    ], workingDirectory: Directory.current.path);
    expect(r.exitCode, isNot(0));
    expect(r.stderr, contains('fichier introuvable'));
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('--binary + --oci-tool trivy → rejeté (seul syft est supporté)',
      () async {
    final bin = File('${tmp.path}/fake-bin')..writeAsBytesSync([0]);
    final r = await Process.run('dart', [
      'run', 'bin/sbom_generator.dart',
      '--binary', bin.path,
      '--oci-tool', 'trivy',
      '-o', '${tmp.path}/out.cdx.json',
    ], workingDirectory: Directory.current.path);
    expect(r.exitCode, isNot(0));
    expect(r.stderr, contains('--oci-tool syft'));
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('--binary et --image ensemble → rejeté', () async {
    final bin = File('${tmp.path}/fake-bin')..writeAsBytesSync([0]);
    final r = await Process.run('dart', [
      'run', 'bin/sbom_generator.dart',
      '--binary', bin.path,
      '--image', 'nginx:latest',
      '-o', '${tmp.path}/out.cdx.json',
    ], workingDirectory: Directory.current.path);
    expect(r.exitCode, isNot(0));
    expect(r.stderr, contains('exclusifs'));
  }, timeout: const Timeout(Duration(seconds: 30)));
}
