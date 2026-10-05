/// Tests d'intégration des validations d'arguments du CLI : options
/// obligatoires, dates strictes, messages d'erreur traduits, outil externe
/// absent (cosign) et dénominateur du résumé « Analysés ».
@TestOn('posix')
library;

import 'dart:io';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('cli_args_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> cli(List<String> args, {Map<String, String>? env}) =>
      Process.run('dart', ['run', 'bin/sbom_generator.dart', ...args],
          environment: env);

  group('options obligatoires des sous-commandes', () {
    for (final (cmd, option) in [
      ('cra', '--sbom'),
      ('convert', '--input'),
      ('licenses', '--input'),
      ('merge', '--output'),
    ]) {
      test('$cmd sans $option : erreur d\'usage, code 1, pas d\'exception',
          () async {
        final r = await cli(['--lang', 'fr', cmd]);
        expect(r.exitCode, 1);
        expect(r.stderr, contains("$cmd: L'option $option est obligatoire."));
        expect(r.stderr, isNot(contains('Unhandled exception')));
      });
    }

    test('--help reste possible sans l\'option obligatoire', () async {
      final r = await cli(['cra', '--help']);
      expect(r.exitCode, 0);
    });
  });

  group('dates de scan', () {
    final sbom = '{"bomFormat":"CycloneDX","specVersion":"1.6",'
        '"components":[]}';
    for (final bad in ['2024-13-45', '2024-02-30', '2024-1-1', 'hier']) {
      test('--cve-after "$bad" est refusée', () async {
        final f = File('${tmp.path}/s.cdx.json')..writeAsStringSync(sbom);
        final r = await cli(
            ['--lang', 'en', 'scan', '--sbom', f.path, '--cve-after', bad]);
        expect(r.exitCode, 1);
        expect(r.stderr, contains('invalid date format for --cve-after'));
      });
    }
  });

  test('message d\'erreur d\'args traduit en français', () async {
    final r =
        await cli(['--lang', 'fr', '-i', 'x', '--cyclonedx-version', '2.0']);
    expect(r.exitCode, 1);
    expect(r.stderr, contains("n'est pas une valeur autorisée"));
    expect(r.stderr, isNot(contains('is not an allowed value')));
  });

  test('--sign sans cosign : avertissement, fichiers écrits, code 0', () async {
    final req = File('${tmp.path}/requirements.txt')
      ..writeAsStringSync('requests==2.31.0\n');
    final out = '${tmp.path}/out.cdx.json';
    final r = await cli(['--lang', 'fr', '-i', req.path, '-o', out, '--sign'],
        env: {'PATH': tmp.path + ':' + _dartDir()});
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(File(out).existsSync(), isTrue);
    expect(r.stderr, contains('sign: cosign introuvable'));
  });

  test('« Analysés : X/Y » : le dénominateur compte les paquets des manifestes',
      () async {
    final req = File('${tmp.path}/requirements.txt')
      ..writeAsStringSync('requests==2.31.0\nurllib3==1.26.0\nflask==3.0.0\n');
    final r = await cli([
      '--lang',
      'fr',
      '-i',
      req.path,
      '-f',
      'csv',
      '-o',
      '${tmp.path}/o.csv'
    ]);
    expect(r.exitCode, 0);
    expect(r.stdout, contains('Analysés : 3/3 paquet(s).'));
  });
}

/// Dossier de l'exécutable `dart` (pour garder `dart` dans le PATH tout en
/// excluant `cosign`).
String _dartDir() => File(Platform.resolvedExecutable).parent.path;
