/// `quality`, `licenses --policy` et `attest` : codes retour et fichiers
/// produits, avec un faux `cosign` pour la signature.
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  late String sbom;
  late String subject;

  Map<String, dynamic> component(String name, {String? license}) => {
        'type': 'library',
        'name': name,
        'version': '1.0',
        'purl': 'pkg:npm/$name@1.0',
        'supplier': {'name': 'ACME'},
        'hashes': [
          {'alg': 'SHA-256', 'content': 'a' * 64}
        ],
        if (license != null)
          'licenses': [
            {
              'license': {'id': license}
            }
          ],
      };

  setUp(() {
    tmp = Directory.systemTemp.createTempSync('qpa_');
    sbom = '${tmp.path}/s.cdx.json';
    File(sbom).writeAsStringSync(jsonEncode({
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'metadata': {
        'timestamp': '2026-01-01T00:00:00Z',
        'tools': {
          'components': [
            {'name': 'sbom_generator'}
          ]
        },
        'component': {'name': 'app'},
      },
      'components': [
        component('libok', license: 'MIT'),
        component('libgpl', license: 'GPL-3.0-only'),
      ],
      'dependencies': [
        {
          'ref': 'libok',
          'dependsOn': ['libgpl']
        }
      ],
    }));
    subject = '${tmp.path}/app.bin';
    File(subject).writeAsStringSync('abc');
  });
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> cli(List<String> args, {Map<String, String>? env}) =>
      Process.run(
          'dart', ['run', 'bin/sbom_generator.dart', '--lang', 'fr', ...args],
          environment: env);

  group('quality', () {
    test('sortie JSON : note et critères', () async {
      final r = await cli(['quality', '-i', sbom, '-f', 'json']);
      expect(r.exitCode, 0, reason: '${r.stderr}');
      final j = jsonDecode(r.stdout as String) as Map;
      expect(j['score'], isA<int>());
      expect((j['criteria'] as List).map((c) => c['id']),
          containsAll(['supplierName', 'timestamp', 'hash', 'license']));
    });

    test('--min-score trop haut : code 2', () async {
      final r = await cli(['quality', '-i', sbom, '--min-score', '101']);
      expect(r.exitCode, 1);
      final low = await cli(['quality', '-i', sbom, '--min-score', '100']);
      // Les composants ont fournisseur, hash et licence mais pas toutes les
      // métadonnées NTIA : la note maximale n'est pas atteinte ou l'est ;
      // seul le lien entre note et code retour est vérifié ici.
      final score = jsonDecode(
          (await cli(['quality', '-i', sbom, '-f', 'json'])).stdout
              as String)['score'] as int;
      expect(low.exitCode, score < 100 ? 2 : 0);
    });

    test('fichier introuvable : code 1', () async {
      final r = await cli(['quality', '-i', '${tmp.path}/absent.json']);
      expect(r.exitCode, 1);
      expect(r.stderr, contains('introuvable'));
    });
  });

  group('licenses --policy', () {
    String policy(String text) =>
        (File('${tmp.path}/policy.txt')..writeAsStringSync(text)).path;

    test('licence refusée : code 2 et composant listé', () async {
      final r = await cli([
        'licenses',
        '-i',
        sbom,
        '-f',
        'json',
        '--policy',
        policy('deny: GPL-*\n')
      ]);
      expect(r.exitCode, 2, reason: '${r.stderr}');
      expect(r.stderr, contains('libgpl'));
      expect(r.stderr, isNot(contains('libok')));
      // Le rapport JSON reste produit sur la sortie standard.
      expect(jsonDecode(r.stdout as String), isNotNull);
    });

    test('politique respectée : code 0', () async {
      final r = await cli([
        'licenses',
        '-i',
        sbom,
        '-f',
        'json',
        '--policy',
        policy('allow: MIT, GPL-3.0-only\n')
      ]);
      expect(r.exitCode, 0, reason: '${r.stderr}');
    });

    test('exception active écarte la violation', () async {
      final r = await cli([
        'licenses',
        '-i',
        sbom,
        '-f',
        'json',
        '--policy',
        policy('deny: GPL-*\nexcept: pkg:npm/libgpl; expires=2999-01-01\n')
      ]);
      expect(r.exitCode, 0, reason: '${r.stderr}');
    });

    test('fichier de politique absent : code 1', () async {
      final r = await cli([
        'licenses',
        '-i',
        sbom,
        '-f',
        'json',
        '--policy',
        '${tmp.path}/nope'
      ]);
      expect(r.exitCode, 1);
    });
  });

  group('attest', () {
    test('SBOM CycloneDX : déclaration in-toto avec le SHA-256 du sujet',
        () async {
      final out = '${tmp.path}/st.json';
      final r = await cli(['attest', '-i', sbom, '-s', subject, '-o', out]);
      expect(r.exitCode, 0, reason: '${r.stderr}');
      final st = jsonDecode(File(out).readAsStringSync()) as Map;
      expect(st['_type'], 'https://in-toto.io/Statement/v1');
      expect(st['predicateType'], 'https://cyclonedx.org/bom');
      expect(st['subject'].single['name'], 'app.bin');
      expect(st['subject'].single['digest']['sha256'],
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
      expect(st['predicate']['bomFormat'], 'CycloneDX');
    });

    test('provenance : --builder-id obligatoire, puis SLSA v1', () async {
      final bad = await cli(
          ['attest', '-i', sbom, '-s', subject, '--predicate', 'provenance']);
      expect(bad.exitCode, 1);
      expect(bad.stderr, contains('--builder-id'));

      final out = '${tmp.path}/prov.json';
      final r = await cli([
        'attest',
        '-i',
        sbom,
        '-s',
        subject,
        '--predicate',
        'provenance',
        '--builder-id',
        'https://ci.example/b',
        '-o',
        out
      ]);
      expect(r.exitCode, 0, reason: '${r.stderr}');
      final st = jsonDecode(File(out).readAsStringSync()) as Map;
      expect(st['predicateType'], 'https://slsa.dev/provenance/v1');
      expect(st['predicate']['runDetails']['builder']['id'],
          'https://ci.example/b');
    });

    test('sujet absent : code 1', () async {
      final r = await cli(['attest', '-i', sbom, '-s', '${tmp.path}/absent']);
      expect(r.exitCode, 1);
      expect(r.stderr, contains('introuvable'));
      final none = await cli(['attest', '-i', sbom]);
      expect(none.exitCode, 1);
      expect(none.stderr, contains('--subject'));
    });

    test('--sign : cosign attest-blob appelé avec le bon type', () async {
      final bin = Directory('${tmp.path}/bin')..createSync();
      File('${bin.path}/cosign').writeAsStringSync(
          '#!/bin/sh\necho "\$@" > "${tmp.path}/cosign.args"\nexit 0\n');
      Process.runSync('chmod', ['+x', '${bin.path}/cosign']);
      final out = '${tmp.path}/st.json';
      final r = await cli([
        'attest',
        '-i',
        sbom,
        '-s',
        subject,
        '-o',
        out,
        '--sign'
      ], env: {
        'PATH': '${bin.path}:${Platform.environment['PATH']}',
      });
      expect(r.exitCode, 0, reason: '${r.stderr}');
      final args = File('${tmp.path}/cosign.args').readAsStringSync();
      expect(args, contains('attest-blob'));
      expect(args, contains('--type cyclonedx'));
      expect(args, contains('--bundle $out.bundle'));
      expect(args, contains(subject));
      // Le prédicat temporaire est supprimé.
      expect(File('$out.predicate.tmp').existsSync(), isFalse);
    });

    test('--sign avec deux sujets : refusé', () async {
      final r = await cli(
          ['attest', '-i', sbom, '-s', subject, '-s', sbom, '--sign']);
      expect(r.exitCode, 1);
    });
  });
}
