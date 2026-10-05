/// Tests d'intégration de `--per-layer` (un SBOM par couche d'image).
///
/// L'image est fabriquée pour le test : une archive `docker save` minimale à
/// deux couches dont la base APK (`lib/apk/db/installed`) évolue — la couche
/// 2 met à jour un paquet, en supprime un autre, en ajoute un troisième, et
/// supprime un fichier par *whiteout*. Le backend skopeo (lecture directe de
/// la base APK) impose le mode rootfs et ne dépend d'aucune base de données
/// externe.
///
/// Le test de bout en bout se saute si `skopeo` est absent ; les tests de
/// validation des options n'ont besoin d'aucun outil.
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:test/test.dart';

Future<bool> _hasSkopeo() async {
  try {
    return (await Process.run('skopeo', ['--version'])).exitCode == 0;
  } on ProcessException {
    return false;
  }
}

String _apkEntry(String name, String version) =>
    'P:$name\nV:$version\nA:x86_64\nL:MIT\nT:$name\n\n';

/// Crée le tar d'une couche à partir de [files] (chemin → contenu) et renvoie
/// son diff_id.
Future<String> _layerTar(
    String workDir, String tarPath, Map<String, String> files) async {
  final dir = Directory('$workDir/src-${tarPath.hashCode}')..createSync();
  files.forEach((path, content) {
    (File('${dir.path}/$path')..createSync(recursive: true))
        .writeAsStringSync(content);
  });
  final r = await Process.run('tar', ['-C', dir.path, '-cf', tarPath, '.']);
  expect(r.exitCode, 0, reason: r.stderr as String);
  dir.deleteSync(recursive: true);
  return 'sha256:${sha256.convert(File(tarPath).readAsBytesSync())}';
}

Future<ProcessResult> _cli(List<String> args) => Process.run(
    'dart', ['run', 'bin/sbom_generator.dart', '--lang', 'fr', ...args]);

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('per_layer_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<String> buildImage() async {
    final img = Directory('${tmp.path}/img')..createSync();
    final d1 = await _layerTar(tmp.path, '${img.path}/l1.tar', {
      'lib/apk/db/installed': _apkEntry('musl', '1.2.4-r0') +
          _apkEntry('zlib', '1.2.13-r0') +
          _apkEntry('busybox', '1.36.1-r0'),
      'etc/obsolete.conf': 'x',
    });
    final d2 = await _layerTar(tmp.path, '${img.path}/l2.tar', {
      'lib/apk/db/installed': _apkEntry('musl', '1.2.4-r0') +
          _apkEntry('zlib', '1.3.1-r0') +
          _apkEntry('curl', '8.9.0-r0'),
      'etc/.wh.obsolete.conf': '',
    });
    File('${img.path}/config.json').writeAsStringSync(jsonEncode({
      'architecture': 'amd64',
      'os': 'linux',
      'rootfs': {
        'type': 'layers',
        'diff_ids': [d1, d2]
      },
      'history': [
        {'created_by': 'ADD rootfs.tar /'},
        {'created_by': 'CMD ["sh"]', 'empty_layer': true},
        {
          'created_by':
              'RUN apk upgrade zlib && apk del busybox && apk add curl'
        },
      ],
    }));
    File('${img.path}/manifest.json').writeAsStringSync(jsonEncode([
      {
        'Config': 'config.json',
        'RepoTags': ['test/per-layer:1'],
        'Layers': ['l1.tar', 'l2.tar'],
      }
    ]));
    final archive = '${tmp.path}/image.tar';
    final r = await Process.run('tar', [
      '-C',
      img.path,
      '-cf',
      archive,
      'manifest.json',
      'config.json',
      'l1.tar',
      'l2.tar',
    ]);
    expect(r.exitCode, 0, reason: r.stderr as String);
    return archive;
  }

  test('rootfs (skopeo) : global annoté + un SBOM par couche', () async {
    if (!await _hasSkopeo()) {
      markTestSkipped('skopeo indisponible');
      return;
    }
    final archive = await buildImage();
    final out = '${tmp.path}/out/app';
    Directory('${tmp.path}/out').createSync();
    final r = await _cli([
      '--image',
      archive,
      '--oci-tool',
      'skopeo',
      '--per-layer',
      '-f',
      'cyclonedx,csv',
      '-o',
      out,
    ]);
    expect(r.exitCode, 0, reason: '${r.stdout}\n${r.stderr}');
    expect(r.stdout, contains('mode rootfs'));

    final names = Directory('${tmp.path}/out')
        .listSync()
        .map((e) => e.path.split('/').last)
        .toList()
      ..sort();
    expect(names.where((n) => n.contains('.layer-01-')), hasLength(2));
    expect(names.where((n) => n.contains('.layer-02-')), hasLength(2));
    expect(names, containsAll(['app.cdx.json', 'app.csv']));

    // Le global est écrit en premier (fichier ouvert par défaut par la GUI).
    final written = RegExp(r'SBOM written → (\S+)')
        .allMatches(r.stdout as String)
        .map((m) => m.group(1)!.split('/').last)
        .toList();
    expect(written.first, 'app.cdx.json');

    final layer2 = jsonDecode(File(
            '${tmp.path}/out/${names.firstWhere((n) => n.contains('.layer-02-') && n.endsWith('.cdx.json'))}')
        .readAsStringSync()) as Map<String, dynamic>;
    final root = (layer2['metadata'] as Map)['component'] as Map;
    expect(root['description'], contains('apk upgrade zlib'));
    final changes = {
      for (final c in layer2['components'] as List)
        c['name']: {
          for (final p in c['properties'] as List? ?? const [])
            p['name']: p['value'],
        }['sbom_generator:layer:change'],
    };
    expect(changes, {'zlib': 'modified', 'curl': 'added'});
    expect(
        (root['properties'] as List)
            .where((p) => p['name'] == 'sbom_generator:layer:removed')
            .single['value'],
        contains('busybox'));

    final global =
        jsonDecode(File('${tmp.path}/out/app.cdx.json').readAsStringSync())
            as Map<String, dynamic>;
    final links = ((global['metadata'] as Map)['component']
        as Map)['externalReferences'] as List;
    expect(links, hasLength(2));
    final zlib = (global['components'] as List)
        .firstWhere((c) => c['name'] == 'zlib') as Map;
    final zp = {
      for (final p in zlib['properties'] as List) p['name']: p['value']
    };
    expect(zp['sbom_generator:layer:index'], '1');
    expect(zp['sbom_generator:layer:modifiedBy'], '2');
  });

  group('validation des options', () {
    test('--layer-mode sans --per-layer', () async {
      final r = await _cli([
        '--image',
        'x.tar',
        '--layer-mode',
        'rootfs',
        '-o',
        '${tmp.path}/o'
      ]);
      expect(r.exitCode, 1);
      expect(r.stderr, contains('--layer-mode nécessite --per-layer'));
    });

    test('--per-layer avec --binary', () async {
      final r = await _cli([
        '--binary',
        Platform.resolvedExecutable,
        '--per-layer',
        '-o',
        '${tmp.path}/o',
      ]);
      expect(r.exitCode, 1);
      expect(r.stderr, contains('pas de couches'));
    });

    test('--layer-mode metadata avec skopeo', () async {
      final r = await _cli([
        '--image',
        'x.tar',
        '--oci-tool',
        'skopeo',
        '--per-layer',
        '--layer-mode',
        'metadata',
        '-o',
        '${tmp.path}/o',
      ]);
      expect(r.exitCode, 1);
      expect(r.stderr, contains('--layer-mode metadata nécessite'));
    });
  });

  group('scan --per-layer : validation', () {
    test('--sbom et --image exclusifs', () async {
      final r = await _cli(['scan', '--sbom', 'a.json', '--image', 'x.tar']);
      expect(r.exitCode, 1);
      expect(r.stderr, contains('exactement l\'un des trois'));
    });

    test('--layer-mode sans --image', () async {
      final f = File('${tmp.path}/s.cdx.json')..writeAsStringSync('{}');
      final r = await _cli(
          ['scan', '--sbom', f.path, '--per-layer', '--layer-mode', 'rootfs']);
      expect(r.exitCode, 1);
      expect(r.stderr, contains('--layer-mode nécessite --image'));
    });

    test('SBOM sans information de couche', () async {
      final f = File('${tmp.path}/s.cdx.json')
        ..writeAsStringSync(jsonEncode({
          'bomFormat': 'CycloneDX',
          'components': [
            {'name': 'a', 'version': '1'},
          ],
        }));
      final r = await _cli(['scan', '--sbom', f.path, '--per-layer']);
      expect(r.exitCode, 1);
      expect(r.stderr, contains('aucune information de couche'));
    });
  });
}
