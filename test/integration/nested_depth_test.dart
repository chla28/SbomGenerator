/// Integration test de `--depth` : descente dans les objets imbriqués d'une
/// archive (jar dans jar dans tgz + lockfile) et attribution des CVE par
/// `scan --package`. Les fixtures sont fabriquées à la volée avec python3
/// (aucun binaire versionné) ; le test se saute si python3 ou unzip manquent.
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

const _fixtureScript = r'''
import io, json, sys, tarfile, zipfile
out = sys.argv[1]
def jar(g, a, v, extra=None):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        z.writestr('META-INF/maven/%s/%s/pom.properties' % (g, a),
                   'groupId=%s\nartifactId=%s\nversion=%s\n' % (g, a, v))
        for n, d in (extra or {}).items():
            z.writestr(n, d)
    return b.getvalue()
baz = jar('org.acme', 'baz', '3.1')
foo = jar('org.acme', 'foo', '1.2.3', {'BOOT-INF/lib/baz-3.1.jar': baz})
bar = jar('org.acme', 'bar', '2.0')
lock = json.dumps({'lockfileVersion': 3, 'packages': {
    '': {'name': 'app'}, 'node_modules/left-pad': {'version': '1.3.0'}}}).encode()
with tarfile.open(out, 'w:gz') as t:
    for n, d in {'o/lib/foo-1.2.3.jar': foo, 'o/lib/bar-2.0.jar': bar,
                 'o/package-lock.json': lock, 'o/readme.txt': b'hi'}.items():
        i = tarfile.TarInfo(n); i.size = len(d); t.addfile(i, io.BytesIO(d))
''';

Future<bool> _has(String cmd, List<String> args) async {
  try {
    return (await Process.run(cmd, args)).exitCode == 0;
  } on ProcessException {
    return false;
  }
}

Set<String> _names(String path) => {
      for (final c
          in (jsonDecode(File(path).readAsStringSync())['components'] as List))
        '${(c as Map)['name']}'
    };

void main() {
  late Directory tmp;
  late String archive;
  var ready = false;

  setUpAll(() async {
    ready = await _has('python3', ['--version']) && await _has('unzip', ['-v']);
  });
  setUp(() async {
    tmp = Directory.systemTemp.createTempSync('nested_depth_test_');
    archive = '${tmp.path}/outer-1.0.0.tgz';
    if (ready) {
      await Process.run('python3', ['-c', _fixtureScript, archive]);
    }
  });
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> gen(List<String> extra) => Process.run(
      'dart', ['run', 'bin/sbom_generator.dart', '-i', archive, ...extra],
      workingDirectory: Directory.current.path);

  test('--depth 0 : seul l\'objet racine, aucun SBOM imbriqué', () async {
    if (!ready) return markTestSkipped('python3/unzip indisponibles');
    final out = '${tmp.path}/sbom.cdx.json';
    final r = await gen(['-o', out]);
    expect(r.exitCode, 0, reason: '${r.stdout}\n${r.stderr}');
    expect(_names(out), {'outer'});
    expect(tmp.listSync().where((e) => e.path.contains('.nested-')), isEmpty);
  }, timeout: const Timeout(Duration(seconds: 90)));

  test('--depth 1 : jars et lockfile directs, pas le jar du fat jar', () async {
    if (!ready) return markTestSkipped('python3/unzip indisponibles');
    final out = '${tmp.path}/sbom.cdx.json';
    final r = await gen(['--depth', '1', '-o', out]);
    expect(r.exitCode, 0, reason: '${r.stdout}\n${r.stderr}');
    expect(_names(out), {'outer', 'foo', 'bar', 'left-pad'});
  }, timeout: const Timeout(Duration(seconds: 90)));

  test('--depth all : 2 niveaux, propriétés, graphe, un SBOM par objet',
      () async {
    if (!ready) return markTestSkipped('python3/unzip indisponibles');
    final out = '${tmp.path}/sbom.cdx.json';
    final r = await gen(['--depth', 'all', '-o', out]);
    expect(r.exitCode, 0, reason: '${r.stdout}\n${r.stderr}');
    expect(_names(out), {'outer', 'foo', 'bar', 'baz', 'left-pad'});

    final doc = jsonDecode(File(out).readAsStringSync()) as Map;
    final baz = (doc['components'] as List)
        .cast<Map>()
        .firstWhere((c) => c['name'] == 'baz');
    final props = {
      for (final p in (baz['properties'] as List).cast<Map>())
        p['name']: p['value']
    };
    expect(props['sbom_generator:nested:depth'], '2');
    expect(props['sbom_generator:nested:location'],
        'outer-1.0.0.tgz!/o/lib/foo-1.2.3.jar!/BOOT-INF/lib/baz-3.1.jar');
    // pas de chemin temporaire dans le SBOM
    expect(File(out).readAsStringSync(), isNot(contains('sbom_nested_')));

    final deps = {
      for (final d in (doc['dependencies'] as List).cast<Map>())
        d['ref']: d['dependsOn']
    };
    expect(deps['pkg-maven-org.acme-foo-1.2.3'],
        contains('pkg-maven-org.acme-baz-3.1'));

    final files = tmp
        .listSync()
        .map((e) => e.path.split('/').last)
        .where((n) => n.contains('.nested-'))
        .toList();
    expect(files, hasLength(4)); // foo, baz, bar, package-lock.json
  }, timeout: const Timeout(Duration(seconds: 90)));

  test('--no-nested-files : fusionné seulement', () async {
    if (!ready) return markTestSkipped('python3/unzip indisponibles');
    final out = '${tmp.path}/sbom.cdx.json';
    final r = await gen(['--depth', '1', '--no-nested-files', '-o', out]);
    expect(r.exitCode, 0, reason: '${r.stdout}\n${r.stderr}');
    expect(tmp.listSync().where((e) => e.path.contains('.nested-')), isEmpty);
  }, timeout: const Timeout(Duration(seconds: 90)));

  test('--depth invalide ou sans --input → erreur', () async {
    final bad = await Process.run(
        'dart', ['run', 'bin/sbom_generator.dart', '-i', 'x', '--depth', 'abc'],
        workingDirectory: Directory.current.path);
    expect(bad.exitCode, isNot(0));
    expect('${bad.stderr}${bad.stdout}', contains('--depth'));
  }, timeout: const Timeout(Duration(seconds: 60)));
}
