import 'dart:io';
import 'package:sbom_generator/yarn_parser.dart';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('yarn_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  File _write(String name, String content) {
    final f = File('${tmp.path}/$name');
    f.writeAsStringSync(content);
    return f;
  }

  group('YarnParser - format v1 classique', () {
    final parser = YarnParser();

    test('extrait paquets basiques', () {
      final f = _write('yarn.lock', '''
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"
  integrity sha512-abc

express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
''');
      final pkgs = parser.parseYarnLock(f.path);
      expect(pkgs, hasLength(2));
      final names = pkgs.map((p) => p.name).toSet();
      expect(names, containsAll(['lodash', 'express']));
    });

    test('extrait correctement la version', () {
      final f = _write('yarn.lock', '''
# yarn lockfile v1

react@^18.0.0:
  version "18.2.0"
  resolved "https://example.com/react.tgz"
''');
      final pkgs = parser.parseYarnLock(f.path);
      expect(pkgs[0].version, '18.2.0');
    });

    test('déduplique les entrées avec plusieurs contraintes', () {
      final f = _write('yarn.lock', '''
# yarn lockfile v1

lodash@^4.17.0, lodash@^4.17.21:
  version "4.17.21"
  resolved "https://example.com/lodash.tgz"
''');
      final pkgs = parser.parseYarnLock(f.path);
      expect(pkgs, hasLength(1));
      expect(pkgs[0].name, 'lodash');
    });

    test('packageType est npm', () {
      final f = _write('yarn.lock', '''
# yarn lockfile v1

foo@^1.0.0:
  version "1.0.0"
  resolved "https://example.com/foo.tgz"
''');
      final pkgs = parser.parseYarnLock(f.path);
      expect(pkgs[0].packageType, 'npm');
    });

    test('PURL de type pkg:npm/...', () {
      final f = _write('yarn.lock', '''
# yarn lockfile v1

axios@^1.4.0:
  version "1.4.0"
  resolved "https://example.com/axios.tgz"
''');
      final pkgs = parser.parseYarnLock(f.path);
      expect(pkgs[0].purl, 'pkg:npm/axios@1.4.0');
    });

    test('URL résolue sans le hash #', () {
      final f = _write('yarn.lock', '''
# yarn lockfile v1

pkg@^1.0.0:
  version "1.0.0"
  resolved "https://example.com/pkg.tgz#abc123"
''');
      final pkgs = parser.parseYarnLock(f.path);
      expect(pkgs[0].url, isNot(contains('#')));
    });
  });

  group('YarnParser - format Berry v2+', () {
    final parser = YarnParser();

    test('détecte le format Berry et extrait les paquets', () {
      final f = _write('yarn.lock', '''
__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: abc123
  languageName: node
  linkType: hard

"react@npm:^18.2.0":
  version: 18.2.0
  resolution: "react@npm:18.2.0"
  languageName: node
  linkType: hard
''');
      final pkgs = parser.parseYarnLock(f.path);
      expect(pkgs, hasLength(2));
      expect(pkgs.map((p) => p.name), containsAll(['lodash', 'react']));
    });

    test('extrait la version Berry correctement', () {
      final f = _write('yarn.lock', '''
__metadata:
  version: 6

"express@npm:^4.18.0":
  version: 4.18.2
  resolution: "express@npm:4.18.2"
  languageName: node
  linkType: hard
''');
      final pkgs = parser.parseYarnLock(f.path);
      expect(pkgs[0].version, '4.18.2');
    });
  });

  group('YarnParser - erreurs', () {
    final parser = YarnParser();

    test('fichier inexistant → liste vide', () {
      expect(parser.parseYarnLock('/nonexistent/yarn.lock'), isEmpty);
    });

    test('fichier vide → liste vide', () {
      final f = _write('yarn.lock', '');
      expect(parser.parseYarnLock(f.path), isEmpty);
    });
  });
}
