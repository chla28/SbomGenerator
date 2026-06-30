import 'dart:convert';
import 'dart:io';
import 'package:sbom_generator/npm_parser.dart';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('npm_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  File _write(String name, Object content) {
    final f = File('${tmp.path}/$name');
    f.writeAsStringSync(
        content is String ? content : jsonEncode(content));
    return f;
  }

  group('NpmParser - lockfileVersion 2 (packages)', () {
    final parser = NpmParser();

    test('extrait les paquets depuis packages, ignore la racine', () {
      final f = _write('package-lock.json', {
        'name': 'my-app',
        'version': '1.0.0',
        'lockfileVersion': 2,
        'packages': {
          '': {'name': 'my-app', 'version': '1.0.0'},
          'node_modules/lodash': {
            'version': '4.17.21',
            'license': 'MIT',
            'resolved': 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          },
          'node_modules/@babel/core': {
            'version': '7.22.0',
            'license': 'MIT',
          },
        },
      });
      final pkgs = parser.parsePackageLock(f.path);
      expect(pkgs, hasLength(2));
      final names = pkgs.map((p) => p.name).toSet();
      expect(names, contains('lodash'));
      expect(names, contains('@babel/core'));
    });

    test('stripNodeModulesPrefix supprime correctement le préfixe', () {
      final f = _write('package-lock.json', {
        'lockfileVersion': 2,
        'packages': {
          '': {},
          'node_modules/express': {'version': '4.18.2', 'license': 'MIT'},
        },
      });
      final pkgs = parser.parsePackageLock(f.path);
      expect(pkgs[0].name, 'express');
    });

    test('licence extraite correctement', () {
      final f = _write('package-lock.json', {
        'lockfileVersion': 2,
        'packages': {
          '': {},
          'node_modules/foo': {'version': '1.0.0', 'license': 'Apache-2.0'},
        },
      });
      final pkgs = parser.parsePackageLock(f.path);
      expect(pkgs[0].license, 'Apache-2.0');
    });

    test('packageType est npm', () {
      final f = _write('package-lock.json', {
        'lockfileVersion': 2,
        'packages': {
          '': {},
          'node_modules/x': {'version': '1.0.0'},
        },
      });
      final pkgs = parser.parsePackageLock(f.path);
      expect(pkgs[0].packageType, 'npm');
    });

    test('PURL de type pkg:npm/...', () {
      final f = _write('package-lock.json', {
        'lockfileVersion': 2,
        'packages': {
          '': {},
          'node_modules/react': {'version': '18.2.0', 'license': 'MIT'},
        },
      });
      final pkgs = parser.parsePackageLock(f.path);
      expect(pkgs[0].purl, 'pkg:npm/react@18.2.0');
    });
  });

  group('NpmParser - lockfileVersion 1 (dependencies)', () {
    final parser = NpmParser();

    test('extrait les dépendances v1', () {
      final f = _write('package-lock.json', {
        'lockfileVersion': 1,
        'dependencies': {
          'lodash': {
            'version': '4.17.21',
            'resolved': 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          },
          'express': {'version': '4.18.2'},
        },
      });
      final pkgs = parser.parsePackageLock(f.path);
      expect(pkgs, hasLength(2));
    });

    test('dépendances imbriquées v1 extraites', () {
      final f = _write('package-lock.json', {
        'lockfileVersion': 1,
        'dependencies': {
          'foo': {
            'version': '1.0.0',
            'dependencies': {
              'bar': {'version': '2.0.0'},
            },
          },
        },
      });
      final pkgs = parser.parsePackageLock(f.path);
      expect(pkgs, hasLength(2));
    });
  });

  group('NpmParser - erreurs', () {
    final parser = NpmParser();

    test('fichier inexistant → liste vide', () {
      expect(parser.parsePackageLock('/nonexistent/package-lock.json'), isEmpty);
    });

    test('JSON invalide → liste vide + warning stderr', () {
      final f = _write('package-lock.json', 'not json {');
      expect(parser.parsePackageLock(f.path), isEmpty);
    });
  });
}
