import 'dart:io';
import 'package:sbom_generator/go_parser.dart';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('go_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  File _write(String name, String content) {
    final f = File('${tmp.path}/$name');
    f.writeAsStringSync(content);
    return f;
  }

  group('GoParser.parseGoSum', () {
    final parser = GoParser();

    test('extrait module et version, supprime le v majuscule', () {
      final f = _write(
          'go.sum',
          'github.com/gorilla/mux v1.8.0 h1:abc=\n'
              'github.com/gorilla/mux v1.8.0/go.mod h1:def=\n');
      final pkgs = parser.parseGoSum(f.path);
      expect(pkgs, hasLength(1));
      expect(pkgs[0].name, 'github.com/gorilla/mux');
      expect(pkgs[0].version, '1.8.0');
      expect(pkgs[0].packageType, 'golang');
    });

    test('ignore les lignes /go.mod', () {
      final f = _write(
          'go.sum',
          'github.com/lib/pq v1.10.7 h1:xyz=\n'
              'github.com/lib/pq v1.10.7/go.mod h1:abc=\n');
      final pkgs = parser.parseGoSum(f.path);
      expect(pkgs, hasLength(1));
    });

    test('déduplique les entrées', () {
      final f = _write(
          'go.sum',
          'github.com/foo/bar v1.0.0 h1:aaa=\n'
              'github.com/foo/bar v1.0.0 h1:bbb=\n');
      final pkgs = parser.parseGoSum(f.path);
      expect(pkgs, hasLength(1));
    });

    test('ignore les lignes vides et commentaires', () {
      final f =
          _write('go.sum', '\n// commentaire\ngithub.com/x/y v0.1.0 h1:z=\n\n');
      final pkgs = parser.parseGoSum(f.path);
      expect(pkgs, hasLength(1));
    });

    test('PURL de type pkg:golang/...', () {
      final f = _write('go.sum', 'golang.org/x/text v0.3.7 h1:abc=\n');
      final pkgs = parser.parseGoSum(f.path);
      expect(pkgs[0].purl, startsWith('pkg:golang/'));
    });

    test('fichier inexistant → liste vide', () {
      final pkgs = parser.parseGoSum('/nonexistent/go.sum');
      expect(pkgs, isEmpty);
    });
  });

  group('GoParser.parseGoMod', () {
    final parser = GoParser();

    test('extrait require bloc multi-lignes', () {
      final f = _write('go.mod', '''
module github.com/myorg/myapp

go 1.21

require (
\tgithub.com/gorilla/mux v1.8.0
\tgithub.com/lib/pq v1.10.7 // indirect
)
''');
      final pkgs = parser.parseGoMod(f.path);
      expect(pkgs, hasLength(2));
      expect(pkgs[0].name, 'github.com/gorilla/mux');
      expect(pkgs[0].version, '1.8.0');
      expect(pkgs[1].name, 'github.com/lib/pq');
    });

    test('extrait require en ligne unique', () {
      final f = _write('go.mod', '''
module example.com/proj
go 1.20
require github.com/pkg/errors v0.9.1
''');
      final pkgs = parser.parseGoMod(f.path);
      expect(pkgs, hasLength(1));
      expect(pkgs[0].name, 'github.com/pkg/errors');
      expect(pkgs[0].version, '0.9.1');
    });

    test('supprime le préfixe v du numéro de version', () {
      final f =
          _write('go.mod', 'module x\nrequire golang.org/x/tools v0.15.0\n');
      final pkgs = parser.parseGoMod(f.path);
      expect(pkgs[0].version, '0.15.0');
    });

    test('fichier inexistant → liste vide', () {
      expect(GoParser().parseGoMod('/nonexistent/go.mod'), isEmpty);
    });
  });
}
