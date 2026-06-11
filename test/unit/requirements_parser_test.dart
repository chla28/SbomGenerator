import 'dart:io';
import 'package:sbom_generator/requirements_parser.dart';
import 'package:test/test.dart';

void main() {
  group('RequirementsParser', () {
    late Directory tmp;

    setUp(() => tmp = Directory.systemTemp.createTempSync('req_test_'));
    tearDown(() => tmp.deleteSync(recursive: true));

    File _write(String content) {
      final f = File('${tmp.path}/requirements.txt');
      f.writeAsStringSync(content);
      return f;
    }

    test('version épinglée == extraite', () {
      final f = _write('requests==2.28.0\n');
      final pkgs = RequirementsParser().parseFile(f.path);
      expect(pkgs, hasLength(1));
      expect(pkgs[0].name, 'requests');
      expect(pkgs[0].version, '2.28.0');
      expect(pkgs[0].packageType, 'pypi');
    });

    test('nom normalisé PEP 503', () {
      final f = _write('My_Package==1.0\n');
      final pkgs = RequirementsParser().parseFile(f.path);
      expect(pkgs[0].name, 'my-package');
    });

    test('extras strippés', () {
      final f = _write('requests[security]==2.28.0\n');
      final pkgs = RequirementsParser().parseFile(f.path);
      expect(pkgs[0].name, 'requests');
      expect(pkgs[0].version, '2.28.0');
    });

    test('commentaires ignorés', () {
      final f = _write('# commentaire\nrequests==2.28.0\n');
      final pkgs = RequirementsParser().parseFile(f.path);
      expect(pkgs, hasLength(1));
    });

    test('lignes vides ignorées', () {
      final f = _write('\n\nrequests==2.28.0\n\n');
      final pkgs = RequirementsParser().parseFile(f.path);
      expect(pkgs, hasLength(1));
    });

    test('directives -r / -i / -e ignorées', () {
      final f =
          _write('-r other.txt\n-i https://pypi.org\n-e .\nrequests==1.0\n');
      final pkgs = RequirementsParser().parseFile(f.path);
      expect(pkgs, hasLength(1));
      expect(pkgs[0].name, 'requests');
    });

    test('marqueurs d\'environnement strippés', () {
      final f = _write('requests==2.28.0 ; python_version >= "3.8"\n');
      final pkgs = RequirementsParser().parseFile(f.path);
      expect(pkgs, hasLength(1));
      expect(pkgs[0].name, 'requests');
    });

    test('nom sans version → version vide', () {
      final f = _write('flask\n');
      final pkgs = RequirementsParser().parseFile(f.path);
      expect(pkgs[0].name, 'flask');
      expect(pkgs[0].version, isEmpty);
    });

    test('plusieurs paquets', () {
      final f = _write('flask==3.0.0\nrequests==2.28.0\nnumpy\n');
      final pkgs = RequirementsParser().parseFile(f.path);
      expect(pkgs, hasLength(3));
    });

    test('fichier inexistant → liste vide sans exception', () {
      final pkgs = RequirementsParser().parseFile('/tmp/nonexistent_req.txt');
      expect(pkgs, isEmpty);
    });
  });
}
