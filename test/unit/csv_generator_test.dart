import 'dart:io';
import 'package:sbom_generator/csv_generator.dart';
import 'package:sbom_generator/models.dart';
import 'package:test/test.dart';

List<Package> _makePackages() => [
      WheelPackage(
        name: 'requests',
        version: '2.28.0',
        license: 'Apache-2.0',
        url: 'https://pypi.org/project/requests',
        summary: 'Python HTTP library',
        vendor: 'Kenneth Reitz',
        arch: 'any',
        sourceRef: 'req.txt',
        requires: [],
        provides: ['requests'],
        packageType: 'pypi',
      ),
      WheelPackage(
        name: 'lodash',
        version: '4.17.21',
        license: 'MIT',
        url: 'https://lodash.com',
        summary: 'Utility library',
        vendor: '',
        arch: 'any',
        sourceRef: 'yarn.lock',
        requires: [],
        provides: ['lodash'],
        packageType: 'npm',
      ),
    ];

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('csv_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  group('CsvGenerator', () {
    test('génère une ligne de headers valide', () async {
      final out = '${tmp.path}/sbom.csv';
      await CsvGenerator().writeToFile(_makePackages(), out);
      final lines = File(out).readAsLinesSync();
      expect(lines.first,
          'name,version,architecture,license,type,purl,url,vendor');
    });

    test('génère une ligne par paquet', () async {
      final out = '${tmp.path}/sbom.csv';
      final pkgs = _makePackages();
      await CsvGenerator().writeToFile(pkgs, out);
      final lines = File(out).readAsLinesSync();
      // header + N lignes de paquets (+ ligne vide possible)
      expect(lines.where((l) => l.isNotEmpty), hasLength(pkgs.length + 1));
    });

    test('trie les paquets par nom', () async {
      final out = '${tmp.path}/sbom.csv';
      await CsvGenerator().writeToFile(_makePackages(), out);
      final lines =
          File(out).readAsLinesSync().where((l) => l.isNotEmpty).toList();
      // lodash < requests alphabétiquement
      expect(lines[1], startsWith('lodash'));
      expect(lines[2], startsWith('requests'));
    });

    test('échappe les virgules dans les valeurs', () async {
      final out = '${tmp.path}/sbom.csv';
      final pkg = WheelPackage(
        name: 'my,pkg',
        version: '1.0',
        license: 'MIT',
        url: '',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: '',
        requires: [],
        provides: ['my,pkg'],
        packageType: 'pypi',
      );
      await CsvGenerator().writeToFile([pkg], out);
      final content = File(out).readAsStringSync();
      expect(content, contains('"my,pkg"'));
    });

    test('échappe les guillemets dans les valeurs', () async {
      final out = '${tmp.path}/sbom.csv';
      final pkg = WheelPackage(
        name: 'say"hello"',
        version: '1.0',
        license: 'MIT',
        url: '',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: '',
        requires: [],
        provides: ['say"hello"'],
        packageType: 'pypi',
      );
      await CsvGenerator().writeToFile([pkg], out);
      final content = File(out).readAsStringSync();
      expect(content, contains('"say""hello"""'));
    });

    test('contient les PURLs corrects', () async {
      final out = '${tmp.path}/sbom.csv';
      await CsvGenerator().writeToFile(_makePackages(), out);
      final content = File(out).readAsStringSync();
      expect(content, contains('pkg:npm/lodash@4.17.21'));
      expect(content, contains('pkg:pypi/requests@2.28.0'));
    });
  });
}
