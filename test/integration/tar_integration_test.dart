/// Integration tests that parse the real example archives.
///
/// Require python3 in PATH. Skipped automatically when python3 is absent.
@TestOn('posix')
library;

import 'dart:io';
import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/tar_parser.dart';
import 'package:sbom_generator/wheel_parser.dart';
import 'package:test/test.dart';

const _base = 'example/3PP';

Future<bool> _hasPython3() async {
  final r = await Process.run('python3', ['--version']);
  return r.exitCode == 0;
}

void main() {
  late bool py3;

  setUpAll(() async {
    py3 = await _hasPython3();
  });

  group('TarParser — archives génériques 3PP', () {
    final tarParser = TarParser();

    void skipIfNoPy3() {
      if (!py3) {
        markTestSkipped('python3 absent — test d\'intégration ignoré');
      }
    }

    test('apache-tomcat → nom=apache-tomcat, ver≈10', () async {
      skipIfNoPy3();
      final pkg =
          await tarParser.parseTarFile('$_base/apache-tomcat-10.1.44.tar.gz');
      expect(pkg, isNotNull);
      expect(pkg!.name, 'apache-tomcat');
      expect(pkg.version, startsWith('10.'));
      expect(pkg.packageType, 'source');
      expect(pkg.purl, startsWith('pkg:generic/apache-tomcat@'));
    });

    test('mariadb → arch=x86_64, licence connue', () async {
      skipIfNoPy3();
      final pkg = await tarParser
          .parseTarFile('$_base/mariadb-11.4.8-linux-systemd-x86_64.tar.gz');
      expect(pkg, isNotNull);
      expect(pkg!.name, 'mariadb');
      expect(pkg.version, '11.4.8');
      expect(pkg.arch, 'x86_64');
      // MariaDB est sous GPL-2.0
      expect(pkg.license, isNotEmpty);
    });

    test('mongodb → nom=mongodb, arch=x86_64', () async {
      skipIfNoPy3();
      final pkg = await tarParser
          .parseTarFile('$_base/mongodb-linux-x86_64-rhel8-8.0.12.tgz');
      expect(pkg, isNotNull);
      expect(pkg!.name, 'mongodb');
      expect(pkg.version, '8.0.12');
      expect(pkg.arch, 'x86_64');
    });

    test('mongodb-database-tools → nom complet préservé', () async {
      skipIfNoPy3();
      final pkg = await tarParser.parseTarFile(
          '$_base/mongodb-database-tools-rhel88-x86_64-100.13.0.tgz');
      expect(pkg, isNotNull);
      expect(pkg!.name, 'mongodb-database-tools');
      expect(pkg.version, '100.13.0');
    });

    test('mongosh → arch=x86_64', () async {
      skipIfNoPy3();
      final pkg =
          await tarParser.parseTarFile('$_base/mongosh-2.5.6-linux-x64.tgz');
      expect(pkg, isNotNull);
      expect(pkg!.name, 'mongosh');
      expect(pkg.version, '2.5.6');
      expect(pkg.arch, 'x86_64');
    });
  });

  group('WheelParser — wheels Python 3PP', () {
    final whlParser = WheelParser();

    void skipIfNoPy3() {
      if (!py3) {
        markTestSkipped('python3 absent — test d\'intégration ignoré');
      }
    }

    test('requests wheel → métadonnées complètes', () async {
      skipIfNoPy3();
      const path = '$_base/python3/requests-2.32.5-py3-none-any.whl';
      if (!File(path).existsSync()) {
        markTestSkipped('fichier wheel absent');
        return;
      }
      final pkg = await whlParser.parseWheelFile(path);
      expect(pkg, isNotNull);
      expect(pkg!.name.toLowerCase(), 'requests');
      expect(pkg.version, isNotEmpty);
      expect(pkg.packageType, 'pypi');
      expect(pkg.purl, startsWith('pkg:pypi/requests@'));
    });

    test('glances wheel → WheelPackage valide', () async {
      skipIfNoPy3();
      const path = '$_base/python3/glances-4.5.3-py3-none-any.whl';
      if (!File(path).existsSync()) {
        markTestSkipped('fichier wheel absent');
        return;
      }
      final pkg = await whlParser.parseWheelFile(path);
      expect(pkg, isNotNull);
      expect(pkg!.name.toLowerCase(), 'glances');
      expect(pkg.purl, startsWith('pkg:pypi/glances@'));
    });
  });

  group('CycloneDX — génération sur liste mixte (smoke test)', () {
    test('bomRefs uniques pour tous les paquets exemple', () async {
      if (!py3) {
        markTestSkipped('python3 absent — test d\'intégration ignoré');
        return;
      }

      final tarParser = TarParser();
      final archives = [
        '$_base/apache-tomcat-10.1.44.tar.gz',
        '$_base/mariadb-11.4.8-linux-systemd-x86_64.tar.gz',
        '$_base/mongodb-linux-x86_64-rhel8-8.0.12.tgz',
        '$_base/mongodb-database-tools-rhel88-x86_64-100.13.0.tgz',
        '$_base/mongosh-2.5.6-linux-x64.tgz',
      ];

      final futures = archives.map(tarParser.parseTarFile).toList();
      final results = await Future.wait(futures);
      final packages = results.whereType<Package>().toList();

      // Tous les paquets ont été parsés
      expect(packages.length, archives.length);

      // Les bomRefs sont tous distincts
      final bomRefs = packages.map((p) => p.bomRef).toSet();
      expect(bomRefs.length, packages.length);

      // Les PURLs sont valides
      for (final pkg in packages) {
        expect(pkg.purl, startsWith('pkg:generic/'));
      }
    });
  });
}
