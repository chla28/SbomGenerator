import 'package:sbom_generator/cyclonedx_generator.dart';
import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/sbom_reader.dart';
import 'package:sbom_generator/spdx3_generator.dart';
import 'package:sbom_generator/spdx_generator.dart';
import 'package:test/test.dart';

void main() {
  group('SbomReader — composants Maven (group/name)', () {
    test('recombine group + name en "groupId:artifactId" à la relecture', () {
      final maven = WheelPackage(
        name: 'com.sun.xml.fastinfoset:FastInfoset',
        version: '1.2.15',
        license: '',
        url: '',
        summary: '',
        vendor: 'com.sun.xml.fastinfoset',
        arch: 'any',
        sourceRef: 'FastInfoset-1.2.15.jar',
        requires: const [],
        provides: const ['com.sun.xml.fastinfoset:FastInfoset'],
        packageType: 'maven',
      );

      final sbom = CycloneDxGenerator().generate([maven], []);
      // Vérifie que le générateur a bien émis group+name séparément (et pas
      // "groupId:artifactId" dans name) — sinon ce test ne prouverait rien.
      final rawComponent = (sbom['components'] as List).single as Map;
      expect(rawComponent['group'], 'com.sun.xml.fastinfoset');
      expect(rawComponent['name'], 'FastInfoset');

      final packages = SbomReader().read(sbom);
      expect(packages, hasLength(1));
      expect(packages.single.name, 'com.sun.xml.fastinfoset:FastInfoset');
      expect(packages.single.packageType, 'maven');
      expect(packages.single.purl,
          'pkg:maven/com.sun.xml.fastinfoset/FastInfoset@1.2.15');
    });

    test('ne préfixe pas le name pour un composant non-Maven sans group', () {
      final rpm = RpmPackage(
        name: 'bash',
        version: '5.1.8',
        release: '6.el9',
        arch: 'x86_64',
        epoch: '(none)',
        license: 'GPL-3.0-or-later',
        vendor: '',
        url: '',
        buildTime: '',
        summary: '',
        requires: const [],
        provides: const [],
      );

      final sbom = CycloneDxGenerator().generate([rpm], []);
      final packages = SbomReader().read(sbom);
      expect(packages.single.name, 'bash');
    });
  });

  group('SbomReader — licences declared/concluded', () {
    test(
        'relit la licence brute complète (entrée "declared") même quand le '
        'générateur a éclaté la licence composée en plusieurs entrées '
        '"concluded"', () {
      final pkg = RpmPackage(
        name: 'foo',
        version: '1.0',
        release: '1',
        arch: 'x86_64',
        epoch: '(none)',
        license: 'GPL-2.0-or-later and BSD-3-Clause and curl',
        vendor: '',
        url: '',
        buildTime: '',
        summary: '',
        requires: const [],
        provides: const [],
      );

      final sbom = CycloneDxGenerator().generate([pkg], []);
      final rawComponent = (sbom['components'] as List).single as Map;
      final licenses = rawComponent['licenses'] as List;
      // Une entrée "declared" (licence brute) + une "concluded" par
      // licence individuelle du AND (GPL-2.0-or-later, BSD-3-Clause, curl).
      expect(licenses, hasLength(4));

      final packages = SbomReader().read(sbom);
      expect(packages.single.license,
          'GPL-2.0-or-later and BSD-3-Clause and curl');
    });

    test('relit une licence simple (non composée) sans changement', () {
      final pkg = RpmPackage(
        name: 'bar',
        version: '1.0',
        release: '1',
        arch: 'x86_64',
        epoch: '(none)',
        license: 'MIT',
        vendor: '',
        url: '',
        buildTime: '',
        summary: '',
        requires: const [],
        provides: const [],
      );

      final sbom = CycloneDxGenerator().generate([pkg], []);
      final packages = SbomReader().read(sbom);
      expect(packages.single.license, 'MIT');
    });
  });

  group('SbomReader — round-trip SPDX 3.0', () {
    final npm = WheelPackage(
      name: 'lodash', version: '4.17.21', license: 'MIT',
      url: 'https://example.test/lodash', summary: 'util',
      vendor: '', arch: 'any', sourceRef: '',
      hashes: [PackageHash('SHA-512', 'b' * 128)],
      requires: const [], provides: const ['lodash'], packageType: 'npm',
    );

    test('relit les éléments software:Package (nom, version, purl, licence)', () {
      final sbom = Spdx3Generator().generate([npm], []);
      final pkgs = SbomReader().read(sbom);
      expect(pkgs, hasLength(1));
      final p = pkgs.single;
      expect(p.name, 'lodash');
      expect(p.fullVersion, '4.17.21');
      expect(p.purl, 'pkg:npm/lodash@4.17.21');
      expect(p.packageType, 'npm');
      expect(p.license, 'MIT');
    });

    test('relit verifiedUsing → Package.hashes', () {
      final sbom = Spdx3Generator().generate([npm], []);
      expect(SbomReader().read(sbom).single.hashes,
          [PackageHash('SHA-512', 'b' * 128)]);
    });

    test('licence NOASSERTION relue comme vide', () {
      final bare = WheelPackage(
        name: 'x', version: '1', license: '', url: '', summary: '',
        vendor: '', arch: 'any', sourceRef: '',
        requires: const [], provides: const ['x'], packageType: 'npm',
      );
      final sbom = Spdx3Generator().generate([bare], []);
      expect(SbomReader().read(sbom).single.license, '');
    });

    test('round-trip SPDX 3.0 → SPDX 2.3 conserve les checksums', () {
      final spdx3 = Spdx3Generator().generate([npm], []);
      final spdx2 =
          SpdxGenerator().generate(SbomReader().read(spdx3), []);
      final p = (spdx2['packages'] as List)
          .cast<Map<String, dynamic>>()
          .firstWhere((e) => e['name'] == 'lodash');
      expect(p['checksums'], [
        {'algorithm': 'SHA512', 'checksumValue': 'b' * 128},
      ]);
    });
  });
}
