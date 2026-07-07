import 'package:sbom_generator/cyclonedx_generator.dart';
import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/sbom_reader.dart';
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
}
