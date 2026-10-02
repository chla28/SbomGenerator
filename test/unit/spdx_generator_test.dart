import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/spdx_generator.dart';
import 'package:test/test.dart';

RpmPackage _pkg({
  required String name,
  String version = '1.0',
  String release = '1.el9',
  String license = 'MIT',
  String vendor = '',
  String url = '',
}) =>
    RpmPackage(
      name: name,
      version: version,
      release: release,
      arch: 'x86_64',
      epoch: '(none)',
      license: license,
      vendor: vendor,
      url: url,
      buildTime: '',
      summary: '',
      requires: const [],
      provides: const [],
    );

void main() {
  final generator = SpdxGenerator();

  group('SpdxGenerator.generate — enveloppe du document', () {
    test('produit un document SPDX-2.3 valide', () {
      final sbom = generator.generate([_pkg(name: 'foo')], []);
      expect(sbom['spdxVersion'], 'SPDX-2.3');
      expect(sbom['SPDXID'], 'SPDXRef-DOCUMENT');
      expect(sbom['dataLicense'], 'CC0-1.0');
      expect(sbom['documentNamespace'], startsWith('https://sbom.local/spdx/'));
    });

    test('utilise le nom de document fourni', () {
      final sbom = generator.generate([_pkg(name: 'foo')], [],
          documentName: 'Mon SBOM');
      expect(sbom['name'], 'Mon SBOM');
    });

    test('nom par défaut si non fourni', () {
      final sbom = generator.generate([_pkg(name: 'foo')], []);
      expect(sbom['name'], 'Package Set SBOM');
    });

    test('sdkTools → creationInfo.creators "Tool: <nom>-<version>"', () {
      final sbom = generator.generate([_pkg(name: 'foo')], [],
          sdkTools: {'flutter': '3.47.2', 'dart': '3.9.0'});
      final creators =
          (sbom['creationInfo'] as Map)['creators'] as List<dynamic>;
      expect(creators, containsAll([
        'Tool: sbom_generator-1.6.0',
        'Tool: flutter-3.47.2',
        'Tool: dart-3.9.0',
      ]));
    });
  });

  group('SpdxGenerator.generate — paquets', () {
    test('génère un package par paquet, avec purl en externalRefs', () {
      final sbom = generator.generate([_pkg(name: 'foo', version: '1.2.3')], []);
      final packages = sbom['packages'] as List;
      expect(packages, hasLength(1));
      final pkg = packages.single as Map<String, dynamic>;
      expect(pkg['name'], 'foo');
      expect(pkg['versionInfo'], contains('1.2.3'));
      final refs = pkg['externalRefs'] as List;
      expect(refs, hasLength(1));
      expect((refs.single as Map)['referenceType'], 'purl');
    });

    test('licence normalisée en expression SPDX', () {
      final sbom = generator.generate(
          [_pkg(name: 'foo', license: 'MIT')], []);
      final pkg = (sbom['packages'] as List).single as Map<String, dynamic>;
      expect(pkg['licenseConcluded'], isNot('NOASSERTION'));
    });

    test('licence absente devient NOASSERTION', () {
      final sbom = generator.generate([_pkg(name: 'foo', license: '')], []);
      final pkg = (sbom['packages'] as List).single as Map<String, dynamic>;
      expect(pkg['licenseConcluded'], 'NOASSERTION');
      expect(pkg['licenseDeclared'], 'NOASSERTION');
    });

    test('downloadLocation NOASSERTION si url absente', () {
      final sbom = generator.generate([_pkg(name: 'foo', url: '')], []);
      final pkg = (sbom['packages'] as List).single as Map<String, dynamic>;
      expect(pkg['downloadLocation'], 'NOASSERTION');
    });

    test('downloadLocation utilise url si fournie', () {
      final sbom = generator
          .generate([_pkg(name: 'foo', url: 'https://example.org/foo')], []);
      final pkg = (sbom['packages'] as List).single as Map<String, dynamic>;
      expect(pkg['downloadLocation'], 'https://example.org/foo');
    });

    test('supplier: "Organization: <vendor>" si présent, sinon NOASSERTION', () {
      final withVendor = generator
          .generate([_pkg(name: 'foo', vendor: 'ACME')], []);
      final pkgWith =
          (withVendor['packages'] as List).single as Map<String, dynamic>;
      expect(pkgWith['supplier'], 'Organization: ACME');

      final withoutVendor = generator.generate([_pkg(name: 'foo')], []);
      final pkgWithout =
          (withoutVendor['packages'] as List).single as Map<String, dynamic>;
      expect(pkgWithout['supplier'], 'NOASSERTION');
    });

    test('checksums émis depuis Package.hashes, libellés SPDX', () {
      final pkg = WheelPackage(
        name: 'lib', version: '1.0', license: 'MIT', url: '', summary: '',
        vendor: '', arch: 'any', sourceRef: '',
        hashes: [PackageHash('SHA-256', 'a' * 64), PackageHash('SHA-512', 'b' * 128)],
        requires: const [], provides: const [], packageType: 'npm',
      );
      final p = (generator.generate([pkg], [])['packages'] as List)
          .single as Map<String, dynamic>;
      expect(p['checksums'], [
        {'algorithm': 'SHA256', 'checksumValue': 'a' * 64},
        {'algorithm': 'SHA512', 'checksumValue': 'b' * 128},
      ]);
    });

    test('pas de clé checksums si aucun hash', () {
      final p = (generator.generate([_pkg(name: 'foo')], [])['packages'] as List)
          .single as Map<String, dynamic>;
      expect(p.containsKey('checksums'), isFalse);
    });

    test('hash d\'en-tête RPM → annotation, jamais checksums', () {
      final pkg = RpmPackage(
        name: 'bash', version: '5.2', release: '1.el9', arch: 'x86_64',
        epoch: '(none)', license: 'GPL', vendor: '', url: '', buildTime: '',
        summary: '', requires: const [], provides: const [],
        headerSha256: 'f' * 64,
      );
      final p = (generator.generate([pkg], [])['packages'] as List)
          .single as Map<String, dynamic>;
      expect(p.containsKey('checksums'), isFalse);
      expect((p['annotations'] as List).first['comment'],
          contains('rpm:header-sha256=${'f' * 64}'));
    });
  });

  group('SpdxGenerator.generate — relations', () {
    test('une relation DESCRIBES par paquet', () {
      final sbom = generator
          .generate([_pkg(name: 'foo'), _pkg(name: 'bar')], []);
      final rels = (sbom['relationships'] as List)
          .cast<Map<String, dynamic>>()
          .where((r) => r['relationshipType'] == 'DESCRIBES')
          .toList();
      expect(rels, hasLength(2));
      expect(rels.every((r) => r['spdxElementId'] == 'SPDXRef-DOCUMENT'), isTrue);
    });

    test('les dépendances produisent des relations DEPENDS_ON', () {
      final foo = _pkg(name: 'foo');
      final bar = _pkg(name: 'bar');
      final deps = [
        PackageDependency(sourceRef: foo.bomRef, dependsOn: [bar.bomRef]),
      ];
      final sbom = generator.generate([foo, bar], deps);
      final dependsOn = (sbom['relationships'] as List)
          .cast<Map<String, dynamic>>()
          .where((r) => r['relationshipType'] == 'DEPENDS_ON')
          .toList();
      expect(dependsOn, hasLength(1));
      expect(dependsOn.single['spdxElementId'], foo.spdxId);
      expect(dependsOn.single['relatedSpdxElement'], bar.spdxId);
    });

    test('une dépendance vers une ref inconnue est ignorée', () {
      final foo = _pkg(name: 'foo');
      final deps = [
        PackageDependency(sourceRef: foo.bomRef, dependsOn: ['inconnu']),
      ];
      final sbom = generator.generate([foo], deps);
      final dependsOn = (sbom['relationships'] as List)
          .cast<Map<String, dynamic>>()
          .where((r) => r['relationshipType'] == 'DEPENDS_ON');
      expect(dependsOn, isEmpty);
    });
  });

  group('SpdxGenerator.generate — paquet OS de base (osInfo)', () {
    const os = OsInfo(
      id: 'redhat',
      version: '9.6',
      prettyName: 'Red Hat Enterprise Linux 9.6 (Plow)',
      cpe: 'cpe:/o:redhat:enterprise_linux:9::baseos',
    );

    test(
        'ajoute un paquet primaryPackagePurpose: OPERATING-SYSTEM avec un '
        'SPDXID préfixé SPDXRef-OperatingSystem-', () {
      final sbom = generator.generate([_pkg(name: 'bash')], [], osInfo: os);
      final packages = (sbom['packages'] as List).cast<Map<String, dynamic>>();

      final osPkg = packages.firstWhere(
          (p) => p['primaryPackagePurpose'] == 'OPERATING-SYSTEM');
      // Le préfixe SPDXRef-OperatingSystem- (et non SPDXRef-Package-) est
      // ce que Trivy reconnaît pour la classe "os-pkgs" en mode
      // `trivy sbom` — vérifié empiriquement, voir spdx_generator.dart.
      expect(osPkg['SPDXID'], startsWith('SPDXRef-OperatingSystem-'));
      expect(osPkg['name'], 'redhat');
      expect(osPkg['versionInfo'], '9.6');
      expect(osPkg['summary'], os.prettyName);
      expect(packages.length, 2); // OS + 1 paquet
    });

    test('ajoute une relation DESCRIBES vers le paquet OS', () {
      final sbom = generator.generate([_pkg(name: 'bash')], [], osInfo: os);
      final packages =
          (sbom['packages'] as List).cast<Map<String, dynamic>>();
      final osSpdxId = packages
          .firstWhere((p) => p['primaryPackagePurpose'] == 'OPERATING-SYSTEM')
          ['SPDXID'];

      final describes = (sbom['relationships'] as List)
          .cast<Map<String, dynamic>>()
          .where((r) =>
              r['relationshipType'] == 'DESCRIBES' &&
              r['relatedSpdxElement'] == osSpdxId);
      expect(describes, hasLength(1));
    });

    test('aucun paquet OS quand osInfo est absent', () {
      final sbom = generator.generate([_pkg(name: 'bash')], []);
      final packages = (sbom['packages'] as List).cast<Map<String, dynamic>>();
      expect(
          packages.any((p) => p['primaryPackagePurpose'] == 'OPERATING-SYSTEM'),
          isFalse);
      expect(packages.length, 1);
    });
  });
}
