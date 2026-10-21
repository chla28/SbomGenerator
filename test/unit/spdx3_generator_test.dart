import 'dart:convert';

import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/schema_validator.dart';
import 'package:sbom_generator/spdx3_generator.dart';
import 'package:test/test.dart';

RpmPackage _pkg({
  required String name,
  String version = '1.0',
  String release = '1.el9',
  String license = 'MIT',
  String vendor = '',
  String url = '',
  String summary = '',
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
      summary: summary,
      requires: const [],
      provides: const [],
    );

List<Map<String, dynamic>> _graph(Map<String, dynamic> sbom) =>
    (sbom['@graph'] as List).cast<Map<String, dynamic>>();

Map<String, dynamic> _findType(Map<String, dynamic> sbom, String type) =>
    _graph(sbom).firstWhere((e) => e['type'] == type);

List<Map<String, dynamic>> _findAllType(
        Map<String, dynamic> sbom, String type) =>
    _graph(sbom).where((e) => e['type'] == type).toList();

void main() {
  final generator = Spdx3Generator();

  group('Spdx3Generator.generate — verifiedUsing', () {
    test('Package.hashes → verifiedUsing avec libellés HashAlgorithm', () {
      final pkg = WheelPackage(
        name: 'lib',
        version: '1.0',
        license: '',
        url: '',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: '',
        hashes: [PackageHash('SHA-256', 'a' * 64)],
        requires: const [],
        provides: const ['lib'],
        packageType: 'npm',
      );
      final elem = _findType(generator.generate([pkg], []), 'software_Package');
      expect(elem['verifiedUsing'], [
        {'type': 'Hash', 'algorithm': 'sha256', 'hashValue': 'a' * 64},
      ]);
    });

    test('aucun verifiedUsing sans hash', () {
      final elem = _findType(
          generator.generate([_pkg(name: 'foo')], []), 'software_Package');
      expect(elem.containsKey('verifiedUsing'), isFalse);
    });
  });

  group('Spdx3Generator.generate — enveloppe du document', () {
    test('produit un JSON-LD avec @context et @graph', () {
      final sbom = generator.generate([_pkg(name: 'foo')], []);
      expect(sbom['@context'], contains('spdx.org'));
      expect(sbom['@graph'], isA<List>());
    });

    test('contient un élément SpdxDocument avec le nom fourni', () {
      final sbom =
          generator.generate([_pkg(name: 'foo')], [], documentName: 'Mon SBOM');
      final doc = _findType(sbom, 'SpdxDocument');
      expect(doc['name'], 'Mon SBOM');
      expect(doc['profileConformance'], containsAll(['core', 'software']));
    });

    test('nom par défaut si non fourni', () {
      final sbom = generator.generate([_pkg(name: 'foo')], []);
      final doc = _findType(sbom, 'SpdxDocument');
      expect(doc['name'], 'Package Set SBOM');
    });

    test('contient un CreationInfo et un Tool', () {
      final sbom = generator.generate([_pkg(name: 'foo')], []);
      expect(_findAllType(sbom, 'CreationInfo'), hasLength(1));
      expect(_findAllType(sbom, 'Tool'), hasLength(1));
    });

    test('sdkTools → un Tool par SDK, référencé dans createdBy', () {
      final sbom = generator.generate([_pkg(name: 'foo')], [],
          sdkTools: {'flutter': '3.47.2', 'dart': '3.9.0'});
      final tools = _findAllType(sbom, 'Tool');
      expect(tools, hasLength(3));
      final byName = {for (final t in tools) t['name']: t};
      expect(byName['flutter']!['comment'], 'version 3.47.2');
      expect(byName['dart']!['comment'], 'version 3.9.0');
      final ci = _findType(sbom, 'CreationInfo');
      expect((ci['createdBy'] as List).length, 3);
    });
  });

  group('Spdx3Generator.generate — paquets', () {
    test('génère un software_Package par paquet avec purl', () {
      final sbom =
          generator.generate([_pkg(name: 'foo', version: '1.2.3')], []);
      final pkgs = _findAllType(sbom, 'software_Package');
      expect(pkgs, hasLength(1));
      final pkg = pkgs.single;
      expect(pkg['name'], 'foo');
      expect(pkg['software_packageVersion'], contains('1.2.3'));
      final ids = pkg['externalIdentifier'] as List;
      expect((ids.single as Map)['externalIdentifierType'], 'packageUrl');
      expect(pkg['software_packageUrl'], (ids.single as Map)['identifier']);
    });

    test('licence absente : aucune relation de licence', () {
      final sbom = generator.generate([_pkg(name: 'foo', license: '')], []);
      expect(_findAllType(sbom, 'simplelicensing_LicenseExpression'), isEmpty);
      expect(
          _findAllType(sbom, 'Relationship')
              .where((r) => '${r['relationshipType']}'.contains('License')),
          isEmpty);
    });

    test('licence : élément LicenseExpression partagé + relations has*License',
        () {
      final sbom = generator.generate([
        _pkg(name: 'foo', license: 'MIT'),
        _pkg(name: 'bar', license: 'MIT'),
      ], []);
      final lic = _findAllType(sbom, 'simplelicensing_LicenseExpression');
      expect(lic, hasLength(1));
      expect(lic.single['simplelicensing_licenseExpression'], 'MIT');
      final kinds = _findAllType(sbom, 'Relationship')
          .where((r) => '${r['relationshipType']}'.contains('License'))
          .map((r) => r['relationshipType'])
          .toList();
      expect(kinds.where((k) => k == 'hasConcludedLicense'), hasLength(2));
      expect(kinds.where((k) => k == 'hasDeclaredLicense'), hasLength(2));
    });

    test('le document généré satisfait le schéma officiel SPDX 3.0', () {
      final sbom = generator.generate([
        _pkg(name: 'foo', license: 'MIT', vendor: 'ACME', summary: 'x'),
        _pkg(name: 'bar'),
      ], [
        PackageDependency(sourceRef: 'foo', dependsOn: ['bar']),
      ]);
      // Aller-retour JSON : le validateur travaille sur le document décodé.
      final decoded = jsonDecode(jsonEncode(sbom)) as Map<String, dynamic>;
      expect(SchemaValidator.validate(decoded), isEmpty);
    });

    test('summary reporté si présent', () {
      final sbom =
          generator.generate([_pkg(name: 'foo', summary: 'Un paquet')], []);
      final pkg = _findAllType(sbom, 'software_Package').single;
      expect(pkg['summary'], 'Un paquet');
    });

    test('vendor produit un élément Organization référencé par suppliedBy', () {
      final sbom = generator.generate([_pkg(name: 'foo', vendor: 'ACME')], []);
      final orgs = _findAllType(sbom, 'Organization');
      expect(orgs, hasLength(1));
      expect(orgs.single['name'], 'ACME');
      final pkg = _findAllType(sbom, 'software_Package').single;
      expect(pkg['suppliedBy'], orgs.single['spdxId']);
    });

    test('deux paquets du même vendor partagent le même Organization', () {
      final sbom = generator.generate([
        _pkg(name: 'foo', vendor: 'ACME'),
        _pkg(name: 'bar', vendor: 'ACME'),
      ], []);
      expect(_findAllType(sbom, 'Organization'), hasLength(1));
    });
  });

  group('Spdx3Generator.generate — relations', () {
    test('une relation "describes" reliant le document aux paquets', () {
      final sbom =
          generator.generate([_pkg(name: 'foo'), _pkg(name: 'bar')], []);
      final describes = _findAllType(sbom, 'Relationship')
          .where((r) => r['relationshipType'] == 'describes')
          .toList();
      expect(describes, hasLength(1));
      expect((describes.single['to'] as List), hasLength(2));
    });

    test('les dépendances produisent des relations dependsOn', () {
      final foo = _pkg(name: 'foo');
      final bar = _pkg(name: 'bar');
      final deps = [
        PackageDependency(sourceRef: foo.bomRef, dependsOn: [bar.bomRef]),
      ];
      final sbom = generator.generate([foo, bar], deps);
      final dependsOn = _findAllType(sbom, 'Relationship')
          .where((r) => r['relationshipType'] == 'dependsOn')
          .toList();
      expect(dependsOn, hasLength(1));
    });

    test('une dépendance vers une ref inconnue est ignorée', () {
      final foo = _pkg(name: 'foo');
      final deps = [
        PackageDependency(sourceRef: foo.bomRef, dependsOn: ['inconnu']),
      ];
      final sbom = generator.generate([foo], deps);
      final dependsOn = _findAllType(sbom, 'Relationship')
          .where((r) => r['relationshipType'] == 'dependsOn');
      expect(dependsOn, isEmpty);
    });
  });

  group('Spdx3Generator.generate — élément OS de base (osInfo)', () {
    const os = OsInfo(
      id: 'redhat',
      version: '9.6',
      prettyName: 'Red Hat Enterprise Linux 9.6 (Plow)',
      cpe: 'cpe:/o:redhat:enterprise_linux:9::baseos',
    );

    test(
        'ajoute un élément software_Package avec '
        'software_primaryPurpose: operatingSystem', () {
      final sbom = generator.generate([_pkg(name: 'bash')], [], osInfo: os);
      final osElems = _findAllType(sbom, 'software_Package')
          .where((e) => e['software_primaryPurpose'] == 'operatingSystem')
          .toList();

      expect(osElems, hasLength(1));
      final elem = osElems.single;
      expect(elem['name'], 'redhat');
      expect(elem['software_packageVersion'], '9.6');
      expect(elem['summary'], os.prettyName);
    });

    test('inclut l\'élément OS dans rootElement et la relation describes', () {
      final sbom = generator.generate([_pkg(name: 'bash')], [], osInfo: os);
      final doc = _findType(sbom, 'SpdxDocument');
      final osSpdxId = _findAllType(sbom, 'software_Package').firstWhere(
          (e) => e['software_primaryPurpose'] == 'operatingSystem')['spdxId'];

      expect(doc['rootElement'], contains(osSpdxId));

      final describes = _findAllType(sbom, 'Relationship')
          .singleWhere((r) => r['relationshipType'] == 'describes');
      expect((describes['to'] as List), contains(osSpdxId));
    });

    test('aucun élément OS quand osInfo est absent', () {
      final sbom = generator.generate([_pkg(name: 'bash')], []);
      final osElems = _findAllType(sbom, 'software_Package')
          .where((e) => e['software_primaryPurpose'] == 'operatingSystem');
      expect(osElems, isEmpty);
    });
  });
}
