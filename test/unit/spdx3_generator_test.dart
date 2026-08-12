import 'package:sbom_generator/models.dart';
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

List<Map<String, dynamic>> _findAllType(Map<String, dynamic> sbom, String type) =>
    _graph(sbom).where((e) => e['type'] == type).toList();

void main() {
  final generator = Spdx3Generator();

  group('Spdx3Generator.generate — enveloppe du document', () {
    test('produit un JSON-LD avec @context et @graph', () {
      final sbom = generator.generate([_pkg(name: 'foo')], []);
      expect(sbom['@context'], contains('spdx.org'));
      expect(sbom['@graph'], isA<List>());
    });

    test('contient un élément SpdxDocument avec le nom fourni', () {
      final sbom = generator
          .generate([_pkg(name: 'foo')], [], documentName: 'Mon SBOM');
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
  });

  group('Spdx3Generator.generate — paquets', () {
    test('génère un software:Package par paquet avec purl', () {
      final sbom = generator.generate([_pkg(name: 'foo', version: '1.2.3')], []);
      final pkgs = _findAllType(sbom, 'software:Package');
      expect(pkgs, hasLength(1));
      final pkg = pkgs.single;
      expect(pkg['name'], 'foo');
      expect(pkg['software:packageVersion'], contains('1.2.3'));
      final ids = pkg['externalIdentifier'] as List;
      expect((ids.single as Map)['externalIdentifierType'], 'purl');
    });

    test('licence absente devient NOASSERTION', () {
      final sbom = generator.generate([_pkg(name: 'foo', license: '')], []);
      final pkg = _findAllType(sbom, 'software:Package').single;
      expect(pkg['concludedLicense'], 'NOASSERTION');
      expect(pkg['declaredLicense'], 'NOASSERTION');
    });

    test('summary reporté si présent', () {
      final sbom =
          generator.generate([_pkg(name: 'foo', summary: 'Un paquet')], []);
      final pkg = _findAllType(sbom, 'software:Package').single;
      expect(pkg['summary'], 'Un paquet');
    });

    test('vendor produit un élément Organization référencé par suppliedBy',
        () {
      final sbom = generator.generate([_pkg(name: 'foo', vendor: 'ACME')], []);
      final orgs = _findAllType(sbom, 'Organization');
      expect(orgs, hasLength(1));
      expect(orgs.single['name'], 'ACME');
      final pkg = _findAllType(sbom, 'software:Package').single;
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
      final sbom = generator
          .generate([_pkg(name: 'foo'), _pkg(name: 'bar')], []);
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
}
