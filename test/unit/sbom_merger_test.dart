import 'package:sbom_generator/sbom_merger.dart';
import 'package:test/test.dart';

Map<String, dynamic> _cdx({
  String? name,
  List<Map<String, dynamic>> components = const [],
  List<Map<String, dynamic>> dependencies = const [],
}) =>
    {
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'metadata': {
        'component': {'name': name ?? 'doc'},
      },
      'components': components,
      if (dependencies.isNotEmpty) 'dependencies': dependencies,
    };

Map<String, dynamic> _comp(String name, {String purl = '', String ref = ''}) =>
    {
      'name': name,
      'version': '1.0',
      if (purl.isNotEmpty) 'purl': purl,
      if (ref.isNotEmpty) 'bom-ref': ref,
    };

Map<String, dynamic> _spdx({
  String? name,
  List<Map<String, dynamic>> packages = const [],
  List<Map<String, dynamic>> relationships = const [],
}) =>
    {
      'spdxVersion': 'SPDX-2.3',
      'name': name ?? 'doc',
      'dataLicense': 'CC0-1.0',
      'packages': packages,
      'relationships': relationships,
    };

Map<String, dynamic> _spdxPkg(String name, String spdxId, {String purl = ''}) =>
    {
      'SPDXID': spdxId,
      'name': name,
      'versionInfo': '1.0',
      'externalRefs': purl.isEmpty
          ? []
          : [
              {
                'referenceCategory': 'PACKAGE-MANAGER',
                'referenceType': 'purl',
                'referenceLocator': purl,
              }
            ],
    };

void main() {
  final merger = SbomMerger();

  group('SbomMerger.merge — cas génériques', () {
    test('lève une erreur si la liste est vide', () {
      expect(() => merger.merge([]), throwsArgumentError);
    });

    test('un seul SBOM est retourné tel quel', () {
      final sbom = _cdx(components: [_comp('foo')]);
      expect(merger.merge([sbom]), same(sbom));
    });
  });

  group('SbomMerger.merge — CycloneDX', () {
    test('fusionne les composants de deux SBOM sans doublon', () {
      final a = _cdx(components: [
        _comp('foo', purl: 'pkg:generic/foo@1.0'),
      ]);
      final b = _cdx(components: [
        _comp('bar', purl: 'pkg:generic/bar@1.0'),
      ]);
      final merged = merger.merge([a, b]);
      expect(merged['bomFormat'], 'CycloneDX');
      final components = merged['components'] as List;
      expect(components, hasLength(2));
    });

    test('déduplique par purl', () {
      final a = _cdx(components: [
        _comp('foo', purl: 'pkg:generic/foo@1.0'),
      ]);
      final b = _cdx(components: [
        _comp('foo', purl: 'pkg:generic/foo@1.0'),
      ]);
      final merged = merger.merge([a, b]);
      expect(merged['components'], hasLength(1));
    });

    test('déduplique par bom-ref si pas de purl', () {
      final a = _cdx(components: [_comp('foo', ref: 'ref-1')]);
      final b = _cdx(components: [_comp('foo', ref: 'ref-1')]);
      final merged = merger.merge([a, b]);
      expect(merged['components'], hasLength(1));
    });

    test('applique le nom de document fourni', () {
      final a = _cdx(name: 'A', components: [_comp('foo')]);
      final b = _cdx(name: 'B', components: [_comp('bar')]);
      final merged = merger.merge([a, b], documentName: 'Merged');
      expect(merged['metadata']['component']['name'], 'Merged');
    });

    test('fusionne les dépendances en dédupliquant par ref', () {
      final a = _cdx(
        components: [_comp('foo', ref: 'ref-1')],
        dependencies: [
          {
            'ref': 'ref-1',
            'dependsOn': ['ref-2']
          }
        ],
      );
      final b = _cdx(
        components: [_comp('foo', ref: 'ref-1')],
        dependencies: [
          {
            'ref': 'ref-1',
            'dependsOn': ['ref-2']
          }
        ],
      );
      final merged = merger.merge([a, b]);
      expect(merged['dependencies'], hasLength(1));
    });
  });

  group('SbomMerger.merge — SPDX 2.x', () {
    test('produit un document SPDX (pas CycloneDX)', () {
      final a = _spdx(packages: [_spdxPkg('foo', 'SPDXRef-foo')]);
      final b = _spdx(packages: [_spdxPkg('bar', 'SPDXRef-bar')]);
      final merged = merger.merge([a, b]);
      expect(merged['spdxVersion'], 'SPDX-2.3');
      expect(merged.containsKey('bomFormat'), isFalse);
      expect(merged['packages'], hasLength(2));
    });

    test('déduplique par purl', () {
      final a = _spdx(packages: [
        _spdxPkg('foo', 'SPDXRef-foo-a', purl: 'pkg:generic/foo@1.0'),
      ]);
      final b = _spdx(packages: [
        _spdxPkg('foo', 'SPDXRef-foo-b', purl: 'pkg:generic/foo@1.0'),
      ]);
      final merged = merger.merge([a, b]);
      expect(merged['packages'], hasLength(1));
    });

    test('déduplique par SPDXID si pas de purl', () {
      final a = _spdx(packages: [_spdxPkg('foo', 'SPDXRef-foo')]);
      final b = _spdx(packages: [_spdxPkg('foo', 'SPDXRef-foo')]);
      final merged = merger.merge([a, b]);
      expect(merged['packages'], hasLength(1));
    });

    test('fusionne les relations en dédupliquant les triples identiques', () {
      final rel = {
        'spdxElementId': 'SPDXRef-DOCUMENT',
        'relationshipType': 'DESCRIBES',
        'relatedSpdxElement': 'SPDXRef-foo',
      };
      final a = _spdx(
          packages: [_spdxPkg('foo', 'SPDXRef-foo')], relationships: [rel]);
      final b = _spdx(
          packages: [_spdxPkg('foo', 'SPDXRef-foo')], relationships: [rel]);
      final merged = merger.merge([a, b]);
      expect(merged['relationships'], hasLength(1));
    });

    test('applique le nom de document fourni', () {
      final a = _spdx(name: 'A', packages: [_spdxPkg('foo', 'SPDXRef-foo')]);
      final b = _spdx(name: 'B', packages: [_spdxPkg('bar', 'SPDXRef-bar')]);
      final merged = merger.merge([a, b], documentName: 'Merged');
      expect(merged['name'], 'Merged');
    });
  });
}
