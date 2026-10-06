import 'package:sbom_generator/sbom_diff.dart';
import 'package:test/test.dart';

Map<String, dynamic> _cdx(List<Map<String, dynamic>> components) => {
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'components': components,
    };

Map<String, dynamic> _comp({
  required String name,
  required String version,
  String purl = '',
  String type = 'library',
}) =>
    {'name': name, 'version': version, 'purl': purl, 'type': type};

Map<String, dynamic> _spdx(List<Map<String, dynamic>> packages) => {
      'spdxVersion': 'SPDX-2.3',
      'name': 'doc',
      'packages': packages,
    };

Map<String, dynamic> _spdxPkg({
  required String name,
  required String version,
  String purl = '',
}) =>
    {
      'name': name,
      'versionInfo': version,
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

Map<String, dynamic> _spdx3(List<Map<String, dynamic>> packages) => {
      '@context': 'https://spdx.org/rdf/3.0.0/spdx-context.jsonld',
      '@graph': [
        {'type': 'SpdxDocument', 'name': 'doc'},
        ...packages,
      ],
    };

Map<String, dynamic> _spdx3Pkg({
  required String name,
  required String version,
  String purl = '',
}) =>
    {
      'type': 'software:Package',
      'name': name,
      'software:packageVersion': version,
      'externalIdentifier': purl.isEmpty
          ? []
          : [
              {'externalIdentifierType': 'purl', 'identifier': purl}
            ],
    };

void main() {
  final differ = SbomDiffer();

  group('SbomDiffer.diff — CycloneDX', () {
    test('aucun changement si les deux documents sont identiques', () {
      final before = _cdx([
        _comp(name: 'foo', version: '1.0', purl: 'pkg:generic/foo@1.0'),
      ]);
      final after = _cdx([
        _comp(name: 'foo', version: '1.0', purl: 'pkg:generic/foo@1.0'),
      ]);
      final result = differ.diff(before, after);
      expect(result.isEmpty, isTrue);
    });

    test('détecte un ajout', () {
      final before = _cdx([]);
      final after = _cdx([
        _comp(name: 'foo', version: '1.0', purl: 'pkg:generic/foo@1.0'),
      ]);
      final result = differ.diff(before, after);
      expect(result.added, hasLength(1));
      expect(result.added.single.name, 'foo');
      expect(result.removed, isEmpty);
      expect(result.updated, isEmpty);
    });

    test('détecte une suppression', () {
      final before = _cdx([
        _comp(name: 'foo', version: '1.0', purl: 'pkg:generic/foo@1.0'),
      ]);
      final after = _cdx([]);
      final result = differ.diff(before, after);
      expect(result.removed, hasLength(1));
      expect(result.removed.single.name, 'foo');
    });

    test('détecte une mise à jour de version (même purl sans version)', () {
      final before = _cdx([
        _comp(name: 'foo', version: '1.0', purl: 'pkg:generic/foo@1.0'),
      ]);
      final after = _cdx([
        _comp(name: 'foo', version: '2.0', purl: 'pkg:generic/foo@2.0'),
      ]);
      final result = differ.diff(before, after);
      expect(result.added, isEmpty);
      expect(result.removed, isEmpty);
      expect(result.updated, hasLength(1));
      expect(result.updated.single.oldVersion, '1.0');
      expect(result.updated.single.newVersion, '2.0');
    });

    test('sans purl, la clé retombe sur "name:type"', () {
      final before = _cdx([_comp(name: 'foo', version: '1.0')]);
      final after = _cdx([_comp(name: 'foo', version: '2.0')]);
      final result = differ.diff(before, after);
      expect(result.updated, hasLength(1));
    });

    test('deux paquets de types différents avec le même nom ne fusionnent pas',
        () {
      final before =
          _cdx([_comp(name: 'foo', version: '1.0', type: 'library')]);
      final after =
          _cdx([_comp(name: 'foo', version: '1.0', type: 'application')]);
      final result = differ.diff(before, after);
      expect(result.added, hasLength(1));
      expect(result.removed, hasLength(1));
    });

    test('les composants sans nom sont ignorés', () {
      final before = _cdx([_comp(name: '', version: '1.0')]);
      final after = _cdx([_comp(name: '', version: '2.0')]);
      final result = differ.diff(before, after);
      expect(result.isEmpty, isTrue);
    });
  });

  group('SbomDiffer.diff — SPDX 2.x', () {
    test('détecte ajout/suppression/mise à jour via externalRefs purl', () {
      final before = _spdx([
        _spdxPkg(name: 'foo', version: '1.0', purl: 'pkg:generic/foo@1.0'),
        _spdxPkg(name: 'bar', version: '1.0', purl: 'pkg:generic/bar@1.0'),
      ]);
      final after = _spdx([
        _spdxPkg(name: 'foo', version: '2.0', purl: 'pkg:generic/foo@2.0'),
        _spdxPkg(name: 'baz', version: '1.0', purl: 'pkg:generic/baz@1.0'),
      ]);
      final result = differ.diff(before, after);
      expect(result.updated, hasLength(1));
      expect(result.updated.single.name, 'foo');
      expect(result.added.single.name, 'baz');
      expect(result.removed.single.name, 'bar');
    });
  });

  group('SbomDiffer.diff — SPDX 3.0 JSON-LD', () {
    test('détecte les changements via externalIdentifier purl', () {
      final before = _spdx3([
        _spdx3Pkg(name: 'foo', version: '1.0', purl: 'pkg:generic/foo@1.0'),
      ]);
      final after = _spdx3([
        _spdx3Pkg(name: 'foo', version: '2.0', purl: 'pkg:generic/foo@2.0'),
      ]);
      final result = differ.diff(before, after);
      expect(result.updated, hasLength(1));
    });

    test('ignore les éléments du graphe qui ne sont pas des paquets', () {
      final before = _spdx3([]);
      final after = _spdx3([
        _spdx3Pkg(name: 'foo', version: '1.0'),
      ]);
      final result = differ.diff(before, after);
      expect(result.added, hasLength(1));
    });
  });

  group('SbomDiffer.diff — métadonnées enrichies', () {
    Map<String, dynamic> comp(String v,
            {String lic = 'MIT',
            String hash = 'aa',
            String layer = '1',
            String supplier = 'ACME'}) =>
        {
          'type': 'library',
          'name': 'foo',
          'version': v,
          'purl': 'pkg:generic/foo@$v',
          'licenses': [
            {
              'license': {'id': lic}
            }
          ],
          'hashes': [
            {'alg': 'SHA-256', 'content': hash}
          ],
          'supplier': {'name': supplier},
          'properties': [
            {'name': 'sbom_generator:layer:index', 'value': layer}
          ],
        };

    test('même version, licence et empreinte changées → « modifié »', () {
      final r = differ.diff(_cdx([comp('1.0')]),
          _cdx([comp('1.0', lic: 'GPL-3.0-only', hash: 'bb')]));
      expect(r.updated, isEmpty);
      expect(r.modified, hasLength(1));
      expect(r.modified.single.changes['license'], ('MIT', 'GPL-3.0-only'));
      expect(r.modified.single.changes['hashes'], ('SHA-256:aa', 'SHA-256:bb'));
      expect(r.isEmpty, isFalse);
    });

    test('version changée : licence/couche signalées, empreintes ignorées', () {
      final r = differ.diff(_cdx([comp('1.0')]),
          _cdx([comp('2.0', hash: 'zz', layer: '3', supplier: 'Autre')]));
      expect(r.modified, isEmpty);
      final c = r.updated.single.changes;
      expect(c.keys, containsAll(['layer', 'supplier']));
      expect(c.containsKey('hashes'), isFalse);
      expect(c['layer'], ('1', '3'));
    });

    test('SPDX 2 : licence et couche (annotation)', () {
      Map<String, dynamic> p(String lic, String idx) => {
            'name': 'foo',
            'versionInfo': '1.0',
            'licenseConcluded': lic,
            'annotations': [
              {'comment': 'x; sbom_generator:layer:index=$idx'}
            ],
          };
      final r =
          differ.diff(_spdx([p('MIT', '1')]), _spdx([p('NOASSERTION', '2')]));
      expect(r.modified.single.changes['license'], ('MIT', ''));
      expect(r.modified.single.changes['layer'], ('1', '2'));
    });

    test('identiques → vide ; toJson expose « modified »', () {
      expect(differ.diff(_cdx([comp('1.0')]), _cdx([comp('1.0')])).isEmpty,
          isTrue);
      final r = differ.diff(_cdx([comp('1.0')]), _cdx([comp('1.0', lic: 'X')]));
      final j = differ.toJson(r);
      expect(j['summary']['modified'], 1);
      expect(j['modified'].single['changes']['license']['after'], 'X');
    });
  });

  group('SbomDiffer.diff — couches', () {
    Map<String, dynamic> withLayers(List<(String, int)> layers) => {
          'bomFormat': 'CycloneDX',
          'metadata': {
            'component': {
              'properties': [
                {'name': 'sbom_generator:layers:mode', 'value': 'metadata'},
                for (var i = 0; i < layers.length; i++)
                  {
                    'name':
                        'sbom_generator:layers:${(i + 1).toString().padLeft(3, '0')}',
                    'value':
                        '{"digest":"sha256:${layers[i].$1.padRight(64, '0')}","added":${layers[i].$2},"modified":0,"removed":0}',
                  },
              ],
            },
          },
          'components': [],
        };

    test('couche ajoutée, supprimée et modifiée', () {
      final r = differ.diff(
        withLayers([('aaaa', 3), ('bbbb', 2)]),
        withLayers([('aaaa', 3), ('bbbb', 5), ('cccc', 1)]),
      );
      final l = r.layers!;
      expect((l.beforeCount, l.afterCount), (2, 3));
      expect(l.added, hasLength(1));
      expect(l.removed, isEmpty);
      expect(l.changed.values.single, ('+2 ~0 -0', '+5 ~0 -0'));
      expect(r.isEmpty, isFalse);
    });

    test('SBOM sans couches : layers == null', () {
      expect(differ.diff(_cdx([]), _cdx([])).layers, isNull);
    });
  });

  group('SbomDiffer.toJson', () {
    test('résume correctement les compteurs', () {
      final before = _cdx([_comp(name: 'a', version: '1.0')]);
      final after = _cdx([_comp(name: 'b', version: '1.0')]);
      final result = differ.diff(before, after);
      final json = differ.toJson(result);
      expect(json['summary']['added'], 1);
      expect(json['summary']['removed'], 1);
      expect(json['summary']['total_changes'], 2);
    });
  });
}
