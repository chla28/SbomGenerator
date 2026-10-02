import 'dart:convert';
import 'dart:io';

import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/nested_archive.dart';
import 'package:test/test.dart';

WheelPackage _jar(String name, String version, String ref) => WheelPackage(
      name: name,
      version: version,
      license: '',
      url: '',
      summary: '',
      vendor: '',
      arch: 'any',
      sourceRef: ref,
      requires: const [],
      provides: [name],
      packageType: 'maven',
    );

void main() {
  group('parseNestedDepth', () {
    test('entiers et all', () {
      expect(parseNestedDepth('0'), 0);
      expect(parseNestedDepth('2'), 2);
      expect(parseNestedDepth('all'), maxNestedDepth);
      expect(parseNestedDepth('ALL'), maxNestedDepth);
    });
    test('plafonne et rejette les valeurs invalides', () {
      expect(parseNestedDepth('999'), maxNestedDepth);
      expect(parseNestedDepth('-1'), isNull);
      expect(parseNestedDepth('abc'), isNull);
      expect(parseNestedDepth(''), isNull);
    });
  });

  group('sourceRef logique', () {
    test('profondeur et champs', () {
      expect(nestedDepthOf('a.rpm'), 0);
      expect(nestedDepthOf('a.rpm!/x/b.jar!/lib/c.jar'), 2);
      expect(nestedFields(_jar('a', '1', '/tmp/a.jar')), isEmpty);
      expect(nestedFields(_jar('a', '1', 'r.rpm!/x/a.jar')),
          {'location': 'r.rpm!/x/a.jar', 'depth': '1'});
    });

    test('copyWith(sourceRef) ne change que sourceRef', () {
      final p = _jar('a', '1', '/tmp/a.jar').copyWith(sourceRef: 'r!/a.jar');
      expect(p.sourceRef, 'r!/a.jar');
      expect(p.name, 'a');
      expect(p.bomRef, _jar('a', '1', 'x').bomRef);
    });
  });

  group('withNestedDependencies', () {
    test('arêtes parent → principal → relocalisés, manifeste → parent', () {
      final root = _jar('root', '1', 'r.rpm');
      final foo = _jar('foo', '1', 'r.rpm!/foo.jar');
      final shaded = _jar('shaded', '2', 'r.rpm!/foo.jar');
      final lockPkg = _jar('left-pad', '1', 'r.rpm!/package-lock.json');
      final objs = [
        NestedObject(
            location: 'r.rpm!/foo.jar',
            depth: 1,
            packages: [foo, shaded],
            parentRef: root.bomRef,
            isArchive: true),
        NestedObject(
            location: 'r.rpm!/package-lock.json',
            depth: 1,
            packages: [lockPkg],
            parentRef: root.bomRef,
            isArchive: false),
      ];
      final deps = withNestedDependencies([
        PackageDependency(sourceRef: root.bomRef, dependsOn: ['x'])
      ], objs);
      final m = {for (final d in deps) d.sourceRef: d.dependsOn};
      expect(m[root.bomRef], containsAll(['x', foo.bomRef, lockPkg.bomRef]));
      expect(m[foo.bomRef], [shaded.bomRef]);
    });
  });

  test('nestedFileBase : numéro, slug assaini', () {
    expect(nestedFileBase('out/sbom', 3, 12, 'a.rpm!/x/y z.jar'),
        'out/sbom.nested-03-y_z.jar');
    expect(nestedFileBase('b', 5, 1000, 'a.tgz!/c.jar'), 'b.nested-0005-c.jar');
  });

  group('NestedSbomIndex', () {
    late Directory tmp;
    setUp(() => tmp = Directory.systemTemp.createTempSync('nested_idx_'));
    tearDown(() => tmp.deleteSync(recursive: true));

    test('lit location, attribue les CVE, repli sur le nom', () {
      final f = File('${tmp.path}/s.cdx.json')
        ..writeAsStringSync(jsonEncode({
          'components': [
            {
              'name': 'baz',
              'version': '3.1',
              'properties': [
                {
                  'name': '${nestedPropertyPrefix}location',
                  'value': 'r.rpm!/a.jar!/baz.jar'
                },
              ],
            },
            {'name': 'root', 'version': '1'},
          ],
        }));
      final idx = NestedSbomIndex.load(f.path);
      expect(idx.isEmpty, isFalse);
      expect(idx.locationOf('baz@3.1'), 'r.rpm!/a.jar!/baz.jar');
      expect(idx.locationOf('baz@0:3.1'), 'r.rpm!/a.jar!/baz.jar');
      expect(idx.locationOf('root@1'), isNull);

      final vulns = <Map<String, dynamic>>[
        {'package': 'baz@3.1'},
        {'package': 'root@1'},
      ];
      expect(attributeNested(vulns, idx, 'r.rpm'), 1);
      expect(vulns[0]['container'], 'r.rpm!/a.jar!/baz.jar');
      expect(vulns[1]['container'], 'r.rpm');
    });

    test('SBOM sans propriété ou illisible → index vide', () {
      final f = File('${tmp.path}/x.json')..writeAsStringSync('pas du json');
      expect(NestedSbomIndex.load(f.path).isEmpty, isTrue);
    });
  });
}
