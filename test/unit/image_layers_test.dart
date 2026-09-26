import 'dart:convert';
import 'dart:io';

import 'package:sbom_generator/csv_generator.dart';
import 'package:sbom_generator/cyclonedx_generator.dart';
import 'package:sbom_generator/image_layers.dart';
import 'package:sbom_generator/markdown_generator.dart';
import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/oci_parser.dart';
import 'package:sbom_generator/simple_json_generator.dart';
import 'package:sbom_generator/spdx_generator.dart';
import 'package:test/test.dart';

OciPackage _apk(String name, String version,
        {String license = 'MIT', String arch = 'x86_64'}) =>
    OciPackage(
      name: name,
      version: version,
      license: license,
      vendor: '',
      url: '',
      summary: '',
      arch: arch,
      sourceRef: 'img',
      imageRef: 'img',
      requires: const [],
      provides: [name],
      packageType: 'apk',
    );

const _d1 = 'sha256:1111111111111111111111111111111111111111111111111111111111111111';
const _d2 = 'sha256:2222222222222222222222222222222222222222222222222222222222222222';
const _d3 = 'sha256:3333333333333333333333333333333333333333333333333333333333333333';

void main() {
  group('layersFromConfig', () {
    test('ignore les entrées history empty_layer', () {
      final layers = layersFromConfig([_d1, _d2], [
        {'created_by': 'ADD rootfs.tar /'},
        {'created_by': 'ENV A=1', 'empty_layer': true},
        {'created_by': 'RUN apk add curl'},
      ]);
      expect(layers.map((l) => l.index), [1, 2]);
      expect(layers[0].createdBy, 'ADD rootfs.tar /');
      expect(layers[1].createdBy, 'RUN apk add curl');
      expect(layers[1].shortDigest, '222222222222');
    });

    test('history incohérent : pas d\'instruction', () {
      final layers = layersFromConfig([_d1, _d2], [
        {'created_by': 'seul'},
      ]);
      expect(layers.every((l) => l.createdBy == null), isTrue);
    });
  });

  group('lecture des couches', () {
    late Directory tmp;
    setUp(() => tmp = Directory.systemTemp.createTempSync('layers_read_'));
    tearDown(() => tmp.deleteSync(recursive: true));

    test('docker-archive : manifest.json + config', () {
      File('${tmp.path}/cfg.json').writeAsStringSync(jsonEncode({
        'rootfs': {'diff_ids': [_d1, _d2]},
        'history': [
          {'created_by': 'base'},
          {'created_by': 'app'},
        ],
      }));
      File('${tmp.path}/manifest.json').writeAsStringSync(jsonEncode([
        {
          'Config': 'cfg.json',
          'Layers': ['a/layer.tar', 'b/layer.tar'],
        }
      ]));
      final layers = readDockerArchiveLayers(tmp.path);
      expect(layers.map((l) => l.diffId), [_d1, _d2]);
      expect(layers[1].blobPath, '${tmp.path}/b/layer.tar');
      expect(layers[1].createdBy, 'app');
    });

    test('layout OCI : index → manifeste amd64 → couches', () {
      void blob(String digest, Object json) {
        final f = File('${tmp.path}/blobs/${digest.replaceFirst(':', '/')}')
          ..createSync(recursive: true);
        f.writeAsStringSync(jsonEncode(json));
      }

      blob(_d3, {
        'config': {'digest': 'sha256:cfg'},
        'layers': [
          {'digest': 'sha256:aaa'},
        ],
      });
      blob('sha256:cfg', {
        'rootfs': {'diff_ids': [_d1]},
      });
      File('${tmp.path}/index.json').writeAsStringSync(jsonEncode({
        'manifests': [
          {
            'digest': 'sha256:arm',
            'platform': {'os': 'linux', 'architecture': 'arm64'},
          },
          {
            'digest': _d3,
            'platform': {'os': 'linux', 'architecture': 'amd64'},
          },
        ],
      }));
      final layers = readOciLayoutLayers(tmp.path);
      expect(layers.single.diffId, _d1);
      expect(layers.single.blobPath, '${tmp.path}/blobs/sha256/aaa');
    });
  });

  group('mergeLayerDir', () {
    late Directory tmp;
    late String root;
    late String layer;
    setUp(() {
      tmp = Directory.systemTemp.createTempSync('layers_merge_');
      root = '${tmp.path}/root';
      layer = '${tmp.path}/layer';
      Directory(root).createSync();
      Directory(layer).createSync();
    });
    tearDown(() => tmp.deleteSync(recursive: true));

    void write(String path, String content) =>
        (File(path)..createSync(recursive: true)).writeAsStringSync(content);

    test('whiteout, répertoire opaque et remplacement', () {
      write('$root/etc/keep', 'k');
      write('$root/etc/gone', 'g');
      write('$root/opt/old/a', 'a');
      write('$root/etc/over', 'v1');

      write('$layer/etc/.wh.gone', '');
      write('$layer/etc/over', 'v2');
      write('$layer/opt/old/.wh..wh..opq', '');
      write('$layer/opt/old/b', 'b');
      mergeLayerDir(layer, root);

      expect(File('$root/etc/keep').existsSync(), isTrue);
      expect(File('$root/etc/gone').existsSync(), isFalse);
      expect(File('$root/etc/over').readAsStringSync(), 'v2');
      expect(File('$root/opt/old/a').existsSync(), isFalse);
      expect(File('$root/opt/old/b').existsSync(), isTrue);
      expect(File('$root/etc/.wh.gone').existsSync(), isFalse);
    });

    test('un lien symbolique d\'une couche n\'ouvre pas de chemin hors du rootfs',
        () {
      final outside = Directory('${tmp.path}/outside')..createSync();
      Link('$root/evil').createSync(outside.path);
      write('$layer/evil/pwned', 'x');
      mergeLayerDir(layer, root);
      expect(File('${outside.path}/pwned').existsSync(), isFalse);
      expect(File('$root/evil/pwned').existsSync(), isTrue);
    });
  });

  group('diffPackages', () {
    test('ajout, suppression, montée de version, changement de licence', () {
      final before = [
        _apk('musl', '1.0'),
        _apk('zlib', '1.2'),
        _apk('busybox', '1.36'),
      ];
      final after = [
        _apk('musl', '1.0', license: 'MIT OR Apache-2.0'),
        _apk('zlib', '1.3'),
        _apk('curl', '8.0'),
      ];
      final d = diffPackages(before, after);
      expect(d.added.map((p) => p.name), ['curl']);
      expect(d.removed.map((p) => p.name), ['busybox']);
      expect(d.modified.map((m) => '${m.before.version}>${m.after.version}'),
          unorderedEquals(['1.0>1.0', '1.2>1.3']));
      expect(d.packages.map((p) => p.name),
          unorderedEquals(['curl', 'musl', 'zlib']));
    });

    test('plusieurs versions d\'un même nom : pas d\'appariement', () {
      final d = diffPackages(
        [_apk('lodash', '4.0')],
        [_apk('lodash', '4.1'), _apk('lodash', '3.0')],
      );
      expect(d.modified, isEmpty);
      expect(d.added, hasLength(2));
      expect(d.removed, hasLength(1));
    });

    test('état identique : delta vide', () {
      final l = [_apk('musl', '1.0')];
      expect(diffPackages(l, [_apk('musl', '1.0')]).isEmpty, isTrue);
    });
  });

  group('LayerAnalysis', () {
    final layers = layersFromConfig([_d1, _d2, _d3], null);

    test('origins : couche d\'introduction et couches de modification', () {
      final analysis = LayerAnalysis(mode: 'rootfs', layers: layers, deltas: [
        LayerDelta.addedOnly([_apk('zlib', '1.2'), _apk('musl', '1.0')]),
        LayerDelta(
          added: const [],
          modified: [(before: _apk('zlib', '1.2'), after: _apk('zlib', '1.3'))],
          removed: [_apk('musl', '1.0')],
        ),
        LayerDelta.addedOnly([_apk('curl', '8.0')]),
      ]);
      final o = analysis.origins();
      expect(o.keys, unorderedEquals([
        _apk('zlib', '1.3').bomRef,
        _apk('curl', '8.0').bomRef,
      ]));
      final zlib = o[_apk('zlib', '1.3').bomRef]!;
      expect(zlib.index, 1);
      expect(zlib.modifiedBy, [2]);
      expect(o[_apk('curl', '8.0').bomRef]!.index, 3);
    });

    test('metadataLayerAnalysis : répartition par couche d\'origine', () {
      final pkgs = [_apk('a', '1'), _apk('b', '1'), _apk('c', '1')];
      final a = metadataLayerAnalysis(layers, {
        pkgs[0].bomRef: 1,
        pkgs[1].bomRef: 3,
      }, pkgs);
      expect(a.deltas.map((d) => d.added.length), [1, 0, 1]);
      expect(a.origins().length, 2);
    });

    test('map applique la transformation à tous les composants', () {
      final a = LayerAnalysis(mode: 'rootfs', layers: layers.take(1).toList(),
          deltas: [
            LayerDelta(
              added: [_apk('a', '1')],
              modified: [(before: _apk('b', '1'), after: _apk('b', '2'))],
              removed: [_apk('c', '1')],
            ),
          ]).map((p) => p.copyWith(license: 'X'));
      final d = a.deltas.single;
      expect([...d.added, d.modified.single.after, ...d.removed]
          .every((p) => p.license == 'X'), isTrue);
    });
  });

  test('layerFileBase : index sur deux chiffres minimum', () {
    final l = layersFromConfig([_d2], null).single;
    expect(layerFileBase('out/app', l, 3), 'out/app.layer-01-222222222222');
    expect(layerFileBase('app', l, 120), 'app.layer-001-222222222222');
  });

  group('attribution par le backend', () {
    test('trivy : Layer.DiffID', () {
      final r = ociParserTrivyLayerAttribution({
        'Metadata': {
          'DiffIDs': [_d1, _d2],
          'ImageConfig': {
            'history': [
              {'created_by': 'ADD base'},
              {'created_by': 'RUN apk add curl'},
            ],
          },
        },
        'Results': [
          {
            'Type': 'alpine',
            'Packages': [
              {'Name': 'musl', 'Version': '1.0', 'Layer': {'DiffID': _d1}},
              {'Name': 'curl', 'Version': '8.0', 'Layer': {'DiffID': _d2}},
            ],
          },
        ],
      }, 'img');
      expect(r.layers.map((l) => l.createdBy),
          ['ADD base', 'RUN apk add curl']);
      expect(r.layerOf.values, unorderedEquals([1, 2]));
    });

    test('syft all-layers : couche la plus basse où le paquet apparaît', () {
      final cfg = base64.encode(utf8.encode(jsonEncode({
        'history': [
          {'created_by': 'base'},
          {'created_by': 'dnf install'},
        ],
      })));
      Map<String, dynamic> art(String name, List<String> layerIds) => {
            'name': name,
            'version': '1.0',
            'type': 'rpm',
            'purl': 'pkg:rpm/fedora/$name@1.0',
            'locations': [
              for (final l in layerIds) {'path': '/rpmdb', 'layerID': l},
            ],
          };
      final r = ociParserSyftLayerAttribution({
        'source': {
          'metadata': {
            'layers': [
              {'digest': _d1},
              {'digest': _d2},
            ],
            'config': cfg,
          },
        },
        'artifacts': [
          art('bash', [_d2, _d1]),
          art('rpm-build', [_d2]),
        ],
      }, 'img');
      expect(r.layers.last.createdBy, 'dnf install');
      final byName = {
        for (final e in r.layerOf.entries) e.key.split('-')[3]: e.value,
      };
      expect(byName, {'bash': 1, 'rpm': 2});
    });
  });

  group('générateurs', () {
    final layers = layersFromConfig([_d1, _d2], [
      {'created_by': 'ADD base'},
      {'created_by': 'RUN apk upgrade'},
    ]);
    final delta = LayerDelta(
      added: [_apk('curl', '8.0')],
      modified: [(before: _apk('zlib', '1.2'), after: _apk('zlib', '1.3'))],
      removed: [_apk('busybox', '1.36')],
    );
    final summary = LayerSummary(
      layer: layers[1],
      total: 2,
      added: 1,
      modified: 1,
      removed: 1,
      fileBase: 'app.layer-02-222222222222',
      documentUuid: 'aaaaaaaa-0000-4000-8000-000000000002',
    );
    final layerDoc = LayerAnnotations.forLayer(
      mode: 'rootfs',
      self: summary,
      delta: delta,
      documentUuid: summary.documentUuid,
      globalUuid: 'bbbbbbbb-0000-4000-8000-000000000000',
      globalFileBase: 'app',
    );
    final global = LayerAnnotations.forGlobal(
      mode: 'rootfs',
      layers: [summary],
      originByRef: {
        _apk('zlib', '1.3').bomRef:
            const LayerOrigin(index: 1, digest: _d1, modifiedBy: [2]),
      },
      documentUuid: 'bbbbbbbb-0000-4000-8000-000000000000',
    );

    test('CycloneDX — SBOM de couche', () {
      final bom = CycloneDxGenerator()
          .generate(delta.packages, const [], layers: layerDoc);
      expect(bom['serialNumber'],
          'urn:uuid:aaaaaaaa-0000-4000-8000-000000000002');
      final root = (bom['metadata'] as Map)['component'] as Map;
      expect(root['version'], _d2);
      expect(root['description'], 'RUN apk upgrade');
      expect((root['externalReferences'] as List).single['url'],
          'urn:cdx:bbbbbbbb-0000-4000-8000-000000000000/1');
      final props = {
        for (final p in root['properties'] as List)
          if (p['name'] != 'sbom_generator:layer:removed') p['name']: p['value'],
      };
      expect(props['sbom_generator:layer:index'], '2');
      expect(props['sbom_generator:layer:removedCount'], '1');
      expect(
          (root['properties'] as List)
              .where((p) => p['name'] == 'sbom_generator:layer:removed')
              .single['value'],
          contains('busybox'));
      final zlib = (bom['components'] as List)
          .firstWhere((c) => c['name'] == 'zlib') as Map;
      final zp = {for (final p in zlib['properties'] as List) p['name']: p['value']};
      expect(zp['sbom_generator:layer:change'], 'modified');
      expect(zp['sbom_generator:layer:previousVersion'], '1.2');
    });

    test('CycloneDX — SBOM global', () {
      final bom = CycloneDxGenerator()
          .generate([_apk('zlib', '1.3')], const [], layers: global);
      final root = (bom['metadata'] as Map)['component'] as Map;
      final summaryProp = (root['properties'] as List)
          .firstWhere((p) => p['name'] == 'sbom_generator:layers:002') as Map;
      final s = jsonDecode(summaryProp['value'] as String) as Map;
      expect(s['file'], 'app.layer-02-222222222222');
      expect(s['bomLink'], 'urn:cdx:aaaaaaaa-0000-4000-8000-000000000002/1');
      final comp = (bom['components'] as List).single as Map;
      final cp = {for (final p in comp['properties'] as List) p['name']: p['value']};
      expect(cp['sbom_generator:layer:index'], '1');
      expect(cp['sbom_generator:layer:modifiedBy'], '2');
    });

    test('SPDX 2.3 — commentaire et annotation', () {
      final doc = SpdxGenerator()
          .generate(delta.packages, const [], layers: layerDoc);
      expect(doc['documentNamespace'],
          endsWith('aaaaaaaa-0000-4000-8000-000000000002'));
      expect(doc['name'], contains('couche 2/2'));
      expect(doc['comment'], contains('RUN apk upgrade'));
      final curl = (doc['packages'] as List)
          .firstWhere((p) => p['name'] == 'curl') as Map;
      expect((curl['annotations'] as List).single['comment'],
          contains('sbom_generator:layer:change=added'));
    });

    test('JSON personnalisé — bloc layer', () {
      final doc = SimpleJsonGenerator()
          .generate(delta.packages, const [], layers: layerDoc);
      final l = doc['layer'] as Map;
      expect(l['index'], 2);
      expect((l['removed'] as List).single['name'], 'busybox');
    });

    test('CSV et Markdown — colonne de changement et supprimés', () async {
      final tmp = Directory.systemTemp.createTempSync('layers_gen_');
      try {
        final csv = '${tmp.path}/l.csv';
        await CsvGenerator().writeToFile(delta.packages, csv, layers: layerDoc);
        final lines = File(csv).readAsLinesSync();
        expect(lines.first, endsWith(',change,previous_version'));
        expect(lines.where((l) => l.startsWith('busybox,')).single,
            contains(',removed,'));
        expect(lines.where((l) => l.startsWith('zlib,')).single,
            endsWith(',modified,1.2'));

        final md = '${tmp.path}/l.md';
        await MarkdownGenerator()
            .writeToFile(delta.packages, md, layers: layerDoc);
        final text = File(md).readAsStringSync();
        expect(text, contains('| Changement |'));
        expect(text, contains('modifié (était 1.2)'));
        expect(text, contains('## Supprimés par cette couche'));
      } finally {
        tmp.deleteSync(recursive: true);
      }
    });
  });
}
