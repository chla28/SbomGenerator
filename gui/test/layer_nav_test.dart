import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/layer_nav.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('layer_nav_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  void touch(String name) => File('${tmp.path}/$name').writeAsStringSync('{}');

  group('LayerNav.discover', () {
    test('depuis le global : couches du même format, triées', () {
      touch('app.cdx.json');
      touch('app.layer-02-bbbbbbbbbbbb.cdx.json');
      touch('app.layer-01-aaaaaaaaaaaa.cdx.json');
      touch('app.layer-01-aaaaaaaaaaaa.spdx.json');
      touch('other.layer-01-cccccccccccc.cdx.json');
      final nav = LayerNav.discover('${tmp.path}/app.cdx.json')!;
      expect(nav.isLayer, isFalse);
      expect(nav.globalPath, '${tmp.path}/app.cdx.json');
      expect(nav.layers.map((l) => l.index), [1, 2]);
      expect(nav.layers.first.path.endsWith('.cdx.json'), isTrue);
    });

    test('depuis une couche : retrouve le global', () {
      touch('app.spdx.json');
      touch('app.layer-01-aaaaaaaaaaaa.spdx.json');
      final nav =
          LayerNav.discover('${tmp.path}/app.layer-01-aaaaaaaaaaaa.spdx.json')!;
      expect(nav.currentIndex, 1);
      expect(nav.globalPath, '${tmp.path}/app.spdx.json');
    });

    test('global sans extension (sortie à format unique)', () {
      touch('sbom');
      touch('sbom.layer-01-aaaaaaaaaaaa.cdx.json');
      final nav = LayerNav.discover('${tmp.path}/sbom')!;
      expect(nav.layers.single.index, 1);
      final back =
          LayerNav.discover('${tmp.path}/sbom.layer-01-aaaaaaaaaaaa.cdx.json')!;
      expect(back.globalPath, '${tmp.path}/sbom');
    });

    test('fichier sans couches : null', () {
      touch('app.cdx.json');
      expect(LayerNav.discover('${tmp.path}/app.cdx.json'), isNull);
    });
  });

  test('isLayerSbomFile', () {
    expect(isLayerSbomFile('/o/app.layer-03-0123456789ab.cdx.json'), isTrue);
    expect(isLayerSbomFile('/o/app.cdx.json'), isFalse);
  });

  group('champs de couche des composants', () {
    test('CycloneDX : propriétés', () {
      final f = layerFieldsOf({
        'properties': [
          {'name': 'sbom_generator:layer:index', 'value': '2'},
          {'name': 'sbom_generator:layer:modifiedBy', 'value': '4,5'},
          {'name': 'rpm:arch', 'value': 'x86_64'},
        ],
      });
      expect(f, {'index': '2', 'modifiedBy': '4,5'});
      expect(layerColumnLabel(f), 'couche 2 (modifié : 4,5)');
      expect(layerGroupKey(f), 'Couche 02');
    });

    test('SPDX 2.3 / 3.0 : annotations', () {
      final spdx = layerFieldsOf({
        'annotations': [
          {
            'comment': 'deb:arch=amd64; sbom_generator:layer:change=modified; '
                'sbom_generator:layer:previousVersion=1.2',
          },
        ],
      });
      expect(layerColumnLabel(spdx), 'modifié (était 1.2)');
      final spdx3 = layerFieldsOf({
        'annotation': [
          {'statement': 'sbom_generator:layer:change=added'},
        ],
      });
      expect(layerColumnLabel(spdx3), 'ajouté');
      expect(layerGroupKey(spdx3), 'Ajoutés');
    });
  });

  group('LayerDocInfo', () {
    test('SBOM global CycloneDX : libellés par couche', () {
      final info = LayerDocInfo.fromSbom({
        'bomFormat': 'CycloneDX',
        'metadata': {
          'component': {
            'properties': [
              {'name': 'sbom_generator:layers:mode', 'value': 'rootfs'},
              {
                'name': 'sbom_generator:layers:001',
                'value': jsonEncode({
                  'index': 1,
                  'added': 16,
                  'modified': 0,
                  'removed': 0,
                  'createdBy': 'ADD base',
                }),
              },
            ],
          },
        },
      });
      expect(info.layerLabels[1], '+16 ~0 -0 — ADD base');
      expect(info.lines.single, contains('mode rootfs'));
    });

    test('SBOM de couche CycloneDX : description et supprimés', () {
      final info = LayerDocInfo.fromSbom({
        'bomFormat': 'CycloneDX',
        'metadata': {
          'component': {
            'description': 'RUN apk del busybox',
            'properties': [
              {'name': 'sbom_generator:layer:index', 'value': '2'},
              {'name': 'sbom_generator:layer:total', 'value': '3'},
              {
                'name': 'sbom_generator:layer:removed',
                'value': 'pkg-oci-apk-busybox-1.36 (busybox 1.36)',
              },
            ],
          },
        },
      });
      expect(info.lines.first, startsWith('Couche 2/3'));
      expect(info.lines, contains('Instruction : RUN apk del busybox'));
      expect(info.removed.single, contains('busybox'));
    });

    test('SBOM sans couches : vide', () {
      expect(
          LayerDocInfo.fromSbom({'bomFormat': 'CycloneDX', 'metadata': {}})
              .isEmpty,
          isTrue);
    });
  });
}
