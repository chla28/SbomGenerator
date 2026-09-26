import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/sbom_config.dart';

void main() {
  group('SbomConfig.toArgs — --binary', () {
    test('émet --binary quand binaryPath est renseigné', () {
      final c = SbomConfig(binaryPath: '/usr/local/bin/mon-app');
      final args = c.toArgs();
      expect(args, containsAllInOrder(['--binary', '/usr/local/bin/mon-app']));
      expect(args, isNot(contains('--image')));
    });

    test('--binary prime sur --image si les deux sont renseignés '
        '(ne devrait pas arriver via l\'UI, qui les rend exclusifs)', () {
      final c = SbomConfig(
        binaryPath: '/usr/local/bin/mon-app',
        imageRef: 'nginx:latest',
      );
      final args = c.toArgs();
      expect(args, contains('--binary'));
      expect(args, isNot(contains('--image')));
    });

    test('--oci-tool n\'est émis que pour --image, jamais pour --binary', () {
      final c = SbomConfig(binaryPath: '/bin/x', ociTool: 'trivy');
      expect(c.toArgs(), isNot(contains('--oci-tool')));
    });

    test('round-trip toJson/fromJson conserve binaryPath', () {
      final c = SbomConfig(binaryPath: '/bin/x');
      final restored = SbomConfig.fromJson(c.toJson());
      expect(restored.binaryPath, '/bin/x');
    });

    test('binaryPath vide par défaut, aucun impact sur --image', () {
      final c = SbomConfig(imageRef: 'nginx:latest', ociTool: 'trivy');
      final args = c.toArgs();
      expect(args, containsAllInOrder(['--image', 'nginx:latest']));
      expect(args, containsAllInOrder(['--oci-tool', 'trivy']));
    });
  });

  group('SbomConfig.toArgs — --per-layer', () {
    test('émet --per-layer et --layer-mode avec une image', () {
      final c = SbomConfig(imageRef: 'nginx:latest', perLayer: true);
      expect(c.toArgs(),
          containsAllInOrder(['--per-layer', '--layer-mode', 'metadata']));
    });

    test('mode rootfs forcé pour skopeo et cdxgen', () {
      for (final tool in ['skopeo', 'cdxgen']) {
        final c = SbomConfig(
            imageRef: 'nginx:latest',
            ociTool: tool,
            perLayer: true,
            layerMode: 'metadata');
        expect(c.effectiveLayerMode, 'rootfs');
        expect(c.toArgs(), containsAllInOrder(['--layer-mode', 'rootfs']));
      }
    });

    test('ignoré sans image (entrée fichier ou binaire)', () {
      expect(SbomConfig(inputFile: 'pkgs.txt', perLayer: true).toArgs(),
          isNot(contains('--per-layer')));
      expect(SbomConfig(binaryPath: '/bin/x', perLayer: true).toArgs(),
          isNot(contains('--per-layer')));
    });

    test('round-trip toJson/fromJson conserve perLayer et layerMode', () {
      final c = SbomConfig(perLayer: true, layerMode: 'rootfs');
      final restored = SbomConfig.fromJson(c.toJson());
      expect(restored.perLayer, isTrue);
      expect(restored.layerMode, 'rootfs');
    });
  });
}
