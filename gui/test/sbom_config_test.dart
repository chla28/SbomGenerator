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
}
