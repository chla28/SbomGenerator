import 'package:test/test.dart';
import 'package:sbom_generator/oci_parser.dart';

void main() {
  group('OciParser.detectRefType', () {
    test('retourne tar pour .tar', () {
      expect(OciParser.detectRefType('/images/ubuntu.tar'), OciRefType.tar);
    });

    test('retourne tar pour .tar.gz', () {
      expect(OciParser.detectRefType('/images/ubuntu.tar.gz'), OciRefType.tar);
    });

    test('retourne tar pour .tgz', () {
      expect(OciParser.detectRefType('/images/ubuntu.tgz'), OciRefType.tar);
    });

    test('retourne registry pour une référence registre', () {
      expect(OciParser.detectRefType('nginx:latest'), OciRefType.registry);
      expect(
        OciParser.detectRefType('ghcr.io/org/app:v1'),
        OciRefType.registry,
      );
    });
  });
}
