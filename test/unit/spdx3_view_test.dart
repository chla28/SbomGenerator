import 'package:sbom_generator/spdx3_view.dart';
import 'package:test/test.dart';

void main() {
  group('spdx3Packages', () {
    test('forme officielle : licences et annotations portées par le graphe',
        () {
      final pkgs = spdx3Packages([
        {
          'type': 'software_Package',
          'spdxId': 'urn:p1',
          'name': 'foo',
          'software_packageVersion': '1.0',
          'software_downloadLocation': 'https://x',
          'externalIdentifier': [
            {
              'type': 'ExternalIdentifier',
              'externalIdentifierType': 'packageUrl',
              'identifier': 'pkg:npm/foo@1.0',
            }
          ],
        },
        {
          'type': 'simplelicensing_LicenseExpression',
          'spdxId': 'urn:l1',
          'simplelicensing_licenseExpression': 'MIT',
        },
        {
          'type': 'Relationship',
          'from': 'urn:p1',
          'to': ['urn:l1'],
          'relationshipType': 'hasDeclaredLicense',
        },
        {
          'type': 'Annotation',
          'subject': 'urn:p1',
          'annotationType': 'other',
          'statement': 'a=b',
        },
      ]);
      final p = pkgs.single;
      expect(p['software:packageVersion'], '1.0');
      expect(p['software:downloadLocation'], 'https://x');
      expect(p['declaredLicense'], 'MIT');
      expect(p['concludedLicense'], isNull);
      expect((p['annotation'] as List).single['statement'], 'a=b');
      expect((p['externalIdentifier'] as List).single['externalIdentifierType'],
          'purl');
    });

    test('purl lue depuis software_packageUrl sans externalIdentifier', () {
      final p = spdx3Packages([
        {
          'type': 'software_Package',
          'spdxId': 'urn:p',
          'name': 'x',
          'software_packageUrl': 'pkg:pub/x@1',
        }
      ]).single;
      expect((p['externalIdentifier'] as List).single['identifier'],
          'pkg:pub/x@1');
    });

    test('ancienne forme (≤ 1.10.x) toujours lue', () {
      final p = spdx3Packages([
        {
          'type': 'software:Package',
          'spdxId': 'urn:p',
          'name': 'old',
          'software:packageVersion': '2.0',
          'concludedLicense': 'Apache-2.0',
          'annotation': [
            {'statement': 'x=y'}
          ],
          'externalIdentifier': [
            {'externalIdentifierType': 'purl', 'identifier': 'pkg:npm/old@2.0'}
          ],
        }
      ]).single;
      expect(p['software:packageVersion'], '2.0');
      expect(p['concludedLicense'], 'Apache-2.0');
      expect((p['annotation'] as List), hasLength(1));
    });

    test('ignore les nœuds qui ne sont pas des paquets', () {
      expect(
          spdx3Packages([
            {'type': 'Tool', 'name': 't'},
            'pas une map',
          ]),
          isEmpty);
    });
  });
}
