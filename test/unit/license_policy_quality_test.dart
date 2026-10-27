import 'package:sbom_generator/license_policy.dart';
import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/sbom_quality.dart';
import 'package:test/test.dart';

WheelPackage pkg(String name, String license) => WheelPackage(
      name: name,
      version: '1.0',
      license: license,
      url: '',
      summary: '',
      vendor: '',
      arch: 'any',
      sourceRef: 'x',
      requires: [],
      provides: [],
      packageType: 'npm',
    );

void main() {
  group('LicensePolicy', () {
    test('allow, deny et glob insensibles à la casse', () {
      final p = LicensePolicy.parse('''
# commentaire
allow: MIT, Apache-2.0, bsd-*
deny: GPL-*
''');
      final v = p.evaluate([
        pkg('a', 'MIT'),
        pkg('b', 'BSD-3-Clause'),
        pkg('c', 'GPL-3.0-only'),
        pkg('d', 'ISC'),
      ]);
      expect(v.map((e) => e.package.name), ['c', 'd']);
      expect(v.first.reason, contains('GPL-3.0-only'));
      expect(v.last.reason, contains('ISC'));
    });

    test('expressions : OR accepte un choix, AND exige les deux', () {
      final p = LicensePolicy.parse('allow: MIT\ndeny: GPL-3.0-only\n');
      expect(p.evaluate([pkg('or', 'MIT OR GPL-3.0-only')]), isEmpty);
      expect(p.evaluate([pkg('and', 'MIT AND GPL-3.0-only')]), hasLength(1));
      expect(p.evaluate([pkg('par', '(MIT OR ISC) AND MIT')]), isEmpty);
      expect(p.evaluate([pkg('with', 'MIT WITH Classpath-exception-2.0')]),
          isEmpty);
    });

    test('unknown : fail par défaut, allow et warn n\'échouent pas', () {
      expect(LicensePolicy.parse('deny: GPL-*').evaluate([pkg('x', '')]),
          hasLength(1));
      expect(
          LicensePolicy.parse('unknown: warn')
              .evaluate([pkg('x', 'NOASSERTION')]),
          isEmpty);
      expect(LicensePolicy.parse('unknown: allow').isUnknown('NONE'), isTrue);
    });

    test('exceptions : active écarte, expirée est signalée', () {
      final p = LicensePolicy.parse('''
deny: GPL-*
except: pkg:npm/a; expires=2030-01-01; reason=OK
except: b; expires=2020-01-01
''');
      final expired = <LicenseException>[];
      final v = p.evaluate([pkg('a', 'GPL-2.0-only'), pkg('b', 'GPL-2.0-only')],
          now: DateTime(2026, 1, 1), expiredOut: expired);
      expect(v.map((e) => e.package.name), ['b']);
      expect(expired.single.package, 'b');
    });

    test('lignes invalides : avertissements, pas d\'exception', () {
      final p = LicensePolicy.parse('n importe quoi\nfoo: bar\nunknown: x\n');
      expect(p.warnings, hasLength(3));
    });
  });

  group('assessQuality', () {
    Map<String, dynamic> cdx(List<Map<String, dynamic>> comps) => {
          'bomFormat': 'CycloneDX',
          'specVersion': '1.6',
          'metadata': {
            'timestamp': '2026-01-01T00:00:00Z',
            'tools': {
              'components': [
                {'name': 't'}
              ]
            },
            'component': {'name': 'app'},
          },
          'components': comps,
          'dependencies': [
            {
              'ref': 'a',
              'dependsOn': ['b']
            }
          ],
        };

    test('SBOM complet : 100 / A', () {
      final r = assessQuality(
          'x.cdx.json',
          cdx([
            {
              'name': 'a',
              'version': '1',
              'supplier': {'name': 'ACME'},
              'purl': 'pkg:npm/a@1',
              'hashes': [
                {'alg': 'SHA-256', 'content': 'a' * 64}
              ],
              'licenses': [
                {
                  'license': {'id': 'MIT'}
                }
              ],
            }
          ]));
      expect(r.score, 100);
      expect(r.grade, 'A');
    });

    test('composant nu : note basse et composant signalé', () {
      final r = assessQuality(
          'x.cdx.json',
          cdx([
            {'name': 'nu'}
          ]));
      expect(r.score, lessThan(60));
      final json = r.toJson();
      expect(json['grade'], isNot('A'));
      expect(r.toText(), contains('nu'));
    });
  });
}
