import 'package:sbom_generator/license_normalizer.dart';
import 'package:test/test.dart';

void main() {
  group('LicenseNormalizer.toSpdxExpression', () {
    test('retourne vide pour une chaîne vide', () {
      expect(LicenseNormalizer.toSpdxExpression(''), isEmpty);
    });

    test('retourne vide pour (none)', () {
      expect(LicenseNormalizer.toSpdxExpression('(none)'), isEmpty);
    });

    test('retourne vide pour des espaces', () {
      expect(LicenseNormalizer.toSpdxExpression('   '), isEmpty);
    });

    test('normalise GPLv2 → GPL-2.0-only', () {
      expect(LicenseNormalizer.toSpdxExpression('GPLv2'), 'GPL-2.0-only');
    });

    test('normalise GPLv2+ → GPL-2.0-or-later', () {
      expect(LicenseNormalizer.toSpdxExpression('GPLv2+'), 'GPL-2.0-or-later');
    });

    test('normalise GPLv3 → GPL-3.0-only', () {
      expect(LicenseNormalizer.toSpdxExpression('GPLv3'), 'GPL-3.0-only');
    });

    test('normalise LGPLv2.1+ → LGPL-2.1-or-later', () {
      expect(
          LicenseNormalizer.toSpdxExpression('LGPLv2.1+'), 'LGPL-2.1-or-later');
    });

    test('normalise ASL 2.0 → Apache-2.0', () {
      expect(LicenseNormalizer.toSpdxExpression('ASL 2.0'), 'Apache-2.0');
    });

    test('normalise MIT → MIT', () {
      expect(LicenseNormalizer.toSpdxExpression('MIT'), 'MIT');
    });

    test('normalise MIT License → MIT', () {
      expect(LicenseNormalizer.toSpdxExpression('MIT License'), 'MIT');
    });

    test('laisse passer un SPDX inconnu tel quel', () {
      expect(LicenseNormalizer.toSpdxExpression('LicenseRef-Custom'),
          'LicenseRef-Custom');
    });

    test('normalise les opérateurs and/or en AND/OR', () {
      final expr = LicenseNormalizer.toSpdxExpression('GPLv2 and MIT');
      expect(expr, contains('AND'));
      expect(expr, contains('GPL-2.0-only'));
      expect(expr, contains('MIT'));
    });

    test('préserve GPL-2.0-or-later sans faux positif sur "or"', () {
      // "GPL-2.0-or-later" ne doit pas avoir son "or" transformé en opérateur
      // (les lookbehind/lookahead protègent les tokens collés)
      final expr = LicenseNormalizer.toSpdxExpression('GPL-2.0-or-later');
      expect(expr, 'GPL-2.0-or-later');
    });

    test('normalise expression composée GPLv2 and MIT', () {
      final expr = LicenseNormalizer.toSpdxExpression('GPLv2 and MIT');
      expect(expr, 'GPL-2.0-only AND MIT');
    });

    test('normalise expression composée LGPLv2.1+ or GPLv2+', () {
      final expr = LicenseNormalizer.toSpdxExpression('LGPLv2.1+ or GPLv2+');
      expect(expr, 'LGPL-2.1-or-later OR GPL-2.0-or-later');
    });
  });

  group('LicenseNormalizer.toCycloneDxLicenses', () {
    test('retourne [] pour (none)', () {
      expect(LicenseNormalizer.toCycloneDxLicenses('(none)'), isEmpty);
    });

    test('retourne [] pour vide', () {
      expect(LicenseNormalizer.toCycloneDxLicenses(''), isEmpty);
    });

    test('produit {"license":{"id":"GPL-2.0-only"}} pour GPLv2', () {
      final result = LicenseNormalizer.toCycloneDxLicenses('GPLv2');
      expect(result, hasLength(1));
      expect(result[0]['license']['id'], 'GPL-2.0-only');
    });

    test('produit {"license":{"id":"MIT"}} pour MIT', () {
      final result = LicenseNormalizer.toCycloneDxLicenses('MIT');
      expect(result, hasLength(1));
      expect(result[0]['license']['id'], 'MIT');
    });

    test('produit {"expression":…} pour une expression composée', () {
      final result = LicenseNormalizer.toCycloneDxLicenses('GPLv2 and MIT');
      expect(result, hasLength(1));
      expect(result[0].containsKey('expression'), isTrue);
      expect(result[0]['expression'], contains('GPL-2.0-only'));
    });

    test('utilise name (pas id) pour LicenseRef-*', () {
      final result = LicenseNormalizer.toCycloneDxLicenses('PublicDomain');
      expect(result, hasLength(1));
      // PublicDomain → LicenseRef-PublicDomain → utilise name
      expect(result[0]['license'].containsKey('name'), isTrue);
    });

    test('utilise name pour une licence inconnue sans numéro de version', () {
      // Pas de tiret+chiffre → non reconnu comme SPDX versionné → name
      final result =
          LicenseNormalizer.toCycloneDxLicenses('ProprietaryLicense');
      expect(result, hasLength(1));
      expect(result[0]['license'].containsKey('name'), isTrue);
    });

    test('utilise id pour une licence inconnue avec numéro de version', () {
      // Contient "-1" → _looksLikeSpdxId + isVersioned = true → id
      final result =
          LicenseNormalizer.toCycloneDxLicenses('MyCustomLicense-1.0');
      expect(result, hasLength(1));
      expect(result[0]['license'].containsKey('id'), isTrue);
    });
  });
}
