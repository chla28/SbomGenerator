import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/policy_checker.dart';
import 'package:test/test.dart';

RpmPackage _pkg({
  required String name,
  String version = '1.0',
  String license = 'MIT',
}) =>
    RpmPackage(
      name: name,
      version: version,
      release: '1.el9',
      arch: 'x86_64',
      epoch: '(none)',
      license: license,
      vendor: '',
      url: '',
      buildTime: '',
      summary: '',
      requires: const [],
      provides: const [],
    );

void main() {
  group('PolicyChecker.checkDenyLicenses', () {
    final checker = PolicyChecker();

    test('aucune violation si denyPatterns est vide', () {
      final packages = [_pkg(name: 'foo', license: 'GPL-3.0-only')];
      expect(checker.checkDenyLicenses(packages, []), isEmpty);
    });

    test('aucune violation si aucun paquet ne correspond', () {
      final packages = [
        _pkg(name: 'foo', license: 'MIT'),
        _pkg(name: 'bar', license: 'Apache-2.0'),
      ];
      expect(checker.checkDenyLicenses(packages, ['GPL-3.0']), isEmpty);
    });

    test('correspondance exacte détecte la violation', () {
      final packages = [_pkg(name: 'foo', license: 'GPL-3.0')];
      final violations = checker.checkDenyLicenses(packages, ['GPL-3.0']);
      expect(violations, hasLength(1));
      expect(violations.single.packageName, 'foo');
      expect(violations.single.deniedPattern, 'GPL-3.0');
    });

    test('correspondance par sous-chaîne : GPL-3.0 matche GPL-3.0-only', () {
      final packages = [_pkg(name: 'foo', license: 'GPL-3.0-only')];
      final violations = checker.checkDenyLicenses(packages, ['GPL-3.0']);
      expect(violations, hasLength(1));
    });

    test('correspondance par sous-chaîne : GPL-3.0 matche GPL-3.0-or-later',
        () {
      final packages = [_pkg(name: 'foo', license: 'GPL-3.0-or-later')];
      final violations = checker.checkDenyLicenses(packages, ['GPL-3.0']);
      expect(violations, hasLength(1));
    });

    test('la correspondance est insensible à la casse', () {
      final packages = [_pkg(name: 'foo', license: 'gpl-3.0-only')];
      final violations = checker.checkDenyLicenses(packages, ['GPL-3.0']);
      expect(violations, hasLength(1));
    });

    test('les paquets sans licence renseignée sont ignorés', () {
      final packages = [_pkg(name: 'foo', license: '')];
      expect(checker.checkDenyLicenses(packages, ['GPL-3.0']), isEmpty);
    });

    test('un seul pattern déclenche une seule violation par paquet', () {
      final packages = [_pkg(name: 'foo', license: 'GPL-3.0-only')];
      final violations = checker.checkDenyLicenses(
          packages, ['GPL', 'GPL-3.0-only']); // deux patterns qui matchent
      expect(violations, hasLength(1));
    });

    test('plusieurs paquets : seuls ceux qui violent la politique remontent',
        () {
      final packages = [
        _pkg(name: 'ok', license: 'MIT'),
        _pkg(name: 'denied1', license: 'AGPL-3.0'),
        _pkg(name: 'denied2', license: 'GPL-3.0-only'),
      ];
      final violations =
          checker.checkDenyLicenses(packages, ['AGPL-3.0', 'GPL-3.0']);
      final names = violations.map((v) => v.packageName).toSet();
      expect(names, {'denied1', 'denied2'});
      expect(violations, hasLength(2));
    });

    test('une licence composée SPDX (AND/OR) matche par sous-chaîne', () {
      final packages = [
        _pkg(name: 'foo', license: '(MIT OR GPL-3.0-only)'),
      ];
      final violations = checker.checkDenyLicenses(packages, ['GPL-3.0']);
      expect(violations, hasLength(1));
    });

    test('GPL ne bloque pas LGPL ni AGPL (jeton SPDX, pas sous-chaîne)', () {
      final packages = [
        _pkg(name: 'a', license: 'LGPL-3.0-only'),
        _pkg(name: 'b', license: 'AGPL-3.0-or-later'),
        _pkg(name: 'c', license: 'GPL-3.0-or-later'),
        _pkg(
            name: 'd',
            license: 'MIT OR (GPL-2.0-only WITH Classpath-exception-2.0)'),
      ];
      final v = checker.checkDenyLicenses(packages, ['GPL-3.0', 'GPL-2.0']);
      expect(v.map((e) => e.packageName), ['c', 'd']);
      expect(
          checker
              .checkDenyLicenses(packages, ['GPL']).map((e) => e.packageName),
          ['c', 'd']);
    });

    test('un motif entre *…* garde la correspondance par sous-chaîne', () {
      final packages = [
        _pkg(name: 'a', license: 'LGPL-3.0-only'),
        _pkg(name: 'b', license: 'MIT'),
      ];
      expect(checker.checkDenyLicenses(packages, ['*GPL*']).single.packageName,
          'a');
    });
  });
}
