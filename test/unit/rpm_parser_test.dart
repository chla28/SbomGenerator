import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/rpm_parser.dart';
import 'package:test/test.dart';

/// Tests for buildDependencies() — no subprocess required.
void main() {
  group('RpmParser.buildDependencies', () {
    final parser = RpmParser();

    RpmPackage _rpm({
      required String name,
      String version = '1.0',
      String release = '1.el9',
      String arch = 'x86_64',
      List<String> requires = const [],
      List<String> provides = const [],
    }) =>
        RpmPackage(
          name: name,
          version: version,
          release: release,
          arch: arch,
          epoch: '(none)',
          license: 'MIT',
          vendor: '',
          url: '',
          buildTime: '',
          summary: '',
          requires: requires,
          provides: provides,
        );

    test('liste vide → liste vide', () {
      final deps = parser.buildDependencies([]);
      expect(deps, isEmpty);
    });

    test('paquet unique sans dépendances', () {
      final pkg = _rpm(name: 'bash');
      final deps = parser.buildDependencies([pkg]);
      expect(deps, hasLength(1));
      expect(deps.first.dependsOn, isEmpty);
    });

    test('résolution directe via nom de paquet', () {
      final a = _rpm(name: 'pkgA', requires: ['pkgB']);
      final b = _rpm(name: 'pkgB');
      final deps = parser.buildDependencies([a, b]);

      final aDeps = deps.firstWhere((d) => d.sourceRef == a.bomRef);
      expect(aDeps.dependsOn, contains(b.bomRef));
    });

    test('résolution via provides', () {
      final a = _rpm(name: 'pkgA', requires: ['libfoo.so.1']);
      final b = _rpm(name: 'pkgB', provides: ['libfoo.so.1']);
      final deps = parser.buildDependencies([a, b]);

      final aDeps = deps.firstWhere((d) => d.sourceRef == a.bomRef);
      expect(aDeps.dependsOn, contains(b.bomRef));
    });

    test('résolution avec contrainte de version strippée', () {
      final a = _rpm(name: 'pkgA', requires: ['pkgB >= 2.0']);
      final b = _rpm(name: 'pkgB', version: '3.0');
      final deps = parser.buildDependencies([a, b]);

      final aDeps = deps.firstWhere((d) => d.sourceRef == a.bomRef);
      expect(aDeps.dependsOn, contains(b.bomRef));
    });

    test('python3dist(lxml) préservé (parenthèses non tronquées)', () {
      final a = _rpm(name: 'pkgA', requires: ['python3dist(lxml) >= 3.0']);
      final b = _rpm(name: 'pkgB', provides: ['python3dist(lxml)']);
      final deps = parser.buildDependencies([a, b]);

      final aDeps = deps.firstWhere((d) => d.sourceRef == a.bomRef);
      expect(aDeps.dependsOn, contains(b.bomRef));
    });

    test('auto-dépendance ignorée', () {
      final a = _rpm(name: 'pkgA', requires: ['pkgA']);
      final deps = parser.buildDependencies([a]);

      final aDeps = deps.firstWhere((d) => d.sourceRef == a.bomRef);
      expect(aDeps.dependsOn, isEmpty);
    });

    test('dépendances hors liste ignorées', () {
      final a = _rpm(name: 'pkgA', requires: ['glibc', 'kernel']);
      final deps = parser.buildDependencies([a]);

      final aDeps = deps.firstWhere((d) => d.sourceRef == a.bomRef);
      expect(aDeps.dependsOn, isEmpty);
    });

    test('dépendances triées', () {
      final a = _rpm(name: 'pkgA', requires: ['pkgC', 'pkgB']);
      final b = _rpm(name: 'pkgB');
      final c = _rpm(name: 'pkgC');
      final deps = parser.buildDependencies([a, b, c]);

      final aDeps = deps.firstWhere((d) => d.sourceRef == a.bomRef);
      expect(aDeps.dependsOn, equals([...aDeps.dependsOn]..sort()));
    });
  });
}
