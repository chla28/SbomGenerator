/// Tests pour le fix "skopeo/rpm — rpm --dbpath sans --root".
///
/// Contexte du bug :
///   rpm --root X --dbpath X/var/lib/rpm combine les deux chemins → chemin
///   invalide → 0 paquets silencieusement.
///   Sur Fedora 33+, %_dbpath pointe vers /usr/lib/sysimage/rpm alors que
///   certaines images (keycloak/UBI 9) stockent leur base dans /var/lib/rpm.
///
/// Fix : détection automatique de rpmdb.sqlite dans les deux emplacements
/// canoniques, puis appel rpm --dbpath <chemin absolu> sans --root.
import 'dart:io';

import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/oci_parser.dart';
import 'package:test/test.dart';

// ── Helpers ───────────────────────────────────────────────────────────────────

const _keycloakTar = 'keycloak_26.tar';

/// Premier layer de keycloak_26.tar (contient var/lib/rpm/rpmdb.sqlite).
/// Dépend de l'image exacte utilisée pour produire keycloak_26.tar
/// localement (`skopeo copy docker://quay.io/keycloak/keycloak:26.0.0
/// docker-archive:keycloak_26.tar`) — à mettre à jour si le fichier est
/// régénéré depuis une autre image/tag (digest de layer différent).
const _keycloakLayer =
    '456a106fc69abcc6e07bbd99e09cdb5b34d4bbd88f7043293e012be50189f055.tar';

bool get _keycloakAvailable => File(_keycloakTar).existsSync();

Future<bool> _toolAvailable(String tool) async {
  final r = await Process.run(tool, ['--version']);
  return r.exitCode == 0;
}

/// Extrait var/lib/rpm/ depuis le premier layer de keycloak_26.tar dans [dest].
Future<void> _extractKeycloakRpmDb(String dest) async {
  await Directory('$dest/var/lib/rpm').create(recursive: true);
  // Extraire le layer du tar principal, puis extraire var/lib/rpm/ depuis ce layer
  await Process.run('bash', [
    '-c',
    'tar -xOf $_keycloakTar $_keycloakLayer 2>/dev/null'
        ' | tar -xf - -C $dest var/lib/rpm/ 2>/dev/null',
  ]);
}

// ── Main ─────────────────────────────────────────────────────────────────────

void main() {
  late Directory tmpDir;

  setUp(() async {
    tmpDir = await Directory.systemTemp.createTemp('sbom_rpm_test_');
  });

  tearDown(() async {
    await Process.run('chmod', ['-R', 'u+rwX', tmpDir.path]);
    await tmpDir.delete(recursive: true);
  });

  // ── Régression subprocess ──────────────────────────────────────────────────

  group('Régression rpm — comportement --dbpath vs --root+--dbpath', () {
    setUp(() async {
      if (!_keycloakAvailable) return;
      await _extractKeycloakRpmDb(tmpDir.path);
    });

    test('--dbpath seul (fix) → retourne les paquets', () async {
      if (!_keycloakAvailable) {
        markTestSkipped('$_keycloakTar absent');
        return;
      }
      final dbPath = '${tmpDir.path}/var/lib/rpm';
      final r = await Process.run('rpm', ['--dbpath', dbPath, '-qa']);
      expect(r.exitCode, 0);
      final pkgs =
          (r.stdout as String).trim().split('\n').where((l) => l.isNotEmpty);
      expect(pkgs, isNotEmpty,
          reason: 'La base RPM doit contenir au moins un paquet');
    });

    test(
        '--root + --dbpath absolu (ancien comportement) → 0 paquets (démontre le bug)',
        () async {
      if (!_keycloakAvailable) {
        markTestSkipped('$_keycloakTar absent');
        return;
      }
      final dbPath = '${tmpDir.path}/var/lib/rpm';
      // Combine --root X et --dbpath X/… : rpm cherche à X/X/… → introuvable
      final r = await Process.run(
          'rpm', ['--root', tmpDir.path, '--dbpath', dbPath, '-qa']);
      expect(r.exitCode, 0,
          reason: 'rpm sort avec 0 même quand la base est invisible');
      expect((r.stdout as String).trim(), isEmpty,
          reason: 'Bug confirmé : 0 paquets avec --root + --dbpath absolu');
    });
  });

  // ── Détection du chemin RPM via OciParser ─────────────────────────────────

  group('OciParser — détection automatique du chemin RPM db', () {
    test(
        'var/lib/rpm/rpmdb.sqlite → détecté, retourne liste (éventuellement vide)',
        () async {
      final rpmDir = '${tmpDir.path}/var/lib/rpm';
      await Directory(rpmDir).create(recursive: true);
      final initR = await Process.run('rpm', ['--initdb', '--dbpath', rpmDir]);
      if (initR.exitCode != 0) {
        markTestSkipped('rpm --initdb a échoué (rpm absent ?)');
        return;
      }
      // DB vide → 0 paquets, mais pas d'exception
      final pkgs = await ociParserParseRpmRoot(tmpDir.path, 'test-image');
      expect(pkgs, isA<List<Package>>());
    });

    test('usr/lib/sysimage/rpm/rpmdb.sqlite → chemin RHEL 8.4+/9 détecté',
        () async {
      final rpmDir = '${tmpDir.path}/usr/lib/sysimage/rpm';
      await Directory(rpmDir).create(recursive: true);
      final initR = await Process.run('rpm', ['--initdb', '--dbpath', rpmDir]);
      if (initR.exitCode != 0) {
        markTestSkipped('rpm --initdb a échoué');
        return;
      }
      final pkgs = await ociParserParseRpmRoot(tmpDir.path, 'test-image');
      expect(pkgs, isA<List<Package>>());
    });

    test(
        'répertoire var/lib/rpm présent mais sans db → liste vide sans exception',
        () async {
      // Crée le dossier mais sans rpmdb.sqlite ni Packages
      await Directory('${tmpDir.path}/var/lib/rpm').create(recursive: true);
      final pkgs = await ociParserParseRpmRoot(tmpDir.path, 'test-image');
      expect(pkgs, isEmpty);
    });

    test('aucun répertoire RPM → liste vide sans exception', () async {
      // rootDir vide, aucune DB
      final pkgs = await ociParserParseRpmRoot(tmpDir.path, 'test-image');
      expect(pkgs, isEmpty);
    });

    test('keycloak layer → paquets RPM retournés avec métadonnées cohérentes',
        () async {
      if (!_keycloakAvailable) {
        markTestSkipped('$_keycloakTar absent');
        return;
      }
      await _extractKeycloakRpmDb(tmpDir.path);

      final pkgs = await ociParserParseRpmRoot(tmpDir.path, 'keycloak_26.tar');

      expect(pkgs.length, greaterThan(5),
          reason: 'L\'image keycloak doit contenir plusieurs paquets RPM');

      // Tous les paquets doivent être de type rpm
      expect(pkgs.every((p) => p.packageType == 'rpm'), isTrue);

      // Paquets UBI 9 attendus dans la base
      final names = pkgs.map((p) => p.name).toSet();
      expect(names, containsAll(['setup', 'filesystem', 'basesystem']),
          reason: 'Paquets de base UBI 9 absents');

      // Pas de gpg-pubkey dans les résultats (filtré)
      expect(names, isNot(contains('gpg-pubkey')));

      // Chaque paquet a un name, version et bomRef non vides
      for (final pkg in pkgs) {
        expect(pkg.name, isNotEmpty);
        expect(pkg.version, isNotEmpty);
        expect(pkg.bomRef, isNotEmpty);
      }
    });
  });

  // ── Intégration complète OciParser + skopeo ───────────────────────────────

  group('OciParser.parseImage — intégration skopeo', () {
    late bool skopeoAvailable;

    setUpAll(() async {
      skopeoAvailable = await _toolAvailable('skopeo');
    });

    test('keycloak_26.tar via skopeo → paquets RPM cohérents', () async {
      if (!skopeoAvailable) {
        markTestSkipped('skopeo absent du PATH');
        return;
      }
      if (!_keycloakAvailable) {
        markTestSkipped('$_keycloakTar absent');
        return;
      }

      final result = await OciParser().parseImage(_keycloakTar, 'skopeo');
      final pkgs = result.packages;

      // skopeo ne lit pas /etc/os-release : pas d'OS détecté (voir
      // OciParser._parseSkopeo).
      expect(result.os, isNull);

      // Keycloak = paquets RPM (OS) + paquets Java/Maven (application)
      expect(pkgs.length, greaterThan(40));

      final rpmPkgs = pkgs.where((p) => p.packageType == 'rpm').toList();
      final javaPkgs = pkgs.where((p) => p.packageType == 'java').toList();
      expect(rpmPkgs, isNotEmpty, reason: 'Paquets RPM UBI 9 attendus');
      expect(javaPkgs, isNotEmpty, reason: 'JARs Keycloak attendus');

      final rpmNames = rpmPkgs.map((p) => p.name).toSet();
      expect(rpmNames, containsAll(['setup', 'filesystem', 'basesystem']));
      expect(rpmNames, isNot(contains('gpg-pubkey')));

      // Quelques artefacts Maven attendus
      final javaNames = javaPkgs.map((p) => p.name).toSet();
      expect(javaNames, contains('snakeyaml'));
    });
  });
}
