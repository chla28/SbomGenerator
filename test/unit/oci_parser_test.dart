import 'dart:io';

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

  group('OciParser (backend trivy) — reconstruction version & PURL upstream', () {
    // Régression : grype compare les versions sur le champ `version` du
    // composant CycloneDX (pas sur le PURL). Sans release/epoch, un paquet à
    // jour paraît bien plus ancien qu'il ne l'est et remonte des CVE déjà
    // corrigées (repro : nginx:1.31.2-perl, 115 faux résultats vs 406 attendus).
    test('recompose epoch:version-release dans le champ version', () {
      final pkg = ociParserTrivyPkgToPackage({
        'Name': 'bsdutils',
        'Version': '2.41',
        'Release': '5',
        'Epoch': 1,
        'Identifier': {
          'PURL': 'pkg:deb/debian/bsdutils@2.41-5?arch=amd64&distro=debian-13&epoch=1',
        },
        'SrcName': 'util-linux',
        'SrcVersion': '2.41',
        'SrcRelease': '5',
      }, 'debian', 'nginx.tar')!;

      expect(pkg.version, '1:2.41-5');
    });

    test('ajoute upstream=<srcName>@<version> quand nom et version source diffèrent', () {
      final pkg = ociParserTrivyPkgToPackage({
        'Name': 'bsdutils',
        'Version': '2.41',
        'Release': '5',
        'Epoch': 1,
        'Identifier': {
          'PURL': 'pkg:deb/debian/bsdutils@2.41-5?arch=amd64&distro=debian-13&epoch=1',
        },
        'SrcName': 'util-linux',
        'SrcVersion': '2.41',
        'SrcRelease': '5',
      }, 'debian', 'nginx.tar')!;

      expect(pkg.purl, contains('upstream=util-linux%402.41-5'));
    });

    test('ajoute upstream=<srcName> sans version quand seul le nom diffère', () {
      final pkg = ociParserTrivyPkgToPackage({
        'Name': 'libc6',
        'Version': '2.41',
        'Release': '12+deb13u3',
        'Identifier': {
          'PURL': 'pkg:deb/debian/libc6@2.41-12%2Bdeb13u3?arch=amd64&distro=debian-13',
        },
        'SrcName': 'glibc',
        'SrcVersion': '2.41',
        'SrcRelease': '12+deb13u3',
      }, 'debian', 'nginx.tar')!;

      expect(pkg.purl, endsWith('upstream=glibc'));
    });

    test('n\'ajoute pas upstream quand paquet binaire == paquet source (nom et version)', () {
      final pkg = ociParserTrivyPkgToPackage({
        'Name': 'sed',
        'Version': '4.9',
        'Release': '2+deb13u1',
        'Identifier': {
          'PURL': 'pkg:deb/debian/sed@4.9-2%2Bdeb13u1?arch=amd64&distro=debian-13',
        },
        'SrcName': 'sed',
        'SrcVersion': '4.9',
        'SrcRelease': '2+deb13u1',
      }, 'debian', 'nginx.tar')!;

      expect(pkg.purl, isNot(contains('upstream=')));
    });

    test('ajoute quand même la version dans upstream si seule la release binaire diffère (binNMU +bN)', () {
      final pkg = ociParserTrivyPkgToPackage({
        'Name': 'libcap2',
        'Version': '2.75',
        'Release': '10+deb13u1+b1',
        'Epoch': 1,
        'Identifier': {
          'PURL': 'pkg:deb/debian/libcap2@2.75-10%2Bdeb13u1%2Bb1?arch=amd64&distro=debian-13&epoch=1',
        },
        'SrcName': 'libcap2',
        'SrcVersion': '2.75',
        'SrcRelease': '10+deb13u1',
        'SrcEpoch': 1,
      }, 'debian', 'nginx.tar')!;

      expect(pkg.purl, contains('upstream=libcap2%401%3A2.75-10%2Bdeb13u1'));
    });

    test('ne touche pas au PURL déjà pourvu d\'un upstream (idempotence)', () {
      final pkg = ociParserTrivyPkgToPackage({
        'Name': 'bsdutils',
        'Version': '2.41',
        'Release': '5',
        'Epoch': 1,
        'Identifier': {
          'PURL': 'pkg:deb/debian/bsdutils@2.41-5?arch=amd64&distro=debian-13&epoch=1&upstream=util-linux',
        },
        'SrcName': 'util-linux',
        'SrcVersion': '2.41',
        'SrcRelease': '5',
      }, 'debian', 'nginx.tar')!;

      expect('upstream='.allMatches(pkg.purl).length, 1);
    });
  });

  group('OciParser (backend syft) — OS de base', () {
    test('traduit l\'id os-release rhel vers la famille Trivy redhat', () {
      final os = ociParserSyftDistroToOsInfo({
        'distro': {
          'id': 'rhel',
          'versionID': '9.6',
          'prettyName': 'Red Hat Enterprise Linux 9.6 (Plow)',
          'cpeName': 'cpe:/o:redhat:enterprise_linux:9::baseos',
        },
      })!;

      // rhel → redhat : sans cette traduction, Trivy en mode `trivy sbom`
      // n'associe le composant à aucune base CVE connue (vérifié
      // empiriquement contre une image réelle).
      expect(os.id, 'redhat');
      expect(os.version, '9.6');
      expect(os.prettyName, 'Red Hat Enterprise Linux 9.6 (Plow)');
      expect(os.cpe, 'cpe:/o:redhat:enterprise_linux:9::baseos');
    });

    test('laisse inchangé un id déjà identique à la famille Trivy (debian)',
        () {
      final os = ociParserSyftDistroToOsInfo({
        'distro': {'id': 'debian', 'versionID': '13'},
      })!;
      expect(os.id, 'debian');
    });

    test('retourne null quand syft n\'a détecté aucune base OS (scratch)',
        () {
      expect(ociParserSyftDistroToOsInfo({}), isNull);
      expect(ociParserSyftDistroToOsInfo({'distro': null}), isNull);
    });
  });

  group('OciParser (backend trivy) — OS de base', () {
    test('reprend Metadata.OS.Family tel quel (déjà la famille Trivy)', () {
      final os = ociParserTrivyMetadataToOsInfo({
        'Metadata': {
          'OS': {'Family': 'redhat', 'Name': '9.6'},
        },
      })!;
      expect(os.id, 'redhat');
      expect(os.version, '9.6');
    });

    test('retourne null quand trivy n\'a détecté aucune base OS (scratch)',
        () {
      expect(ociParserTrivyMetadataToOsInfo({}), isNull);
      expect(
          ociParserTrivyMetadataToOsInfo({'Metadata': <String, dynamic>{}}),
          isNull);
    });
  });

  group('OciParser (backend skopeo) — licence dpkg via copyright DEP-5', () {
    late Directory tmp;

    setUp(() async {
      tmp = await Directory.systemTemp.createTemp('oci_parser_dpkg_test_');
    });

    tearDown(() async {
      await tmp.delete(recursive: true);
    });

    Future<void> writeCopyright(String pkg, String content) async {
      final dir = Directory('${tmp.path}/usr/share/doc/$pkg');
      await dir.create(recursive: true);
      await File('${dir.path}/copyright').writeAsString(content);
    }

    test(
        'extrait la licence depuis le champ License: de la stanza Files: * '
        '(DEP-5)', () async {
      await writeCopyright('bash', '''
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: *
Copyright: 1994-2023 Free Software Foundation, Inc.
License: GPL-3+

Files: examples/*
Copyright: 1994 Someone Else
License: MIT
''');
      final status = File('${tmp.path}/status');
      await status.writeAsString('''
Package: bash
Status: install ok installed
Version: 5.2.15-2
Architecture: amd64
Maintainer: Someone <x@example.org>
Depends: libc6
Description: GNU Bourne Again SHell
 Bash is an sh-compatible shell.
''');

      final packages =
          await ociParserParseDpkgStatus(status, 'test:image', tmp.path);
      expect(packages, hasLength(1));
      // La stanza "Files: *" (couvre tout le paquet) est priorisée sur les
      // autres stanzas plus spécifiques (ex. examples/*).
      expect(packages.single.license, 'GPL-3+');
    });

    test('sans stanza Files: * , concatène les licences distinctes trouvées',
        () async {
      await writeCopyright('foo', '''
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/

Files: src/*
Copyright: 2020 A
License: MIT

Files: doc/*
Copyright: 2020 B
License: CC0-1.0
''');
      final status = File('${tmp.path}/status');
      await status.writeAsString('''
Package: foo
Status: install ok installed
Version: 1.0
Architecture: amd64
Description: test
''');

      final packages =
          await ociParserParseDpkgStatus(status, 'test:image', tmp.path);
      expect(packages.single.license, 'MIT and CC0-1.0');
    });

    test(
        'ignore un copyright file en texte libre (pas de format DEP-5 '
        'machine-readable)', () async {
      await writeCopyright('legacy-pkg', '''
This package was written by someone.

It is released under the GNU General Public License, version 2, or (at
your option) any later version.
''');
      final status = File('${tmp.path}/status');
      await status.writeAsString('''
Package: legacy-pkg
Status: install ok installed
Version: 1.0
Architecture: amd64
Description: test
''');

      final packages =
          await ociParserParseDpkgStatus(status, 'test:image', tmp.path);
      expect(packages.single.license, isEmpty);
    });

    test('chaîne vide quand /usr/share/doc/<pkg>/copyright est absent',
        () async {
      final status = File('${tmp.path}/status');
      await status.writeAsString('''
Package: nodoc
Status: install ok installed
Version: 1.0
Architecture: amd64
Description: test
''');

      final packages =
          await ociParserParseDpkgStatus(status, 'test:image', tmp.path);
      expect(packages.single.license, isEmpty);
    });
  });
}
