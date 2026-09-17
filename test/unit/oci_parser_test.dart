import 'dart:io';

import 'package:test/test.dart';
import 'package:sbom_generator/models.dart';
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

    test('retourne binary pour un fichier local existant (--binary)', () {
      final f = File(
          '${Directory.systemTemp.createTempSync('oci_binary_test_').path}/mon-app')
        ..writeAsBytesSync([0]);
      expect(OciParser.detectRefType(f.path), OciRefType.binary);
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

    test('ramène la point release Debian (13.6) au majeur (13)', () {
      final os = ociParserSyftDistroToOsInfo({
        'distro': {'id': 'debian', 'versionID': '13.6'},
      })!;
      expect(os.version, '13');
    });

    test('conserve le mineur pour une distro non Debian (rhel 9.6)', () {
      final os = ociParserSyftDistroToOsInfo({
        'distro': {'id': 'rhel', 'versionID': '9.6'},
      })!;
      expect(os.version, '9.6');
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

  group('OciParser (backend syft) — champs de composant', () {
    test('reprend le mainteneur dpkg (clé minuscule) comme vendor/supplier', () {
      final pkg = ociParserSyftArtifactToPackage({
        'name': 'apt',
        'version': '3.0.3',
        'type': 'deb',
        'metadata': {
          'package': 'apt',
          'architecture': 'amd64',
          'maintainer': 'APT Development Team <deity@lists.debian.org>',
        },
      }, 'debian.tar')!;

      expect(pkg.vendor, 'APT Development Team <deity@lists.debian.org>');
      // La clé syft est `architecture` (minuscule) — était ignorée avant.
      expect(pkg.arch, 'amd64');
    });

    test(
        'ramène distro=debian-13.6 au majeur et ajoute distro_name '
        '(compat OSV-Scanner)', () {
      final pkg = ociParserSyftArtifactToPackage({
        'name': 'apt',
        'version': '3.0.3',
        'type': 'deb',
        'purl': 'pkg:deb/debian/apt@3.0.3?arch=amd64&distro=debian-13.6',
      }, 'debian.tar', distroCodename: 'trixie')!;

      expect(pkg.purl,
          'pkg:deb/debian/apt@3.0.3?arch=amd64&distro=debian-13&distro_name=trixie');
    });

    test('ajoute distro_name même quand distro=debian-13 est déjà au majeur',
        () {
      final pkg = ociParserSyftArtifactToPackage({
        'name': 'bash',
        'version': '5.2.37',
        'type': 'deb',
        'purl': 'pkg:deb/debian/bash@5.2.37?arch=amd64&distro=debian-13',
      }, 'debian.tar', distroCodename: 'trixie')!;

      expect(pkg.purl,
          'pkg:deb/debian/bash@5.2.37?arch=amd64&distro=debian-13&distro_name=trixie');
    });

    test(
        'retire upstream= du binaire quand un paquet source distinct existe '
        '(évite le double comptage Grype)', () {
      final pkg = ociParserSyftArtifactToPackage({
        'name': 'zlib1g',
        'version': '1:1.3.dfsg+really1.3.1-1+b1',
        'type': 'deb',
        'metadata': {'source': 'zlib', 'sourceVersion': '1:1.3.dfsg+really1.3.1-1'},
        'purl': 'pkg:deb/debian/zlib1g@1%3A1.3.dfsg%2Breally1.3.1-1%2Bb1'
            '?arch=amd64&distro=debian-13&upstream=zlib%401%3A1.3.dfsg&distro_name=trixie',
      }, 'debian.tar')!;

      expect(pkg.purl, isNot(contains('upstream=')));
      expect(pkg.purl, contains('distro=debian-13'));
      expect(pkg.purl, contains('distro_name=trixie'));
    });

    test('garde upstream= si la source est identique au nom binaire', () {
      final pkg = ociParserSyftArtifactToPackage({
        'name': 'bash',
        'version': '5.2.37-2',
        'type': 'deb',
        'metadata': {'source': 'bash'},
        'purl': 'pkg:deb/debian/bash@5.2.37-2?arch=amd64&distro=debian-13'
            '&upstream=bash%405.2.37-2',
      }, 'debian.tar')!;
      expect(pkg.purl, contains('upstream='));
    });

    test('_syftSourcePackage : composant source dérivé du binaire', () {
      final src = ociParserSyftSourcePackage({
        'name': 'perl-base',
        'version': '5.40.1-6',
        'type': 'deb',
        'metadata': {'source': 'perl'},
        'purl': 'pkg:deb/debian/perl-base@5.40.1-6?arch=amd64&distro=debian-13.6'
            '&upstream=perl',
      }, 'trixie', 'debian.tar')!;

      expect(src.name, 'perl');
      expect(src.version, '5.40.1-6');
      expect(src.packageType, 'deb');
      expect(src.purl,
          'pkg:deb/debian/perl@5.40.1-6?arch=amd64&distro=debian-13&distro_name=trixie');
    });

    test('_syftSourcePackage : utilise sourceVersion quand fournie', () {
      final src = ociParserSyftSourcePackage({
        'name': 'zlib1g',
        'version': '1:1.3.dfsg+really1.3.1-1+b1',
        'type': 'deb',
        'metadata': {'source': 'zlib', 'sourceVersion': '1:1.3.dfsg+really1.3.1-1'},
        'purl': 'pkg:deb/debian/zlib1g@1%3A1.3.dfsg%2Breally1.3.1-1%2Bb1'
            '?arch=amd64&distro=debian-13&upstream=zlib%401%3A1.3',
      }, 'trixie', 'debian.tar')!;
      expect(src.version, '1:1.3.dfsg+really1.3.1-1');
      expect(src.purl, contains('zlib@1%3A1.3.dfsg%2Breally1.3.1-1?'));
      expect(src.purl, isNot(contains('upstream=')));
    });

    test('_syftSourcePackage : null si source == nom, non-deb, ou déjà présent',
        () {
      expect(
          ociParserSyftSourcePackage(
              {'name': 'bash', 'type': 'deb', 'metadata': {'source': 'bash'}},
              'trixie', 'i.tar'),
          isNull);
      expect(
          ociParserSyftSourcePackage(
              {'name': 'foo', 'type': 'npm', 'metadata': {'source': 'bar'}},
              'trixie', 'i.tar'),
          isNull);
      expect(
          ociParserSyftSourcePackage(
              {'name': 'perl-base', 'type': 'deb', 'metadata': {'source': 'perl'}},
              'trixie', 'i.tar', existingNames: {'perl'}),
          isNull);
    });

    test('laisse intact un PURL alpine (le mineur y est signifiant)', () {
      final pkg = ociParserSyftArtifactToPackage({
        'name': 'musl',
        'version': '1.2.5',
        'type': 'apk',
        'purl': 'pkg:apk/alpine/musl@1.2.5?arch=x86_64&distro=alpine-3.20.3',
      }, 'alpine.tar', distroCodename: 'v3.20')!;

      expect(pkg.purl,
          'pkg:apk/alpine/musl@1.2.5?arch=x86_64&distro=alpine-3.20.3');
    });

    test('reprend vendor rpm (clé minuscule)', () {
      final pkg = ociParserSyftArtifactToPackage({
        'name': 'bash',
        'version': '5.2.15',
        'type': 'rpm',
        'metadata': {'arch': 'x86_64', 'vendor': 'Red Hat, Inc.'},
      }, 'ubi9.tar')!;
      expect(pkg.vendor, 'Red Hat, Inc.');
      expect(pkg.arch, 'x86_64');
    });
  });

  group('OciParser (backend cdxgen) — filtrage & normalisation des composants',
      () {
    test('conserve un composant deb avec son PURL et son arch', () {
      final pkg = ociParserCdxgenComponentToPackage({
        'type': 'library',
        'name': 'adduser',
        'version': '3.134',
        'group': 'debian',
        'purl': 'pkg:deb/debian/adduser@3.134'
            '?arch=all&distro=debian-12&distro_name=bookworm',
        'supplier': {'name': 'Debian Adduser Developers'},
        'hashes': [
          {'alg': 'SHA-256', 'content': 'c' * 64},
        ],
        'licenses': [
          {
            'license': {'id': 'GPL-2.0-or-later'}
          },
        ],
      }, 'debian.tar')!;

      expect(pkg.name, 'adduser');
      expect(pkg.version, '3.134');
      // Le PURL de cdxgen (avec distro=) est repris tel quel — grype en a besoin.
      expect(pkg.purl,
          'pkg:deb/debian/adduser@3.134?arch=all&distro=debian-12&distro_name=bookworm');
      expect(pkg.packageType, 'deb');
      expect(pkg.arch, 'all');
      expect(pkg.license, 'GPL-2.0-or-later');
      expect(pkg.vendor, 'Debian Adduser Developers');
      expect(pkg.hashes, [PackageHash('SHA-256', 'c' * 64)]);
    });

    test('écarte les composants de type file (inventaire fichiers cdxgen)', () {
      expect(
        ociParserCdxgenComponentToPackage({
          'type': 'file',
          'name': 'AdduserCommon.pm',
          'purl': 'pkg:generic/AdduserCommon.pm#usr/share/perl5/Debian/AdduserCommon.pm',
        }, 'debian.tar'),
        isNull,
      );
    });

    test('écarte les PURL pkg:generic (dépôts APT, binaires non tracés)', () {
      expect(
        ociParserCdxgenComponentToPackage({
          'type': 'data',
          'name': 'deb.debian.org/debian',
          'version': 'bookworm',
          'purl': 'pkg:generic/os-repository/deb.debian.org%2Fdebian@bookworm',
        }, 'debian.tar'),
        isNull,
      );
    });

    test('écarte les actifs cryptographiques', () {
      expect(
        ociParserCdxgenComponentToPackage({
          'type': 'cryptographic-asset',
          'name': 'RSA-2048',
          'purl': 'pkg:generic/rsa',
        }, 'debian.tar'),
        isNull,
      );
    });

    test('recombine groupId:artifactId pour un composant maven', () {
      final pkg = ociParserCdxgenComponentToPackage({
        'type': 'library',
        'name': 'guava',
        'version': '33.0.0-jre',
        'group': 'com.google.guava',
        'purl': 'pkg:maven/com.google.guava/guava@33.0.0-jre',
      }, 'app.tar')!;
      expect(pkg.name, 'com.google.guava:guava');
      expect(pkg.packageType, 'java');
    });

    test('licence au format expression CycloneDX', () {
      final pkg = ociParserCdxgenComponentToPackage({
        'type': 'library',
        'name': 'openssl',
        'version': '3.0.11',
        'purl': 'pkg:deb/debian/openssl@3.0.11',
        'licenses': [
          {'expression': 'Apache-2.0 AND OpenSSL'},
        ],
      }, 'debian.tar')!;
      expect(pkg.license, 'Apache-2.0 AND OpenSSL');
    });
  });

  group('OciParser (backend cdxgen) — OS de base depuis le qualifiant distro',
      () {
    test('debian-12 → id debian, version 12', () {
      final os = ociParserCdxgenOsInfo('debian-12')!;
      expect(os.id, 'debian');
      expect(os.version, '12');
    });

    test('alpine-3.19 → id alpine, version 3.19', () {
      final os = ociParserCdxgenOsInfo('alpine-3.19')!;
      expect(os.id, 'alpine');
      expect(os.version, '3.19');
    });

    test('traduit rhel-9 vers la famille Trivy redhat', () {
      final os = ociParserCdxgenOsInfo('rhel-9')!;
      expect(os.id, 'redhat');
      expect(os.version, '9');
    });

    test('retourne null quand aucun qualifiant distro (image distroless)', () {
      expect(ociParserCdxgenOsInfo(null), isNull);
      expect(ociParserCdxgenOsInfo(''), isNull);
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
