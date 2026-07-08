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
}
