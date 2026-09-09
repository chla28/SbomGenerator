import 'package:sbom_generator/models.dart';
import 'package:test/test.dart';

void main() {
  group('Package.copyWith', () {
    final rpm = RpmPackage(
      name: 'bash', version: '5.2', release: '1.el9', arch: 'x86_64',
      epoch: '(none)', license: 'GPLv3+', vendor: 'Red Hat, Inc.',
      url: 'https://gnu.org/bash', buildTime: '1700000000', summary: 's',
      requires: const ['glibc'], provides: const ['bash'],
      hashes: [PackageHash('SHA-256', 'a' * 64)],
      headerSha256: 'f' * 64, sourceRpm: 'bash-5.2-1.el9.src.rpm',
      sourceRef: 'bash',
    );
    final wheel = WheelPackage(
      name: 'requests', version: '2.31.0', license: 'Apache-2.0',
      url: '', summary: '', vendor: '', arch: 'any', sourceRef: 'r.txt',
      hashes: [PackageHash('SHA-512', 'b' * 128)],
      requires: const [], provides: const ['requests'], packageType: 'pypi',
    );

    test('remplace uniquement license, garde le type et les autres champs', () {
      final r = rpm.copyWith(license: 'MIT');
      expect(r, isA<RpmPackage>());
      expect(r.license, 'MIT');
      expect(r.vendor, 'Red Hat, Inc.');
      expect(r.version, '5.2');
      expect(r.headerSha256, 'f' * 64);
      expect(r.hashes, rpm.hashes);
      expect(r.purl, rpm.purl);
    });

    test('remplace uniquement vendor', () {
      final w = wheel.copyWith(vendor: 'ACME');
      expect(w, isA<WheelPackage>());
      expect(w.vendor, 'ACME');
      expect(w.license, 'Apache-2.0');
      expect(w.packageType, 'pypi');
      expect(w.hashes, wheel.hashes);
    });

    test('sans argument = copie identique', () {
      final w = wheel.copyWith();
      expect(w.name, wheel.name);
      expect(w.vendor, wheel.vendor);
      expect(w.license, wheel.license);
    });

    test('DebPackage et OciPackage conservent leur type', () {
      final deb = DebPackage(
        name: 'curl', version: '8.0', arch: 'amd64', license: '',
        vendor: 'Debian', url: '', summary: '', sourceRef: 'c.deb',
        requires: const [], provides: const ['curl'],
      );
      final oci = OciPackage(
        name: 'openssl', version: '3.0', license: '', vendor: '',
        url: '', summary: '', arch: 'x86_64', sourceRef: 'img', imageRef: 'img',
        requires: const [], provides: const ['openssl'], packageType: 'rpm',
        purlOverride: 'pkg:rpm/openssl@3.0',
      );
      expect(deb.copyWith(vendor: 'X'), isA<DebPackage>());
      final o = oci.copyWith(vendor: 'X');
      expect(o, isA<OciPackage>());
      expect(o.purl, 'pkg:rpm/openssl@3.0'); // purlOverride préservé
    });
  });
}
