/// Exécute `RpmParser.parsePackage` contre la vraie base RPM installée.
/// Se saute si `rpm` est absent (environnement non RPM).
@TestOn('posix')
library;

import 'dart:io';

import 'package:sbom_generator/rpm_parser.dart';
import 'package:test/test.dart';

Future<bool> _rpmAvailable() async {
  try {
    final r = await Process.run('rpm', ['--version']);
    if (r.exitCode != 0) return false;
    // `rpm` doit aussi être un paquet installé pour le test.
    final q = await Process.run('rpm', ['-q', 'rpm']);
    return q.exitCode == 0;
  } on ProcessException {
    return false;
  }
}

final _hex64 = RegExp(r'^[0-9a-f]{64}$');
final _hex32 = RegExp(r'^[0-9a-f]{32}$');

void main() {
  test('paquet installé : SIGMD5 → empreinte MD5, en-tête → rpm:header-sha256',
      () async {
    if (!await _rpmAvailable()) {
      markTestSkipped('rpm indisponible');
      return;
    }
    final pkg = await RpmParser().parsePackage('rpm');
    expect(pkg, isNotNull);
    expect(pkg!.name, 'rpm');
    expect(pkg.version, isNotEmpty);

    // %{SIGMD5} = « pkgid » (MD5 en-tête + payload) → seule empreinte pour un
    // paquet installé (pas de fichier .rpm à hacher).
    expect(pkg.hashes, hasLength(1));
    expect(pkg.hashes.single.alg, 'MD5');
    expect(_hex32.hasMatch(pkg.hashes.single.content), isTrue);

    // %{SHA256HEADER} reste à part (hash de l'en-tête, pas du fichier).
    expect(_hex64.hasMatch(pkg.headerSha256), isTrue);
  }, timeout: const Timeout(Duration(seconds: 30)));
}
