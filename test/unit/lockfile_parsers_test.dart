import 'dart:convert';
import 'dart:io';

import 'package:sbom_generator/cargo_parser.dart';
import 'package:sbom_generator/composer_parser.dart';
import 'package:sbom_generator/gem_parser.dart';
import 'package:sbom_generator/pnpm_parser.dart';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('lockfiles_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  String write(String name, String content) {
    final f = File('${tmp.path}/$name')..writeAsStringSync(content);
    return f.path;
  }

  final sha256 = 'a' * 64;
  // SRI sha512 valide (64 octets) : le base64 doit être canonique.
  final sri = 'sha512-${base64.encode(List.filled(64, 7))}';

  group('CargoParser', () {
    test('crates externes avec checksum ; membres du workspace ignorés', () {
      final path = write('Cargo.lock', '''
version = 3

[[package]]
name = "mon-appli"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "$sha256"
''');
      final pkgs = CargoParser().parseCargoLock(path);
      expect(pkgs, hasLength(1));
      expect(pkgs.single.name, 'serde');
      expect(pkgs.single.version, '1.0.200');
      expect(pkgs.single.purl, 'pkg:cargo/serde@1.0.200');
      expect(pkgs.single.hashes.single.content, sha256);
    });

    test('fichier absent : liste vide', () {
      expect(CargoParser().parseCargoLock('${tmp.path}/nope'), isEmpty);
    });
  });

  group('PnpmParser', () {
    test('format v9 : clés name@version, paquets à scope, suffixe de pairs',
        () {
      final path = write('pnpm-lock.yaml', '''
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:

  '@babel/core@7.24.0':
    resolution: {integrity: $sri}
    engines: {node: '>=6.9.0'}

  lodash@4.17.21:
    resolution: {integrity: $sri}

  react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: $sri}

snapshots:

  lodash@4.17.21: {}
''');
      final pkgs = PnpmParser().parsePnpmLock(path);
      expect(pkgs.map((p) => '${p.name}@${p.version}'),
          ['@babel/core@7.24.0', 'lodash@4.17.21', 'react-dom@18.2.0']);
      expect(pkgs.first.purl, 'pkg:npm/%40babel%2Fcore@7.24.0');
      expect(pkgs.every((p) => p.hashes.length == 1), isTrue);
    });

    test('formats v5 (/nom/version) et v6 (/nom@version)', () {
      final path = write('pnpm-lock.yaml', '''
lockfileVersion: 5.4

packages:

  /lodash/4.17.21:
    resolution: {integrity: $sri}
    dev: false

  /@scope/pkg/1.2.3_react@18.0.0:
    resolution: {integrity: $sri}
    dev: false

  /chalk@5.3.0:
    resolution: {integrity: $sri}
''');
      final pkgs = PnpmParser().parsePnpmLock(path);
      expect(pkgs.map((p) => '${p.name}@${p.version}'),
          ['lodash@4.17.21', '@scope/pkg@1.2.3', 'chalk@5.3.0']);
    });

    test('paquet git sans version semver ignoré', () {
      final path = write('pnpm-lock.yaml', '''
packages:

  mylib@https://codeload.github.com/o/r/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/o/r/tar.gz/abc}
''');
      expect(PnpmParser().parsePnpmLock(path), isEmpty);
    });
  });

  group('ComposerParser', () {
    test('packages et packages-dev ; préfixe v retiré ; licence et auteur', () {
      final path = write('composer.lock', '''
{
  "packages": [
    {
      "name": "Monolog/Monolog",
      "version": "v3.5.0",
      "description": "Logging",
      "license": ["MIT"],
      "authors": [{"name": "Jordi Boggiano"}],
      "dist": {"shasum": "${'b' * 40}", "url": "https://x"}
    }
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "version": "10.5.0", "dist": {"shasum": ""}}
  ]
}
''');
      final pkgs = ComposerParser().parseComposerLock(path);
      expect(pkgs, hasLength(2));
      expect(pkgs.first.purl, 'pkg:composer/monolog/monolog@3.5.0');
      expect(pkgs.first.license, 'MIT');
      expect(pkgs.first.vendor, 'Jordi Boggiano');
      expect(pkgs.first.hashes.single.alg, 'SHA-1');
      expect(pkgs.last.hashes, isEmpty);
    });

    test('JSON invalide : liste vide', () {
      expect(
          ComposerParser().parseComposerLock(write('composer.lock', '{nope')),
          isEmpty);
    });
  });

  group('GemParser', () {
    test('specs de GEM, plateforme retirée, PATH ignoré, CHECKSUMS lus', () {
      final path = write('Gemfile.lock', '''
PATH
  remote: .
  specs:
    mon_gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.15.4-x86_64-linux)
      racc (~> 1.4)
    racc (1.7.1)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  nokogiri

CHECKSUMS
  nokogiri (1.15.4-x86_64-linux) sha256=$sha256
  racc (1.7.1) sha256=${'c' * 64}

BUNDLED WITH
   2.5.3
''');
      final pkgs = GemParser().parseGemfileLock(path);
      expect(pkgs.map((p) => '${p.name}@${p.version}'),
          ['nokogiri@1.15.4', 'racc@1.7.1']);
      expect(pkgs.first.purl, 'pkg:gem/nokogiri@1.15.4');
      expect(pkgs.first.hashes.single.content, sha256);
    });
  });
}
