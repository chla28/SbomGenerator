import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sbom_generator/hash_utils.dart';
import 'package:sbom_generator/models.dart';
import 'package:test/test.dart';

void main() {
  final sha256Hex = 'a' * 64;
  final sha512Hex = 'b' * 128;

  group('normalizeHashAlg', () {
    test('formes équivalentes → libellé CycloneDX', () {
      expect(normalizeHashAlg('sha256'), 'SHA-256');
      expect(normalizeHashAlg('SHA-256'), 'SHA-256');
      expect(normalizeHashAlg('SHA256'), 'SHA-256');
      expect(normalizeHashAlg('sha512'), 'SHA-512');
      expect(normalizeHashAlg('sha1'), 'SHA-1');
      expect(normalizeHashAlg('md5'), 'MD5');
      expect(normalizeHashAlg('sha3-256'), 'SHA3-256');
    });

    test('inconnu / non standard → null', () {
      expect(normalizeHashAlg('h1'), isNull);
      expect(normalizeHashAlg('sha224'), isNull);
      expect(normalizeHashAlg('crc32'), isNull);
    });
  });

  group('packageHash', () {
    test('rejette une valeur non hexadécimale ou de mauvaise longueur', () {
      expect(packageHash('SHA-256', 'deadbeef'), isNull);
      expect(packageHash('SHA-256', 'z' * 64), isNull);
      expect(
          packageHash('SHA-256', sha256Hex), PackageHash('SHA-256', sha256Hex));
    });

    test('normalise la casse de la valeur', () {
      expect(packageHash('SHA-256', ('A' * 64))!.content, sha256Hex);
    });
  });

  group('packageHashFromDigestString (Trivy `Digest`)', () {
    test('parse "<algo>:<hex>"', () {
      expect(packageHashFromDigestString('sha256:$sha256Hex'),
          PackageHash('SHA-256', sha256Hex));
      expect(packageHashFromDigestString('md5:${'c' * 32}'),
          PackageHash('MD5', 'c' * 32));
    });

    test('null si mal formé', () {
      expect(packageHashFromDigestString('sha256'), isNull);
      expect(packageHashFromDigestString(null), isNull);
    });
  });

  group('packageHashFromSri (npm/yarn `integrity`)', () {
    test('sha512-<base64> → SHA-512 hexadécimal', () {
      final bytes = Uint8List.fromList(List.filled(64, 0xab));
      final h = packageHashFromSri('sha512-${base64.encode(bytes)}');
      expect(h, isNotNull);
      expect(h!.alg, 'SHA-512');
      expect(h.content, 'ab' * 64);
    });

    test('null si vide ou invalide', () {
      expect(packageHashFromSri(''), isNull);
      expect(packageHashFromSri('sha999-abc'), isNull);
    });
  });

  group('hashesFromSyftMetadata', () {
    test('lit archiveDigests / digests / digest (liste ou objet)', () {
      final out = hashesFromSyftMetadata({
        'archiveDigests': [
          {'algorithm': 'sha1', 'value': 'd' * 40},
        ],
        'digest': {'algorithm': 'sha256', 'value': sha256Hex},
      });
      expect(out, contains(PackageHash('SHA-1', 'd' * 40)));
      expect(out, contains(PackageHash('SHA-256', sha256Hex)));
    });

    test('ignore un h1Digest Go (non standard)', () {
      final out = hashesFromSyftMetadata({'h1Digest': 'h1:abcd'});
      expect(out, isEmpty);
    });
  });

  group('hashesFromCycloneDx', () {
    test('parse [{alg, content}] et filtre les entrées invalides', () {
      final out = hashesFromCycloneDx([
        {'alg': 'SHA-256', 'content': sha256Hex},
        {'alg': 'SHA-256', 'content': 'trop court'},
        {'alg': 'h1', 'content': 'x'},
      ]);
      expect(out, [PackageHash('SHA-256', sha256Hex)]);
    });
  });

  group('hashLocalFile', () {
    test('calcule SHA-256 + SHA-512 d\'un fichier', () {
      final tmp =
          File('${Directory.systemTemp.createTempSync('hash_').path}/data.bin')
            ..writeAsStringSync('hello');
      final out = hashLocalFile(tmp.path);
      expect(out.map((h) => h.alg), ['SHA-256', 'SHA-512']);
      expect(out.first.content,
          '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });

    test('liste vide si le fichier est absent', () {
      expect(hashLocalFile('/nonexistent/x'), isEmpty);
    });
  });

  group('conversion de libellés', () {
    test('spdx2Alg', () {
      expect(spdx2Alg('SHA-256'), 'SHA256');
      expect(spdx2Alg('SHA-1'), 'SHA1');
      expect(spdx2Alg('SHA3-256'), 'SHA3-256');
    });

    test('spdx3Alg', () {
      expect(spdx3Alg('SHA-256'), 'sha256');
      expect(spdx3Alg('SHA-512'), 'sha512');
      expect(spdx3Alg('SHA3-256'), 'sha3_256');
    });
  });

  // Garde-fou : le hex de "hello" ci-dessus est stable — sert de référence.
  test('sanity SHA-512 hex length', () => expect(sha512Hex.length, 128));
}
