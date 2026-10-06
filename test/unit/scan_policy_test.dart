import 'dart:convert';
import 'dart:io';

import 'package:sbom_generator/scan_policy.dart';
import 'package:test/test.dart';

void main() {
  final now = DateTime(2026, 6, 15);

  test('severityRank : ordre et synonymes', () {
    expect(severityRank('Critical') > severityRank('HIGH'), isTrue);
    expect(severityRank('moderate'), severityRank('Medium'));
    expect(severityRank('Unknown'), 0);
  });

  group('IgnoreList', () {
    final list = IgnoreList.parse('''
# commentaire
CVE-1; package=openssl; expires=2026-12-31; reason=non joignable
CVE-2; expires=2026-01-01; reason=expirée
CVE-3
cve 4 invalide
CVE-5; expires=pas-une-date; reason=x
''');

    test('lecture des règles et avertissements', () {
      expect(
          list.entries.map((e) => e.id), ['CVE-1', 'CVE-2', 'CVE-3', 'CVE-5']);
      expect(list.warnings.any((w) => w.contains('CVE-3')), isTrue,
          reason: 'justification manquante');
      expect(list.warnings.any((w) => w.contains('pas-une-date')), isTrue);
      expect(list.warnings.any((w) => w.contains('ligne 5')), isTrue);
    });

    test('portée par paquet et insensibilité à la casse', () {
      expect(list.match('cve-1', 'openssl@3.0', now), isNotNull);
      expect(list.match('CVE-1', 'zlib@1.0', now), isNull);
      expect(list.match('CVE-3', 'nimporte@1', now), isNotNull);
    });

    test('expiration inclusive : valable jusqu\'à la fin du jour', () {
      expect(list.match('CVE-2', 'x@1', now), isNull);
      expect(list.expired(now).map((e) => e.id), ['CVE-2']);
      final lastDay = DateTime(2026, 12, 31, 18);
      expect(list.match('CVE-1', 'openssl@1', lastDay), isNotNull);
      expect(list.match('CVE-1', 'openssl@1', DateTime(2027, 1, 1)), isNull);
    });

    test('paquet npm à portée : le nom garde son @ initial', () {
      final l = IgnoreList.parse('CVE-9; package=@scope/pkg; reason=r');
      expect(l.match('CVE-9', '@scope/pkg@1.2.3', now), isNotNull);
    });
  });

  group('Baseline', () {
    test('clé = identifiant + nom de paquet (la version n\'y est pas)', () {
      final b = Baseline.fromJson({
        'findings': [
          {'id': 'CVE-1', 'package': 'foo@1.0'},
        ],
      });
      expect(b.contains('cve-1', 'foo@2.0'), isTrue);
      expect(b.contains('CVE-1', 'bar@1.0'), isFalse);
      expect(b.length, 1);
    });

    test('fichier sans "findings" → FormatException', () {
      expect(() => Baseline.fromJson({'x': 1}), throwsFormatException);
    });
  });

  group('ScanCache', () {
    late Directory dir;
    setUp(() => dir = Directory.systemTemp.createTempSync('scancache_'));
    tearDown(() => dir.deleteSync(recursive: true));

    String sbom(String ts, String uuid, List<String> names) {
      final f = File('${dir.path}/s_$ts.json');
      f.writeAsStringSync(jsonEncode({
        'bomFormat': 'CycloneDX',
        'serialNumber': uuid,
        'metadata': {'timestamp': ts},
        'components': [
          for (final n in names)
            {'name': n, 'version': '1', 'purl': 'pkg:x/$n@1'},
        ],
      }));
      return f.path;
    }

    test('empreinte indépendante de l\'horodatage, de l\'UUID et de l\'ordre',
        () {
      final a = ScanCache.sbomDigest(sbom('t1', 'u1', ['a', 'b']));
      final b = ScanCache.sbomDigest(sbom('t2', 'u2', ['b', 'a']));
      final c = ScanCache.sbomDigest(sbom('t3', 'u3', ['a', 'c']));
      expect(a, b);
      expect(a, isNot(c));
    });

    test('lecture, expiration (TTL) et clé par scanner/version', () {
      final cache =
          ScanCache(Directory('${dir.path}/c'), const Duration(hours: 1));
      final t0 = DateTime.utc(2026, 1, 1, 12);
      cache.write(
          'd',
          'grype',
          '0.9',
          [
            {'id': 'CVE-1', 'severity': 'High'}
          ],
          t0);
      expect(
          cache.read('d', 'grype', '0.9', t0.add(const Duration(minutes: 30))),
          [
            {'id': 'CVE-1', 'severity': 'High'}
          ]);
      expect(cache.read('d', 'grype', '0.9', t0.add(const Duration(hours: 2))),
          isNull);
      expect(cache.read('d', 'grype', '1.0', t0), isNull);
      expect(cache.read('d', 'trivy', '0.9', t0), isNull);
    });
  });
}
