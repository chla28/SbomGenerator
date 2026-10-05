import 'dart:convert';
import 'dart:io';

import 'package:sbom_generator/vuln_enrichment.dart';
import 'package:test/test.dart';

void main() {
  group('parseCvssVector', () {
    test('v3.1 AV:N/AC:L/PR:N/UI:N → exploitabilité 3.9', () {
      final r = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      expect(r.exploitability, closeTo(3.9, 0.05));
      expect(r.maturity, isNull);
    });

    test('maturité E:H extraite du vecteur', () {
      final r =
          parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H');
      expect(r.maturity, 'High');
      expect(r.exploitability, closeTo(3.9, 0.05));
    });

    test('E:P → Proof-of-Concept, E:U → Unproven', () {
      expect(parseCvssVector('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/E:P').maturity,
          'Proof-of-Concept');
      expect(parseCvssVector('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/E:U').maturity,
          'Unproven');
    });

    test('scope changed relève le poids PR', () {
      final u = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U');
      final c = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C');
      expect(c.exploitability! > u.exploitability!, isTrue);
    });

    test('vecteur v2 : pas d\'exploitabilité v3, maturité seule si E:', () {
      final r = parseCvssVector('AV:N/AC:L/Au:N/C:P/I:P/A:P');
      expect(r.exploitability, isNull);
    });

    test('vecteur nul ou vide', () {
      expect(parseCvssVector(null).exploitability, isNull);
      expect(parseCvssVector('').maturity, isNull);
    });
  });

  group('ExploitInfo.riskScore', () {
    test('KEV domine EPSS et sévérité', () {
      final kevLow = ExploitInfo(inKev: true, epssScore: 0.01);
      final noKevHigh = ExploitInfo(epssScore: 0.99);
      expect(kevLow.riskScore('low') > noKevHigh.riskScore('critical'), isTrue);
    });

    test('à KEV égal, EPSS puis sévérité départagent', () {
      final a = ExploitInfo(epssScore: 0.5);
      final b = ExploitInfo(epssScore: 0.2);
      expect(a.riskScore('low') > b.riskScore('low'), isTrue);
      expect(b.riskScore('critical') > b.riskScore('low'), isTrue);
    });
  });

  group('VulnEnricher', () {
    late Directory tmp;
    setUp(() => tmp = Directory.systemTemp.createTempSync('venrich_'));
    tearDown(() => tmp.deleteSync(recursive: true));

    test('hors-ligne : combine la graine du scanner, aucune requête', () async {
      final enricher = VulnEnricher(
        enableNetwork: false,
        cacheDir: tmp,
        httpClientFactory: () => throw StateError('réseau interdit'),
      );
      final out = await enricher.enrich({
        'CVE-2021-44228'
      }, seed: {
        'CVE-2021-44228': const CveSeed(
          kev: true,
          kevRansomware: true,
          epssScore: 0.97,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        ),
      });
      final e = out['CVE-2021-44228']!;
      expect(e.inKev, isTrue);
      expect(e.kevRansomware, isTrue);
      expect(e.epssScore, 0.97);
      expect(e.cvssExploitabilityScore, closeTo(3.9, 0.05));
    });

    test('en ligne : récupère KEV + EPSS depuis des serveurs locaux', () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((req) async {
        if (req.uri.path.contains('known_exploited')) {
          req.response.write(jsonEncode({
            'vulnerabilities': [
              {
                'cveID': 'CVE-2021-44228',
                'dateAdded': '2021-12-10',
                'dueDate': '2021-12-24',
                'knownRansomwareCampaignUse': 'Known',
              }
            ]
          }));
        } else if (req.uri.path.contains('epss')) {
          req.response.write(jsonEncode({
            'data': [
              {'cve': 'CVE-2021-44228', 'epss': '0.94', 'percentile': '0.99'}
            ]
          }));
        } else {
          req.response.write('{}');
        }
        await req.response.close();
      });
      final base = 'http://${server.address.host}:${server.port}';
      final enricher = VulnEnricher(
        cacheDir: tmp,
        enablePoc: false,
        kevFeedUrl: Uri.parse('$base/known_exploited_vulnerabilities.json'),
        epssApiUrl: Uri.parse('$base/epss'),
      );
      final out = await enricher.enrich({'CVE-2021-44228'});
      await server.close(force: true);

      final e = out['CVE-2021-44228']!;
      expect(e.inKev, isTrue);
      expect(e.kevDueDate, DateTime(2021, 12, 24));
      expect(e.kevRansomware, isTrue);
      expect(e.epssScore, closeTo(0.94, 0.001));
      expect(e.epssPercentile, closeTo(0.99, 0.001));

      // Cache écrit → relecture hors-ligne sans réseau.
      final offline = VulnEnricher(
        enableNetwork: false,
        cacheDir: tmp,
        httpClientFactory: () => throw StateError('réseau interdit'),
      );
      final again = await offline.enrich({'CVE-2021-44228'});
      expect(again['CVE-2021-44228']!.inKev, isTrue);
      expect(again['CVE-2021-44228']!.epssScore, closeTo(0.94, 0.001));
    });

    test('réseau en échec : dégradation silencieuse, pas d\'exception',
        () async {
      final enricher = VulnEnricher(
        cacheDir: tmp,
        timeout: const Duration(milliseconds: 50),
        kevFeedUrl: Uri.parse('http://127.0.0.1:1/kev.json'),
        epssApiUrl: Uri.parse('http://127.0.0.1:1/epss'),
        pocApiBase: Uri.parse('http://127.0.0.1:1/'),
      );
      final out = await enricher.enrich({'CVE-2021-44228'});
      expect(out['CVE-2021-44228']!.inKev, isFalse);
      expect(out['CVE-2021-44228']!.epssScore, isNull);
    });
  });
}
