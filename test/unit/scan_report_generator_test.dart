import 'package:sbom_generator/scan_report_generator.dart';
import 'package:sbom_generator/vuln_enrichment.dart';
import 'package:test/test.dart';

Map<String, dynamic> _v(String id, String sev) => {
      'id': id,
      'severity': sev,
      'package': 'p@1',
      'published': null,
      'modified': null
    };

void main() {
  group('ScanReportGenerator', () {
    test('résumé global : scanners exécutés, CVE uniques, total brut', () {
      final gen = ScanReportGenerator(
        sbomPath: 'sbom.cdx.json',
        generatedAt: DateTime.utc(2026, 1, 2, 3, 4),
        resultsByScanner: {
          'grype': [_v('CVE-2026-1', 'High'), _v('CVE-2026-2', 'Low')],
          'trivy': [_v('CVE-2026-2', 'Medium'), _v('CVE-2026-3', 'Critical')],
          // osv absent → "non exécuté"
        },
      );
      final md = gen.toMarkdown();
      expect(md, contains('| Scanners exécutés | 2 / 3'));
      // CVE-1, CVE-2, CVE-3 → 3 uniques
      expect(md, contains('| CVE uniques (tous scanners) | 3 |'));
      expect(md, contains('| Résultats bruts cumulés | 4 |'));
      expect(md, contains('_Non exécuté._'));
    });

    test('normalise les CVE préfixées distro d\'OSV-Scanner pour le comptage',
        () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [_v('CVE-2026-13221', 'Critical')],
          'osv': [_v('DEBIAN-CVE-2026-13221', 'Medium')],
        },
      );
      // Même vulnérabilité → 1 seule CVE unique, 1 seule ligne inter-scanners.
      expect(gen.toMarkdown(), contains('| CVE uniques (tous scanners) | 1 |'));
      final adoc = gen.toAsciiDoc();
      expect('CVE-2026-13221'.allMatches(adoc).length, 1);
      expect(adoc, isNot(contains('DEBIAN-CVE-2026-13221')));
    });

    test('matrice inter-scanners : ✓/— par scanner, pire sévérité affichée',
        () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [_v('CVE-2026-9', 'Unknown')],
          'trivy': [_v('CVE-2026-9', 'High')],
          'osv': <Map<String, dynamic>>[],
        },
      );
      final adoc = gen.toAsciiDoc();
      // pire sévérité = High (pas Unknown de grype)
      expect(adoc, contains('| [.sev-high]#ÉLEVÉE# | CVE-2026-9 | ✓ | — | ✓'));
    });

    test('note par CVE : Grype won\'t fix + version corrigée annoncée ailleurs',
        () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [
            {
              'id': 'CVE-2026-8376',
              'severity': 'Critical',
              'package': 'perl-base@5.40.1-6',
              'fixState': 'wont-fix',
              'fixedVersions': <String>[],
            },
          ],
          'osv': [
            {
              'id': 'DEBIAN-CVE-2026-8376',
              'severity': 'Critical',
              'package': 'perl@5.40.1-6',
              'fixedVersions': ['5.40.1-8'],
            },
          ],
        },
      );

      expect(
          gen.cveNotes(), containsPair('CVE-2026-8376', contains('5.40.1-8')));
      final md = gen.toMarkdown();
      expect(md, contains('### Notes par CVE'));
      expect(md, contains('**CVE-2026-8376** (`perl-base@5.40.1-6`)'));
      expect(md, contains('unstable'));
      expect(gen.toAsciiDoc(), contains('=== Notes par CVE'));
    });

    test('pas de note si Grype voit un correctif (fixState=fixed)', () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [
            {
              'id': 'CVE-2026-1',
              'severity': 'High',
              'package': 'foo@1',
              'fixState': 'fixed',
              'fixedVersions': ['2'],
            },
          ],
          'osv': [
            {
              'id': 'CVE-2026-1',
              'severity': 'High',
              'package': 'foo@1',
              'fixedVersions': ['2']
            },
          ],
        },
      );
      expect(gen.cveNotes(), isEmpty);
      expect(gen.toMarkdown(), isNot(contains('Notes par CVE')));
    });

    test('pas de note si aucun autre scanner n\'annonce de version corrigée',
        () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [
            {
              'id': 'CVE-2026-2',
              'severity': 'High',
              'package': 'bar@1',
              'fixState': 'wont-fix',
              'fixedVersions': <String>[]
            },
          ],
          'osv': [
            {
              'id': 'CVE-2026-2',
              'severity': 'High',
              'package': 'bar@1',
              'fixedVersions': <String>[]
            },
          ],
        },
      );
      expect(gen.cveNotes(), isEmpty);
    });

    test('comparaison inter-scanners omise si < 2 scanners exécutés', () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [_v('CVE-2026-1', 'High')],
        },
      );
      expect(gen.toMarkdown(), isNot(contains('Comparaison inter-scanners')));
    });

    test('scanner exécuté sans résultat vs non exécuté', () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': <Map<String, dynamic>>[],
          // trivy, osv absents
        },
      );
      final md = gen.toMarkdown();
      expect(md, contains('### Grype\n\nAucune vulnérabilité détectée.'));
      expect(md, contains('### OSV-Scanner\n\n_Non exécuté._'));
      expect(md, contains('| Scanners exécutés | 1 / 3'));
    });

    test('AsciiDoc : en-tête doctype + badges de sévérité colorés', () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [_v('CVE-2026-1', 'Critical')],
        },
      );
      final adoc = gen.toAsciiDoc();
      expect(adoc, startsWith('= Rapport de vulnérabilités'));
      expect(adoc, contains(':doctype: article'));
      expect(adoc, contains(':title-page:'));
      expect(adoc, contains('[.sev-critical]#CRITIQUE#'));
    });

    test('AsciiDoc : résumé exécutif — encart chiffré + verdict', () {
      final gen = ScanReportGenerator(
        sbomPath: '/tmp/x/mon-sbom.cdx.json',
        resultsByScanner: {
          'grype': [_v('CVE-2026-1', 'Critical'), _v('CVE-2026-2', 'High')],
        },
        exploitById: {
          'CVE-2026-1': const ExploitInfo(inKev: true),
        },
      );
      final adoc = gen.toAsciiDoc();
      expect(adoc, contains('== Résumé exécutif'));
      expect(adoc, contains('`mon-sbom.cdx.json`')); // basename, pas le chemin
      expect(adoc, contains('h| Critiques h| Élevées h| CISA KEV'));
      expect(adoc, contains('[.h1-num-alert]*1*')); // 1 critique → rouge
      expect(adoc, contains('[.verdict-urgent]*Action immédiate requise.'));
    });

    test('alerts() : CVE uniques Critical + High, pire sévérité, scanners', () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [
            _v('CVE-2026-1', 'Critical'),
            _v('CVE-2026-2', 'High'),
            _v('CVE-2026-3', 'Medium'), // exclu
          ],
          'trivy': [
            _v('CVE-2026-2', 'Critical'), // pire sévérité → Critical
            _v('CVE-2026-4', 'Low'), // exclu
          ],
          'osv': <Map<String, dynamic>>[],
        },
      );
      final a = gen.alerts();
      expect(a.map((x) => x.id), ['CVE-2026-1', 'CVE-2026-2']);
      final two = a.firstWhere((x) => x.id == 'CVE-2026-2');
      expect(two.severity.toLowerCase(), 'critical');
      expect(two.scanners, containsAll(['Grype', 'Trivy']));
      expect(a.first.package, 'p@1');
    });

    test('alerts() : normalise les ID distro-préfixés avant dédup', () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [_v('CVE-2026-13221', 'Critical')],
          'osv': [_v('DEBIAN-CVE-2026-13221', 'High')],
        },
      );
      expect(gen.alerts(), hasLength(1));
      expect(gen.alerts().single.id, 'CVE-2026-13221');
    });

    test('alerts() vide si aucune CVE Critical/High', () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [_v('CVE-2026-1', 'Medium'), _v('CVE-2026-2', 'Low')],
        },
      );
      expect(gen.alerts(), isEmpty);
    });

    test('échappe le séparateur de cellule dans les identifiants', () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [_v('GHSA-x|y', 'High')],
          'trivy': [_v('GHSA-x|y', 'High')],
        },
      );
      expect(gen.toAsciiDoc(), contains(r'GHSA-x\|y'));
    });

    group('exploitabilité', () {
      final gen = ScanReportGenerator(
        sbomPath: 's',
        resultsByScanner: {
          'grype': [
            _v('CVE-2021-44228', 'Critical'),
            _v('CVE-2021-45046', 'Critical'),
            _v('CVE-2020-9999', 'High'),
          ],
          'trivy': [_v('CVE-2021-44228', 'Critical')],
        },
        exploitById: {
          'CVE-2021-44228': ExploitInfo(
            inKev: true,
            kevDateAdded: DateTime(2021, 12, 10),
            kevDueDate: DateTime(2021, 12, 24),
            kevRansomware: true,
            epssScore: 0.97,
            epssPercentile: 0.999,
            pocKnown: true,
            pocCount: 42,
            cvssExploitabilityScore: 3.9,
            exploitMaturity: 'High',
          ),
          'CVE-2021-45046': ExploitInfo(
              epssScore: 0.30,
              epssPercentile: 0.98,
              pocKnown: true,
              pocCount: 3),
          // Aucun signal notable → écartée de la priorisation.
          'CVE-2020-9999': ExploitInfo(epssScore: 0.02),
        },
      );

      test('résumé global : compteurs KEV / EPSS / PoC', () {
        final md = gen.toMarkdown();
        expect(md, contains('| CVE activement exploitées (CISA KEV) | 1 |'));
        expect(md, contains('| CVE avec EPSS ≥ 10 % | 2 |'));
        expect(md, contains('| CVE avec PoC / exploit public | 2 |'));
      });

      test('section CISA KEV listée avec dates et rançongiciel', () {
        final md = gen.toMarkdown();
        expect(md, contains('### CVE activement exploitées (CISA KEV)'));
        expect(md, contains('CVE-2021-44228'));
        expect(md, contains('2021-12-10'));
        expect(md, contains('2021-12-24'));
        expect(md, contains('⚠️ oui'));
      });

      test('priorisation par risque : KEV en tête, sans-signal écartée', () {
        final md = gen.toMarkdown();
        final section = md.substring(md.indexOf('### Priorisation par risque'));
        expect(section.indexOf('CVE-2021-44228'),
            lessThan(section.indexOf('CVE-2021-45046')));
        expect(section, contains('3.9, mat. High'));
        expect(section, isNot(contains('CVE-2020-9999')),
            reason: 'sans signal → hors tableau');
        expect(section, contains('1 autre(s) CVE sans signal'));
      });

      test('AsciiDoc : section exploitabilité rendue', () {
        final adoc = gen.toAsciiDoc();
        expect(adoc, contains('== Exploitabilité et exploitation active'));
        expect(adoc, contains('=== Priorisation par risque'));
      });

      test('exploitById vide → aucune section ni colonne', () {
        final plain = ScanReportGenerator(
          sbomPath: 's',
          resultsByScanner: {
            'grype': [_v('CVE-2021-44228', 'Critical')],
          },
        );
        final md = plain.toMarkdown();
        expect(md, isNot(contains('Priorisation par risque')));
        expect(md, isNot(contains('CISA KEV')));
      });
    });
  });
}
