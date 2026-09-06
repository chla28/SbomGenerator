import 'package:sbom_generator/scan_report_generator.dart';
import 'package:test/test.dart';

Map<String, dynamic> _v(String id, String sev) =>
    {'id': id, 'severity': sev, 'package': 'p@1', 'published': null, 'modified': null};

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

    test('normalise les CVE préfixées distro d\'OSV-Scanner pour le comptage', () {
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

    test('matrice inter-scanners : ✓/— par scanner, pire sévérité affichée', () {
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
      expect(adoc, contains('| [.sev-high]#HIGH# | CVE-2026-9 | ✓ | — | ✓'));
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
      expect(adoc, startsWith('= Rapport de synthèse'));
      expect(adoc, contains(':doctype: article'));
      expect(adoc, contains('[.sev-critical]#CRITICAL#'));
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
  });
}
