import 'package:sbom_generator/cra_report.dart';
import 'package:sbom_generator/i18n.dart';
import 'package:sbom_generator/license_report_generator.dart';
import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/scan_report_generator.dart';
import 'package:test/test.dart';

/// Les rapports lisibles suivent la langue courante ; les identifiants et
/// clés lus par des programmes (JSON) restent stables.
void main() {
  tearDown(() => currentLang = Lang.fr);

  final cdx = {
    'bomFormat': 'CycloneDX',
    'specVersion': '1.6',
    'components': [
      {'type': 'library', 'name': 'x', 'version': '1.0'}
    ],
  };

  test('rapport de synthèse des scans : titres FR / EN', () {
    final gen = ScanReportGenerator(
      sbomPath: 's.cdx.json',
      generatedAt: DateTime.utc(2026, 9, 8),
      resultsByScanner: {
        'grype': [
          {'id': 'CVE-1', 'severity': 'High', 'package': 'p@1'}
        ],
      },
    );
    currentLang = Lang.fr;
    expect(gen.toMarkdown(), contains('## Résumé global'));
    expect(gen.toAsciiDoc(), contains(':revdate: 8 septembre 2026'));
    currentLang = Lang.en;
    expect(gen.toMarkdown(), contains('## Global summary'));
    expect(gen.toMarkdown(), contains('_Not run._'));
    expect(gen.toAsciiDoc(), contains(':revdate: 8 September 2026'));
    expect(gen.toAsciiDoc(), contains('== Executive summary'));
    expect(gen.toAsciiDoc(), contains('#HIGH#'));
  });

  test('rapport CRA : AsciiDoc traduit, JSON à clés stables', () {
    final gen = CraReportGenerator(
      sbomPath: 's.cdx.json',
      sbom: cdx,
      meta: const CraMetadata(),
      generatedAt: DateTime.utc(2026, 9, 8),
    );
    currentLang = Lang.fr;
    final frJson = gen.toJson();
    expect(gen.toAsciiDoc(), contains('== Portée et limites'));
    currentLang = Lang.en;
    final enJson = gen.toJson();
    final adoc = gen.toAsciiDoc();
    expect(adoc, contains('= Compliance report: Cyber Resilience Act'));
    expect(adoc, contains('== Scope and limits'));
    expect(gen.verdictSentence, startsWith('Non-compliant'));
    // Clés NTIA identiques dans les deux langues.
    expect((enJson['ntiaMinimumElements'] as Map).keys,
        (frJson['ntiaMinimumElements'] as Map).keys);
    expect(
        (enJson['ntiaMinimumElements'] as Map).keys, contains('supplierName'));
  });

  test('rapport de licences : Markdown FR / EN', () {
    final pkgs = <Package>[
      WheelPackage(
          name: 'a',
          version: '1',
          license: 'GPL-3.0-only',
          url: '',
          summary: '',
          vendor: '',
          arch: 'any',
          sourceRef: 'a',
          requires: const [],
          provides: const []),
    ];
    final gen = LicenseReportGenerator();
    currentLang = Lang.fr;
    expect(gen.render(pkgs, format: LicenseReportFormat.markdown),
        contains('## Résumé'));
    currentLang = Lang.en;
    final md = gen.render(pkgs, format: LicenseReportFormat.markdown);
    expect(md, contains('## Summary'));
    expect(md, contains('strong copyleft'));
  });
}
