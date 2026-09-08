import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/pdf_report.dart';

void main() {
  test('frenchSeverityLabel : libellés français, insensible à la casse', () {
    expect(frenchSeverityLabel('Critical'), 'CRITIQUE');
    expect(frenchSeverityLabel('HIGH'), 'ÉLEVÉE');
    expect(frenchSeverityLabel('medium'), 'MOYENNE');
    expect(frenchSeverityLabel('Low'), 'FAIBLE');
    expect(frenchSeverityLabel(''), '?');
    expect(frenchSeverityLabel('Unknown'), 'UNKNOWN');
  });

  test('pdfSeverityBadge : rôle de thème + libellé francisé', () {
    expect(pdfSeverityBadge('critical'), '[.sev-critical]#CRITIQUE#');
    expect(pdfSeverityBadge('High'), '[.sev-high]#ÉLEVÉE#');
    expect(pdfSeverityBadge('autre'), '[.sev-other]#AUTRE#');
  });

  test('pdfFrenchDate : date longue en français', () {
    expect(pdfFrenchDate(DateTime(2026, 9, 8)), '8 septembre 2026');
    expect(pdfFrenchDate(DateTime(2026, 1, 1)), '1 janvier 2026');
    expect(pdfFrenchDate(DateTime(2026, 12, 31)), '31 décembre 2026');
  });
}
