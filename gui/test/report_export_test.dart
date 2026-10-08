import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/services/report_export.dart';

void main() {
  test('reportArgs : commande `sbom-generator report`', () {
    expect(reportArgs(input: 'in.json', output: 'out.pdf', severity: 'high'), [
      'report', '--input', 'in.json', '--output', 'out.pdf', //
      '--format', 'pdf', '--severity', 'high',
    ]);
  });

  test('reportArgs : tendance et VEX désactivé', () {
    final a = reportArgs(
      input: 'in.json',
      output: 'out.pdf',
      severity: 'all',
      compareWith: 'old.json',
      applyVex: false,
    );
    expect(a, containsAllInOrder(['--compare-with', 'old.json']));
    expect(a.last, '--no-vex');
  });
}
