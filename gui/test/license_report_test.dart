import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/license_report.dart';

const _json = '''
{
  "name": "Doc",
  "summary": {"packages": 4, "distinctLicenses": 3,
    "strongCopyleftPackages": 1, "weakCopyleftPackages": 1, "unknownPackages": 1},
  "licenses": [
    {"license": "GPL-3.0-only", "category": "strong-copyleft",
     "packages": [{"name": "b", "version": "1", "purl": "pkg:x/b@1"}]},
    {"license": "LGPL-2.1-only", "category": "weak-copyleft",
     "packages": [{"name": "c", "version": "", "purl": ""}]},
    {"license": "MIT", "category": "permissive",
     "packages": [{"name": "a", "version": "2", "purl": ""}]}
  ],
  "unknown": [{"name": "d", "version": "3", "purl": ""}]
}
''';

void main() {
  test('parse : résumé, catégories et groupe « sans licence »', () {
    final r = LicenseReportData.parse(_json);
    expect(r.name, 'Doc');
    expect(r.totalPackages, 4);
    expect(r.distinctLicenses, 3);
    expect(r.unknownPackages, 1);
    expect(r.groups.map((g) => g.category), [
      LicenseCategory.strongCopyleft,
      LicenseCategory.weakCopyleft,
      LicenseCategory.permissive,
      LicenseCategory.unknown,
    ]);
    expect(r.groups.last.license, isEmpty);
  });

  test('tryParse renvoie null sur du JSON invalide', () {
    expect(LicenseReportData.tryParse('pas du json'), isNull);
    expect(LicenseReportData.tryParse('{}'), isNull);
  });

  test('filter : par licence (groupe entier) ou par paquet', () {
    final r = LicenseReportData.parse(_json);
    expect(r.filter('').length, 4);
    expect(r.filter('gpl').map((g) => g.license), [
      'GPL-3.0-only',
      'LGPL-2.1-only',
    ]);
    final byPkg = r.filter('a 2');
    expect(byPkg.single.license, 'MIT');
    expect(r.filter('zzz'), isEmpty);
  });
}
