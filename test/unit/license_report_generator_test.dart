import 'dart:convert';
import 'dart:io';
import 'package:sbom_generator/license_report_generator.dart';
import 'package:sbom_generator/models.dart';
import 'package:test/test.dart';

WheelPackage _pkg({
  required String name,
  String version = '1.0',
  String license = 'MIT',
}) =>
    WheelPackage(
      name: name,
      version: version,
      license: license,
      url: '',
      summary: '',
      vendor: '',
      arch: 'any',
      sourceRef: 'test',
      requires: const [],
      provides: [name],
      packageType: 'pypi',
    );

void main() {
  late Directory tmp;
  setUp(
      () => tmp = Directory.systemTemp.createTempSync('license_report_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  group('LicenseReportGenerator — regroupement', () {
    test('regroupe les paquets par licence exacte', () async {
      final out = '${tmp.path}/licences.adoc';
      await LicenseReportGenerator().writeToFile(
        [
          _pkg(name: 'a', license: 'MIT'),
          _pkg(name: 'b', license: 'MIT'),
          _pkg(name: 'c', license: 'Apache-2.0'),
        ],
        out,
      );
      final content = File(out).readAsStringSync();
      expect(content, contains('=== MIT (2)'));
      expect(content, contains('=== Apache-2.0 (1)'));
      expect(content, contains('Paquets analysés | 3'));
      expect(content, contains('Licences (expressions) distinctes | 2'));
    });

    test('titre par défaut = nom du document fourni', () async {
      final out = '${tmp.path}/licences.adoc';
      await LicenseReportGenerator().writeToFile(
        [_pkg(name: 'a')],
        out,
        documentName: 'Mon projet',
      );
      final content = File(out).readAsStringSync();
      expect(content, startsWith('= Mon projet'));
    });
  });

  group('LicenseReportGenerator — licences inconnues', () {
    test('paquets sans licence listés dans une section dédiée', () async {
      final out = '${tmp.path}/licences.adoc';
      await LicenseReportGenerator().writeToFile(
        [_pkg(name: 'nolicense', license: '')],
        out,
      );
      final content = File(out).readAsStringSync();
      expect(content, contains('Paquets sans licence détectée | 1'));
      expect(content, contains('nolicense'));
      expect(content, isNot(contains('=== ('))); // pas de section vide "==="
    });
  });

  group('LicenseReportGenerator — copyleft', () {
    test('licence GPL simple détectée comme copyleft fort', () async {
      final out = '${tmp.path}/licences.adoc';
      await LicenseReportGenerator().writeToFile(
        [_pkg(name: 'gpl-pkg', license: 'GPL-3.0-only')],
        out,
      );
      final content = File(out).readAsStringSync();
      expect(content, contains('[copyleft fort]'));
      expect(content,
          contains('Paquets sous licence copyleft fort (GPL/AGPL) | 1'));
      expect(content, contains('WARNING'));
      expect(content, contains('GPL-3.0-only'));
    });

    test('LGPL détectée comme copyleft faible, pas fort', () async {
      final out = '${tmp.path}/licences.adoc';
      await LicenseReportGenerator().writeToFile(
        [_pkg(name: 'lgpl-pkg', license: 'LGPL-2.1-only')],
        out,
      );
      final content = File(out).readAsStringSync();
      expect(content, contains('[copyleft faible]'));
      expect(content,
          contains('Paquets sous licence copyleft fort (GPL/AGPL) | 0'));
      expect(
          content,
          contains(
              'Paquets sous licence copyleft faible (LGPL/MPL/EPL/CDDL/CPL/EUPL) | 1'));
    });

    test('AGPL détectée comme copyleft fort (et non confondue avec GPL simple)',
        () async {
      final out = '${tmp.path}/licences.adoc';
      await LicenseReportGenerator().writeToFile(
        [_pkg(name: 'agpl-pkg', license: 'AGPL-3.0-only')],
        out,
      );
      final content = File(out).readAsStringSync();
      expect(content, contains('[copyleft fort]'));
      expect(content, contains('AGPL-3.0-only'));
    });

    test('MIT/Apache ne déclenchent aucune alerte copyleft', () async {
      final out = '${tmp.path}/licences.adoc';
      await LicenseReportGenerator().writeToFile(
        [
          _pkg(name: 'a', license: 'MIT'),
          _pkg(name: 'b', license: 'Apache-2.0')
        ],
        out,
      );
      final content = File(out).readAsStringSync();
      expect(content, isNot(contains('[copyleft')));
      expect(content, isNot(contains('WARNING')));
      expect(content,
          contains('Paquets sous licence copyleft fort (GPL/AGPL) | 0'));
    });

    test(
        'expression composée avec GPL noyé listée avec le token individuel, pas la chaîne entière',
        () async {
      final out = '${tmp.path}/licences.adoc';
      const compound = 'BSD-3-Clause AND GPL-2.0-only AND MIT';
      await LicenseReportGenerator().writeToFile(
        [_pkg(name: 'mixed', license: compound)],
        out,
      );
      final content = File(out).readAsStringSync();
      // Le groupe détaillé garde l'expression complète (fidèle à la source)…
      expect(content, contains('=== $compound [copyleft fort] (1)'));
      // …mais l'avertissement en tête de rapport ne liste que le token GPL.
      final warningSection = content.split('[WARNING]')[1].split('====')[1];
      expect(warningSection, contains('GPL-2.0-only'));
      expect(warningSection, isNot(contains(compound)));
    });
  });

  group('LicenseReportGenerator — formats', () {
    final pkgs = [
      _pkg(name: 'a', license: 'MIT'),
      _pkg(name: 'b', license: 'GPL-3.0-only'),
      _pkg(name: 'c, "x"', license: 'LGPL-2.1-only'),
      _pkg(name: 'd', license: ''),
    ];
    String render(LicenseReportFormat f) =>
        LicenseReportGenerator().render(pkgs, documentName: 'Doc', format: f);

    test('parse accepte adoc et refuse un format inconnu', () {
      expect(LicenseReportFormat.parse('adoc'), LicenseReportFormat.asciidoc);
      expect(LicenseReportFormat.parse('HTML'), LicenseReportFormat.html);
      expect(LicenseReportFormat.parse('pdf'), isNull);
    });

    test('json : résumé, catégories et paquets sans licence', () {
      final j =
          jsonDecode(render(LicenseReportFormat.json)) as Map<String, dynamic>;
      expect(j['summary']['packages'], 4);
      expect(j['summary']['strongCopyleftPackages'], 1);
      expect(j['summary']['weakCopyleftPackages'], 1);
      expect(j['summary']['unknownPackages'], 1);
      final cats = {
        for (final l in j['licenses'] as List) l['license']: l['category'],
      };
      expect(cats['GPL-3.0-only'], 'strong-copyleft');
      expect(cats['LGPL-2.1-only'], 'weak-copyleft');
      expect(cats['MIT'], 'permissive');
      expect((j['unknown'] as List).single['name'], 'd');
    });

    test('csv : échappement RFC 4180', () {
      final csv = render(LicenseReportFormat.csv);
      expect(csv.split('\r\n').first, 'license,category,name,version,purl');
      expect(csv, contains('"c, ""x"""'));
      expect(csv, contains(',unknown,d,'));
    });

    test('markdown et html : titre, copyleft et échappement HTML', () {
      final md = render(LicenseReportFormat.markdown);
      expect(md, contains('# Doc'));
      expect(md, contains('### GPL-3.0-only [copyleft fort] (1)'));
      final html = render(LicenseReportFormat.html);
      expect(html, contains('<title>Doc</title>'));
      expect(html, contains('copyleft fort'));
      expect(html, contains('c, &quot;x&quot;'));
    });
  });
}
