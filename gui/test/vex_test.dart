import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/vex.dart';
import 'package:sbom_generator_gui/services/vex_controller.dart';

void main() {
  const notAffected = VexStatement(
    vulnId: 'CVE-2024-1',
    products: ['foo@1.0'],
    status: 'not_affected',
    justification: 'vulnerable_code_not_in_execute_path',
    impactStatement: 'jamais appelé',
  );

  group('format', () {
    test('OpenVEX : écriture puis relecture', () {
      final doc = buildOpenVex([notAffected], author: 'moi', toolVersion: '1');
      final back = parseVex(jsonDecode(encodeVex(doc)) as Map<String, dynamic>);
      expect(back.single.vulnId, 'CVE-2024-1');
      expect(back.single.products, ['foo@1.0']);
      expect(back.single.justification, 'vulnerable_code_not_in_execute_path');
      expect(back.single.impactStatement, 'jamais appelé');
    });

    test('CycloneDX VEX : états et justifications converties', () {
      final doc = buildCycloneDxVex(
        [notAffected, const VexStatement(vulnId: 'CVE-2', status: 'fixed')],
        author: 'moi',
        toolVersion: '1',
      );
      expect(doc['vulnerabilities'][0]['analysis']['state'], 'not_affected');
      expect(
        doc['vulnerabilities'][0]['analysis']['justification'],
        'code_not_reachable',
      );
      expect(doc['vulnerabilities'][1]['analysis']['state'], 'resolved');
      final back = parseVex(doc);
      expect(back.map((s) => s.status), ['not_affected', 'fixed']);
      expect(back.first.justification, 'vulnerable_code_not_in_execute_path');
    });

    test('CSAF 2.0 VEX : écriture puis relecture, produit joker', () {
      final doc = buildCsafVex(
        [
          notAffected,
          const VexStatement(
            vulnId: 'CVE-2',
            status: 'affected',
            actionStatement: 'Mettre à jour',
          ),
          const VexStatement(
            vulnId: 'GHSA-xxxx',
            products: ['pkg:npm/bar@2.0'],
            status: 'fixed',
          ),
        ],
        author: 'moi',
        toolVersion: '1',
      );
      expect(doc['document']['category'], 'csaf_vex');
      expect(isCsafVex(doc), isTrue);
      final back = parseVex(jsonDecode(encodeVex(doc)) as Map<String, dynamic>);
      expect(back, hasLength(3));
      final cve1 = back.firstWhere((s) => s.vulnId == 'CVE-2024-1');
      expect(cve1.status, 'not_affected');
      expect(cve1.products, ['foo@1.0']);
      expect(cve1.justification, 'vulnerable_code_not_in_execute_path');
      expect(cve1.impactStatement, 'jamais appelé');
      final cve2 = back.firstWhere((s) => s.vulnId == 'CVE-2');
      expect(cve2.products, isEmpty); // joker => tous les produits
      expect(cve2.actionStatement, 'Mettre à jour');
      final ghsa = back.firstWhere((s) => s.vulnId == 'GHSA-xxxx');
      expect(ghsa.products, ['pkg:npm/bar@2.0']);
    });

    test('CSAF : un document non VEX n\'est pas reconnu', () {
      expect(
        isCsafVex({
          'document': {'category': 'csaf_security_advisory'},
        }),
        isFalse,
      );
      expect(
        () => parseVex({
          'document': {'category': 'csaf_security_advisory'},
        }),
        throwsFormatException,
      );
    });

    test('document inconnu : FormatException', () {
      expect(() => parseVex({'a': 1}), throwsFormatException);
    });

    test('produits : PURL, nom, nom@version', () {
      const s = VexStatement(
        vulnId: 'C',
        products: ['pkg:maven/org.x/lib@1.2?type=jar', 'bar'],
        status: 'fixed',
      );
      expect(s.appliesTo('lib', '1.2'), isTrue);
      expect(s.appliesTo('lib', '1.3'), isFalse);
      expect(s.appliesTo('bar', '9'), isTrue);
      expect(s.appliesTo('baz', '1'), isFalse);
      expect(
        const VexStatement(vulnId: 'C', status: 'fixed').appliesTo('n', '1'),
        isTrue,
      );
    });
  });

  group('VexController', () {
    test('masque seulement not_affected/fixed, id normalisé', () {
      final c = VexController()
        ..set(notAffected)
        ..set(const VexStatement(vulnId: 'CVE-9', status: 'affected'));
      expect(c.suppresses('CVE-2024-1', 'foo', '1.0'), isTrue);
      expect(c.suppresses('DEBIAN-CVE-2024-1', 'foo', '1.0'), isTrue);
      expect(c.suppresses('CVE-2024-1', 'foo', '2.0'), isFalse);
      expect(c.suppresses('CVE-9', 'x', '1'), isFalse);
    });

    test('une déclaration de même cible en remplace une autre', () {
      final c = VexController()
        ..set(notAffected)
        ..set(
          const VexStatement(
            vulnId: 'cve-2024-1',
            products: ['foo@1.0'],
            status: 'affected',
          ),
        );
      expect(c.statements, hasLength(1));
      expect(c.suppresses('CVE-2024-1', 'foo', '1.0'), isFalse);
    });

    test('persistance : encode / restore, notifications', () async {
      String? saved;
      var n = 0;
      final c = VexController(persist: (j) async => saved = j)
        ..addListener(() => n++);
      c.set(notAffected);
      expect(n, 1);
      expect(saved, isNotNull);
      final d = VexController()..restore(saved);
      expect(d.statements.single.vulnId, 'CVE-2024-1');
      expect(VexController()..restore('{pas du json'), isA<VexController>());
      c.remove(c.statements.single);
      expect(c.isEmpty, isTrue);
    });

    test('merge : import qui remplace, compte', () {
      final c = VexController()..set(notAffected);
      final k = c.merge([
        const VexStatement(
          vulnId: 'CVE-2024-1',
          products: ['foo@1.0'],
          status: 'fixed',
        ),
        const VexStatement(vulnId: 'CVE-3', status: 'fixed'),
      ]);
      expect(k, 2);
      expect(c.statements, hasLength(2));
    });

    test('filterByVex', () {
      final c = VexController()..set(notAffected);
      final rows = [('CVE-2024-1', 'foo', '1.0'), ('CVE-2024-1', 'foo', '2.0')];
      final out = filterByVex<(String, String, String)>(
        rows,
        c,
        (r) => (id: r.$1, name: r.$2, version: r.$3),
      );
      expect(out, [('CVE-2024-1', 'foo', '2.0')]);
      expect(
        filterByVex<int>(null, c, (_) => (id: '', name: '', version: '')),
        isNull,
      );
    });
  });
}
