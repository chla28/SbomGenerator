import 'dart:convert';

import 'package:sbom_generator/schema_validator.dart';
import 'package:sbom_generator/vex.dart';
import 'package:test/test.dart';

Map<String, dynamic> _openVex(List<Map<String, dynamic>> statements) => {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': 'urn:x',
      'author': 'a',
      'timestamp': '2026-01-01T00:00:00Z',
      'version': 1,
      'statements': statements,
    };

void main() {
  group('VexDocument.parse', () {
    test('OpenVEX : déclarations, produits PURL, justification', () {
      final doc = VexDocument.parse(_openVex([
        {
          'vulnerability': {'name': 'CVE-2024-1'},
          'products': [
            {'@id': 'pkg:npm/foo@1.0.0'}
          ],
          'status': 'not_affected',
          'justification': 'component_not_present',
        },
        {
          'vulnerability': {'name': 'CVE-2024-2'},
          'status': 'under_investigation',
        },
        {
          'vulnerability': {'name': 'CVE-2024-3'},
          'status': 'inconnu'
        },
      ]));
      expect(doc.statements, hasLength(2)); // l'état inconnu est ignoré
      expect(doc.statements.first.suppresses, isTrue);
      expect(doc.statements.first.justification, 'component_not_present');
      expect(doc.statements.last.suppresses, isFalse);
    });

    test('CycloneDX VEX : états et justifications converties', () {
      final doc = VexDocument.parse({
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'vulnerabilities': [
          {
            'id': 'CVE-2024-1',
            'analysis': {
              'state': 'not_affected',
              'justification': 'code_not_reachable',
              'detail': 'jamais appelé',
            },
            'affects': [
              {'ref': 'pkg:npm/foo@1.0.0'}
            ],
          },
          {
            'id': 'CVE-2024-2',
            'analysis': {'state': 'resolved'},
          },
          {
            'id': 'CVE-2024-3',
            'analysis': {'state': 'exploitable'},
          },
        ],
      });
      expect(doc.statements.map((s) => s.status),
          ['not_affected', 'fixed', 'affected']);
      expect(doc.statements.first.justification,
          'vulnerable_code_not_in_execute_path');
      expect(doc.statements.first.impactStatement, 'jamais appelé');
    });

    test('document non reconnu → FormatException', () {
      expect(() => VexDocument.parse({'foo': 1}), throwsFormatException);
    });
  });

  group('correspondance des produits', () {
    final doc = VexDocument.parse(_openVex([
      {
        'vulnerability': {'name': 'CVE-1'},
        'products': [
          {'@id': 'pkg:maven/org.x/lib@1.2.3?type=jar'}
        ],
        'status': 'not_affected',
        'justification': 'component_not_present',
      },
      {
        'vulnerability': {'name': 'cve-2'},
        'status': 'fixed',
      },
      {
        'vulnerability': {'name': 'CVE-3'},
        'products': [
          {'@id': 'foo@2.0'}
        ],
        'status': 'not_affected',
        'justification': 'component_not_present',
      },
    ]));

    test('PURL avec version et qualificateurs', () {
      expect(doc.find('CVE-1', 'lib', '1.2.3'), isNotNull);
      expect(doc.find('CVE-1', 'lib', '9.9.9'), isNull);
      expect(doc.find('CVE-1', 'autre', '1.2.3'), isNull);
    });

    test('sans produit = tous ; identifiant insensible à la casse', () {
      expect(doc.find('CVE-2', 'nimporte', '0'), isNotNull);
    });

    test('nom@version simple', () {
      expect(doc.find('CVE-3', 'foo', '2.0'), isNotNull);
      expect(doc.find('CVE-3', 'foo', '2.1'), isNull);
    });
  });

  group('génération', () {
    final statements = [
      const VexStatement(
        vulnId: 'CVE-2024-1',
        products: ['pkg:npm/foo@1.0.0'],
        status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
        impactStatement: 'non appelé',
      ),
      const VexStatement(
        vulnId: 'CVE-2024-2',
        products: ['pkg:npm/bar@2.0.0'],
        status: 'affected',
        actionStatement: 'Mettre à jour vers 2.1.',
      ),
    ];

    test('OpenVEX : relu à l\'identique', () {
      final doc = buildOpenVex(
          statements: statements, author: 'moi', toolVersion: '1.0');
      expect(doc['@context'], contains('openvex'));
      final back =
          VexDocument.parse(jsonDecode(encodeVex(doc)) as Map<String, dynamic>);
      expect(back.statements.map((s) => (s.vulnId, s.status)),
          [('CVE-2024-1', 'not_affected'), ('CVE-2024-2', 'affected')]);
      expect(back.statements.first.impactStatement, 'non appelé');
    });

    test('CycloneDX VEX : relu et conforme au schéma officiel 1.6', () {
      final doc = buildCycloneDxVex(
          statements: statements, author: 'moi', toolVersion: '1.0');
      final back =
          VexDocument.parse(jsonDecode(encodeVex(doc)) as Map<String, dynamic>);
      expect(
          back.statements.map((s) => s.status), ['not_affected', 'affected']);
      expect(SchemaValidator.validate(doc), isEmpty);
    });
  });
}
