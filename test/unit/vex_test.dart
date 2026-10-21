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
  group('CSAF 2.0 VEX', () {
    // Document type d'un éditeur : produits en branches, composant lié à une
    // plate-forme par une relation, justification en flag.
    Map<String, dynamic> csaf() => {
          'document': {'category': 'csaf_vex', 'csaf_version': '2.0'},
          'product_tree': {
            'branches': [
              {
                'category': 'vendor',
                'name': 'ACME',
                'branches': [
                  {
                    'category': 'product_version',
                    'name': 'foo 1.0.0',
                    'product': {
                      'product_id': 'P1',
                      'name': 'foo 1.0.0',
                      'product_identification_helper': {
                        'purl': 'pkg:npm/foo@1.0.0'
                      },
                    },
                  },
                  {
                    'category': 'product_version',
                    'name': 'appli 2',
                    'product': {'product_id': 'P2', 'name': 'appli 2'},
                  },
                ],
              },
            ],
            'relationships': [
              {
                'category': 'installed_on',
                'product_reference': 'P1',
                'relates_to_product_reference': 'P2',
                'full_product_name': {'product_id': 'P1-ON-P2', 'name': 'x'},
              },
            ],
          },
          'vulnerabilities': [
            {
              'cve': 'CVE-2024-1234',
              'product_status': {
                'known_not_affected': ['P1-ON-P2'],
                'known_affected': ['P2'],
              },
              'flags': [
                {
                  'label': 'vulnerable_code_not_present',
                  'product_ids': ['P1-ON-P2'],
                },
              ],
              'threats': [
                {
                  'category': 'impact',
                  'details': 'Code absent',
                  'product_ids': ['P1-ON-P2'],
                },
              ],
              'remediations': [
                {
                  'category': 'vendor_fix',
                  'details': 'Passer en 2.1',
                  'product_ids': ['P2'],
                },
              ],
            },
            {
              'ids': [
                {'system_name': 'GitHub', 'text': 'GHSA-aaaa-bbbb-cccc'}
              ],
              'product_status': {
                'fixed': ['P1']
              },
            },
          ],
        };

    test('lecture : états, produits résolus en PURL, justification', () {
      final doc = VexDocument.parse(csaf());
      expect(doc.statements, hasLength(3));
      final na = doc.statements.firstWhere((s) => s.status == 'not_affected');
      expect(na.vulnId, 'CVE-2024-1234');
      expect(na.products, ['pkg:npm/foo@1.0.0']);
      expect(na.justification, 'vulnerable_code_not_present');
      expect(na.impactStatement, 'Code absent');
      expect(na.suppresses, isTrue);

      final aff = doc.statements.firstWhere((s) => s.status == 'affected');
      expect(aff.products, ['appli 2']);
      expect(aff.actionStatement, 'Passer en 2.1');
      // La justification d'un autre produit ne déborde pas.
      expect(aff.justification, isNull);

      final fixed = doc.statements.firstWhere((s) => s.status == 'fixed');
      expect(fixed.vulnId, 'GHSA-aaaa-bbbb-cccc');
    });

    test('la déclaration s\'applique au paquet visé seulement', () {
      final doc = VexDocument.parse(csaf());
      expect(doc.find('CVE-2024-1234', 'foo', '1.0.0')?.status, 'not_affected');
      expect(doc.find('CVE-2024-1234', 'bar', '1.0.0'), isNull);
    });

    test('un category autre que csaf_vex est refusé', () {
      expect(
          () => VexDocument.parse({
                'document': {'category': 'csaf_security_advisory'}
              }),
          throwsFormatException);
    });

    test('écriture puis relecture : mêmes déclarations', () {
      final src = [
        const VexStatement(
          vulnId: 'CVE-2024-1',
          products: ['pkg:npm/foo@1.0.0'],
          status: 'not_affected',
          justification: 'component_not_present',
          impactStatement: 'absent',
        ),
        const VexStatement(
          vulnId: 'GHSA-xxxx-yyyy-zzzz',
          status: 'affected',
          actionStatement: 'Mettre à jour',
        ),
      ];
      final json = jsonDecode(encodeVex(
              buildCsafVex(statements: src, author: 'moi', toolVersion: '1')))
          as Map<String, dynamic>;
      expect(isCsafVex(json), isTrue);
      final back = VexDocument.parse(json).statements;
      expect(back.map((s) => s.vulnId), ['CVE-2024-1', 'GHSA-xxxx-yyyy-zzzz']);
      expect(back.first.products, ['pkg:npm/foo@1.0.0']);
      expect(back.first.justification, 'component_not_present');
      // Pas de produit = tous les produits, aller-retour compris.
      expect(back.last.products, isEmpty);
      expect(back.last.actionStatement, 'Mettre à jour');
    });

    test('structure du document produit', () {
      final doc = buildCsafVex(
        statements: const [
          VexStatement(
              vulnId: 'CVE-2024-0009',
              products: ['pkg:npm/foo@1.0.0'],
              status: 'fixed'),
        ],
        author: 'moi',
        toolVersion: '1.2.3',
      );
      expect(doc['document']['category'], 'csaf_vex');
      expect(doc['document']['csaf_version'], '2.0');
      expect(doc['vulnerabilities'].single['cve'], 'CVE-2024-0009');
      expect(doc['vulnerabilities'].single['product_status']['fixed'],
          ['CSAFPID-0001']);
      expect(
          doc['product_tree']['full_product_names']
              .single['product_identification_helper']['purl'],
          'pkg:npm/foo@1.0.0');
    });
  });
}
