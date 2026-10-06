import 'package:sbom_generator/cra_report.dart';
import 'package:sbom_generator/vuln_enrichment.dart';
import 'package:test/test.dart';

/// SBOM CycloneDX riche : tous les champs obligatoires renseignés.
Map<String, dynamic> _fullCdx() => {
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'metadata': {
        'timestamp': '2026-09-08T10:00:00Z',
        'authors': [
          {'name': 'CI'}
        ],
        'component': {'type': 'application', 'name': 'app', 'version': '1.0'},
      },
      'components': [
        {
          'type': 'library',
          'name': 'log4j-core',
          'version': '2.14.1',
          'purl': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
          'supplier': {'name': 'Apache'},
          'hashes': [
            {'alg': 'SHA-256', 'content': 'abc'}
          ],
          'licenses': [
            {
              'license': {'id': 'Apache-2.0'}
            }
          ],
        }
      ],
      'dependencies': [
        {
          'ref': 'app',
          'dependsOn': ['log4j-core']
        }
      ],
    };

Map<String, dynamic> _barecdx() => {
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'components': [
        {'type': 'library', 'name': 'x', 'version': '1.0'}
      ],
    };

void main() {
  group('CraMetadata', () {
    test('parseConfig : clés FR et EN, guillemets, commentaires', () {
      const cfg = '''
        # rapport CRA
        manufacturer: "ACME Corp"
        produit: WidgetOS
        product_version: '3.2.1'
        vulnerability_contact: security@acme.example  # e-mail
      ''';
      final m = CraMetadata.parseConfig(cfg);
      expect(m.manufacturer, 'ACME Corp');
      expect(m.product, 'WidgetOS');
      expect(m.productVersion, '3.2.1');
      expect(m.vulnerabilityContact, 'security@acme.example');
    });

    test('merge : this prioritaire, other en complément', () {
      const a = CraMetadata(manufacturer: 'A');
      const b = CraMetadata(manufacturer: 'B', product: 'P');
      final m = a.merge(b);
      expect(m.manufacturer, 'A');
      expect(m.product, 'P');
    });
  });

  group('CraReportGenerator', () {
    test('SBOM complet : tous les champs obligatoires conformes', () {
      final gen = CraReportGenerator(
        sbomPath: '/x/sbom.cdx.json',
        sbom: _fullCdx(),
        meta: const CraMetadata(
            manufacturer: 'ACME', product: 'App', productVersion: '1.0'),
      );
      expect(gen.fieldChecks.every((c) => c.status == CraStatus.ok), isTrue);
      expect(gen.dependencyStatus, CraStatus.ok);
      // Pas de scan → verdict « partiel » (conforme avec réserves).
      expect(gen.verdict, CraStatus.partial);
      expect(gen.blockers, isEmpty);
      final adoc = gen.toAsciiDoc();
      expect(adoc, startsWith('= Rapport de conformité'));
      expect(adoc, contains(':title-page:'));
      expect(adoc, contains('== Portée et limites'));
    });

    test('SBOM pauvre : champs manquants → points bloquants', () {
      final gen = CraReportGenerator(
          sbomPath: 's', sbom: _barecdx(), meta: const CraMetadata());
      expect(gen.verdict, CraStatus.fail);
      expect(gen.blockers, contains(contains('relation de dépendance')));
      expect(gen.blockers, contains(contains('Fournisseur')));
      final j = gen.toJson();
      expect(j['verdict'], 'fail');
      expect(j['sbom']['machineReadable'], isTrue);
    });

    test('vulnérabilités : inventaire, correctifs, KEV → art. 14', () {
      final gen = CraReportGenerator(
        sbomPath: 's',
        sbom: _fullCdx(),
        meta: const CraMetadata(),
        scanResults: {
          'grype': [
            {
              'id': 'CVE-2021-44228',
              'severity': 'Critical',
              'package': 'log4j-core@2.14.1',
              'fixState': 'fixed',
              'fixedVersions': ['2.15.0'],
            },
            {
              'id': 'CVE-2099-9999',
              'severity': 'High',
              'package': 'x@1',
              'fixState': 'not-fixed',
              'fixedVersions': <String>[],
            },
          ],
        },
        exploitById: {
          'CVE-2021-44228':
              ExploitInfo(inKev: true, kevDateAdded: DateTime(2021, 12, 10)),
        },
        toolVersions: {'Grype': '0.118.0'},
      );
      expect(gen.totalCves, 2);
      expect(gen.sevCount('critical'), 1);
      expect(gen.cvesWithoutFix, ['CVE-2099-9999']);
      expect(gen.kevCves, ['CVE-2021-44228']);
      expect(gen.verdict, CraStatus.fail);
      final j = gen.toJson()['vulnerabilities'] as Map;
      expect(j['article14NotificationRequired'], isTrue);
      expect((j['activelyExploited'] as List).single['cve'], 'CVE-2021-44228');

      final adoc = gen.toAsciiDoc();
      expect(adoc, contains('art. 14'));
      expect(adoc, contains('sous 24 h'));
      expect(adoc, contains('CVE-2099-9999')); // sans correctif
    });

    test('SPDX 2.3 : détection format + champs', () {
      final spdx = {
        'spdxVersion': 'SPDX-2.3',
        'creationInfo': {
          'created': '2026-09-08T10:00:00Z',
          'creators': ['Tool: sbom-generator'],
        },
        'documentDescribes': ['SPDXRef-App'],
        'packages': [
          {'SPDXID': 'SPDXRef-App', 'name': 'App', 'versionInfo': '1.0'},
          {
            'SPDXID': 'SPDXRef-lib',
            'name': 'lib',
            'versionInfo': '2.0',
            'supplier': 'Organization: ACME',
            'licenseConcluded': 'MIT',
            'checksums': [
              {'algorithm': 'SHA256', 'checksumValue': 'abc'}
            ],
            'externalRefs': [
              {'referenceType': 'purl', 'referenceLocator': 'pkg:pypi/lib@2.0'}
            ],
          },
        ],
        'relationships': [
          {
            'spdxElementId': 'SPDXRef-App',
            'relationshipType': 'DEPENDS_ON',
            'relatedSpdxElement': 'SPDXRef-lib',
          }
        ],
      };
      final gen = CraReportGenerator(
          sbomPath: 's', sbom: spdx, meta: const CraMetadata());
      // 1 composant hors racine.
      final j = gen.toJson()['sbom'] as Map;
      expect(j['componentCount'], 1);
      expect(j['format'], contains('SPDX'));
      expect(gen.dependencyStatus, CraStatus.ok);
      expect(gen.fieldChecks.firstWhere((c) => c.label == 'Licence').status,
          CraStatus.ok);
    });

    test('SPDX 3.0 : composants, champs et métadonnées lus dans le graphe', () {
      final gen = CraReportGenerator(
        sbomPath: 's.spdx3.jsonld',
        sbom: {
          '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
          '@graph': [
            {
              'type': 'CreationInfo',
              '@id': '_:ci',
              'created': '2026-01-01T00:00:00Z',
              'createdBy': ['t'],
            },
            {
              'type': 'SpdxDocument',
              'spdxId': 'd',
              'rootElement': ['p1'],
            },
            {
              'type': 'software:Package',
              'spdxId': 'p1',
              'name': 'foo',
              'software:packageVersion': '1.0',
              'suppliedBy': 'org',
              'externalIdentifier': [
                {'externalIdentifierType': 'purl', 'identifier': 'pkg:x/foo'}
              ],
              'verifiedUsing': [
                {'type': 'Hash', 'algorithm': 'sha256', 'hashValue': 'ab'}
              ],
              'concludedLicense': 'MIT',
            },
            {
              'type': 'Relationship',
              'from': 'p1',
              'to': ['p2'],
              'relationshipType': 'dependsOn',
            },
          ],
        },
        meta: const CraMetadata(),
      );
      expect(gen.fieldChecks, hasLength(6));
      expect(gen.fieldChecks.every((c) => c.status == CraStatus.ok), isTrue);
      expect(gen.dependencyStatus, CraStatus.ok);
      final md = gen.toJson()['sbom']['documentMetadata'];
      expect(md['author'], isTrue);
      expect(md['timestamp'], '2026-01-01T00:00:00Z');
      expect(md['primaryComponent'], isTrue);
    });
  });
}
