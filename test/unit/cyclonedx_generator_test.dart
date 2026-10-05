import 'package:sbom_generator/cyclonedx_generator.dart';
import 'package:sbom_generator/models.dart';
import 'package:test/test.dart';

RpmPackage _rpm({
  required String name,
  String version = '1.0',
  String release = '1.el9',
  String arch = 'x86_64',
}) =>
    RpmPackage(
      name: name,
      version: version,
      release: release,
      arch: arch,
      epoch: '(none)',
      license: 'MIT',
      vendor: '',
      url: '',
      buildTime: '',
      summary: '',
      requires: const [],
      provides: const [],
    );

WheelPackage _maven({
  required String groupId,
  required String artifactId,
  String version = '1.0.0',
}) =>
    WheelPackage(
      name: '$groupId:$artifactId',
      version: version,
      license: '',
      url: '',
      summary: '',
      vendor: groupId,
      arch: 'any',
      sourceRef: '$artifactId-$version.jar',
      requires: const [],
      provides: ['$groupId:$artifactId'],
      packageType: 'maven',
    );

void main() {
  final generator = CycloneDxGenerator();

  group('CycloneDxGenerator.generate — hashes', () {
    Map<String, dynamic> component(List<Package> pkgs) =>
        (generator.generate(pkgs, [])['components'] as List)
            .whereType<Map<String, dynamic>>()
            .firstWhere((c) => c['type'] == 'library');

    test('Package.hashes → tableau hashes multi-algorithme', () {
      final pkg = WheelPackage(
        name: 'lib',
        version: '1.0',
        license: '',
        url: '',
        summary: '',
        vendor: '',
        arch: 'any',
        sourceRef: '',
        hashes: [PackageHash('SHA-512', 'b' * 128)],
        requires: const [],
        provides: const ['lib'],
        packageType: 'npm',
      );
      expect(component([pkg])['hashes'], [
        {'alg': 'SHA-512', 'content': 'b' * 128},
      ]);
    });

    test('pas de clé hashes si le paquet n\'en a pas', () {
      expect(component([_rpm(name: 'bash')]).containsKey('hashes'), isFalse);
    });

    test('hash d\'en-tête RPM → propriété rpm:header-sha256, pas hashes', () {
      final pkg = RpmPackage(
        name: 'bash',
        version: '5.2',
        release: '1.el9',
        arch: 'x86_64',
        epoch: '(none)',
        license: 'GPL',
        vendor: '',
        url: '',
        buildTime: '',
        summary: '',
        requires: const [],
        provides: const [],
        headerSha256: 'f' * 64,
      );
      final c = component([pkg]);
      expect(c.containsKey('hashes'), isFalse);
      expect(
          (c['properties'] as List).any((p) =>
              p['name'] == 'rpm:header-sha256' && p['value'] == 'f' * 64),
          isTrue);
    });
  });

  group('CycloneDxGenerator.generate — specVersion', () {
    test('génère en 1.6 par défaut', () {
      final sbom = generator.generate([_rpm(name: 'bash')], []);
      expect(sbom['specVersion'], '1.6');
      expect(sbom.containsKey('citations'), isFalse);
      expect(sbom.containsKey('definitions'), isFalse);
      expect((sbom['metadata'] as Map).containsKey('distributionConstraints'),
          isFalse);
    });

    test('génère en 1.7 quand demandé explicitement', () {
      final sbom =
          generator.generate([_rpm(name: 'bash')], [], specVersion: '1.7');
      expect(sbom['specVersion'], '1.7');
    });

    test('rejette une specVersion inconnue', () {
      expect(
        () => generator.generate([_rpm(name: 'bash')], [], specVersion: '2.0'),
        throwsArgumentError,
      );
    });

    test('rejette --tlp en 1.6', () {
      expect(
        () => generator.generate([_rpm(name: 'bash')], [], tlp: 'AMBER'),
        throwsArgumentError,
      );
    });

    test('rejette un citationSource en 1.6', () {
      expect(
        () => generator
            .generate([_rpm(name: 'bash')], [], citationSource: 'syft'),
        throwsArgumentError,
      );
    });

    test('rejette une carte de brevets non vide en 1.6', () {
      expect(
        () => generator.generate([
          _rpm(name: 'bash')
        ], [], patentsByPackageName: {
          'bash': const PatentAssertion(
            patentNumber: 'US1234567',
            jurisdiction: 'US',
            legalStatus: 'granted',
            assertionType: 'license',
          ),
        }),
        throwsArgumentError,
      );
    });
  });

  group('CycloneDxGenerator.generate — distributionConstraints (1.7)', () {
    test('ajoute metadata.distributionConstraints.tlp', () {
      final sbom = generator.generate([_rpm(name: 'bash')], [],
          specVersion: '1.7', tlp: 'AMBER_AND_STRICT');
      final metadata = sbom['metadata'] as Map<String, dynamic>;
      expect(metadata['distributionConstraints'], {'tlp': 'AMBER_AND_STRICT'});
    });

    test('rejette une classification TLP invalide', () {
      expect(
        () => generator.generate([_rpm(name: 'bash')], [],
            specVersion: '1.7', tlp: 'PURPLE'),
        throwsArgumentError,
      );
    });
  });

  group('CycloneDxGenerator.generate — citations (1.7)', () {
    test('ajoute une citation attribuée à l\'outil source', () {
      final sbom = generator.generate([_rpm(name: 'bash')], [],
          specVersion: '1.7', citationSource: 'syft');

      final citations = sbom['citations'] as List;
      expect(citations, hasLength(1));
      final citation = citations.first as Map<String, dynamic>;
      expect(citation['attributedTo'], 'tool-syft');
      expect(citation['pointers'], ['/components']);
      expect(citation['timestamp'], isNotNull);

      final tools =
          ((sbom['metadata'] as Map)['tools'] as Map)['components'] as List;
      expect(tools.any((t) => t['bom-ref'] == 'tool-syft'), isTrue);
    });

    test('n\'ajoute pas de tool dupliqué pour "sbom_generator"', () {
      final sbom = generator.generate([_rpm(name: 'bash')], [],
          specVersion: '1.7', citationSource: 'sbom_generator');
      final tools =
          ((sbom['metadata'] as Map)['tools'] as Map)['components'] as List;
      expect(tools, hasLength(1));
    });
  });

  group('CycloneDxGenerator.generate — sdkTools (toolchain de build)', () {
    test('ajoute chaque SDK à metadata.tools.components (type platform)', () {
      final sbom = generator.generate([_rpm(name: 'bash')], [],
          sdkTools: {'flutter': '3.47.2', 'dart': '3.9.0'});
      final tools = ((sbom['metadata'] as Map)['tools'] as Map)['components']
          as List<dynamic>;
      final byName = {for (final t in tools) t['name']: t};
      expect(byName['flutter'], {
        'type': 'platform',
        'bom-ref': 'tool-sdk-flutter',
        'name': 'flutter',
        'version': '3.47.2'
      });
      expect(byName['dart']!['version'], '3.9.0');
      // sbom_generator lui-même reste présent
      expect(byName.containsKey('sbom_generator'), isTrue);
    });

    test('sdkTools vide → aucun tool supplémentaire', () {
      final sbom = generator.generate([_rpm(name: 'bash')], []);
      final tools =
          ((sbom['metadata'] as Map)['tools'] as Map)['components'] as List;
      expect(tools, hasLength(1));
    });
  });

  group('CycloneDxGenerator.generate — patentAssertions (1.7)', () {
    test(
        'ajoute patentAssertions au composant correspondant + definitions.patents',
        () {
      final sbom = generator.generate(
        [_rpm(name: 'bash'), _rpm(name: 'coreutils')],
        [],
        specVersion: '1.7',
        organization: 'ACME Corp',
        patentsByPackageName: {
          'bash': const PatentAssertion(
            patentNumber: 'US1234567',
            jurisdiction: 'US',
            legalStatus: 'granted',
            assertionType: 'license',
          ),
        },
      );

      final components = sbom['components'] as List;
      final bashComponent =
          components.firstWhere((c) => c['name'] == 'bash') as Map;
      final coreutilsComponent =
          components.firstWhere((c) => c['name'] == 'coreutils') as Map;

      expect(bashComponent.containsKey('patentAssertions'), isTrue);
      final assertion =
          (bashComponent['patentAssertions'] as List).first as Map;
      expect(assertion['assertionType'], 'license');
      expect(assertion['asserter'], {'name': 'ACME Corp', 'url': <String>[]});
      expect(assertion['patentRefs'], ['patent-us1234567']);

      expect(coreutilsComponent.containsKey('patentAssertions'), isFalse);

      final patentDefs = (sbom['definitions'] as Map)['patents'] as List;
      expect(patentDefs, hasLength(1));
      expect(patentDefs.first, {
        'bom-ref': 'patent-us1234567',
        'patentNumber': 'US1234567',
        'jurisdiction': 'US',
        'patentLegalStatus': 'granted',
      });
    });

    test('rejette une juridiction de brevet invalide', () {
      expect(
        () => generator.generate([_rpm(name: 'bash')], [],
            specVersion: '1.7',
            patentsByPackageName: {
              'bash': const PatentAssertion(
                patentNumber: 'US1234567',
                jurisdiction: 'USA',
                legalStatus: 'granted',
                assertionType: 'license',
              ),
            }),
        throwsArgumentError,
      );
    });

    test('rejette un legalStatus de brevet invalide', () {
      expect(
        () => generator.generate([_rpm(name: 'bash')], [],
            specVersion: '1.7',
            patentsByPackageName: {
              'bash': const PatentAssertion(
                patentNumber: 'US1234567',
                jurisdiction: 'US',
                legalStatus: 'not-a-status',
                assertionType: 'license',
              ),
            }),
        throwsArgumentError,
      );
    });

    test('rejette un assertionType de brevet invalide', () {
      expect(
        () => generator.generate([_rpm(name: 'bash')], [],
            specVersion: '1.7',
            patentsByPackageName: {
              'bash': const PatentAssertion(
                patentNumber: 'US1234567',
                jurisdiction: 'US',
                legalStatus: 'granted',
                assertionType: 'not-a-type',
              ),
            }),
        throwsArgumentError,
      );
    });
  });

  group('CycloneDxGenerator.generate — champ group (composants Maven)', () {
    test('sépare groupId/artifactId dans les champs group/name dédiés', () {
      final sbom = generator.generate([
        _maven(
            groupId: 'com.sun.xml.fastinfoset',
            artifactId: 'FastInfoset',
            version: '1.2.15')
      ], []);
      final component = (sbom['components'] as List).single as Map;
      expect(component['group'], 'com.sun.xml.fastinfoset');
      expect(component['name'], 'FastInfoset');
      expect(component['purl'],
          'pkg:maven/com.sun.xml.fastinfoset/FastInfoset@1.2.15');
    });

    test('n\'ajoute pas de champ group pour les paquets non-Maven', () {
      final sbom = generator.generate([_rpm(name: 'bash')], []);
      final component = (sbom['components'] as List).single as Map;
      expect(component.containsKey('group'), isFalse);
      expect(component['name'], 'bash');
    });
  });

  group('CycloneDxGenerator.generate — composant OS de base (osInfo)', () {
    const os = OsInfo(
      id: 'redhat',
      version: '9.6',
      prettyName: 'Red Hat Enterprise Linux 9.6 (Plow)',
      cpe: 'cpe:/o:redhat:enterprise_linux:9::baseos',
    );

    test('ajoute un composant type: operating-system en tête de components',
        () {
      final sbom = generator.generate([_rpm(name: 'bash')], [], osInfo: os);
      final components = sbom['components'] as List;

      // En tête : c'est ce composant que Trivy (et les autres consommateurs)
      // doivent trouver pour évaluer les CVE des paquets système — voir
      // OsInfo dans lib/models.dart.
      final osComponent = components.first as Map;
      expect(osComponent['type'], 'operating-system');
      expect(osComponent['name'], 'redhat');
      expect(osComponent['version'], '9.6');
      expect(osComponent['description'], os.prettyName);
      expect(osComponent['cpe'], os.cpe);
      expect(components.length, 2); // OS + 1 paquet
    });

    test(
        'aucun composant OS quand osInfo est absent (image sans base OS '
        'détectée, ex. scratch, ou source non-image)', () {
      final sbom = generator.generate([_rpm(name: 'bash')], []);
      final components = sbom['components'] as List;
      expect(components.any((c) => c['type'] == 'operating-system'), isFalse);
      expect(components.length, 1);
    });
  });
}
