import 'dart:convert';
import 'dart:io';

import 'package:sbom_generator/attestation.dart';
import 'package:sbom_generator/sbom_reader.dart';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('attest_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  test('types de prédicat par format ; SPDX 3.0 sans type enregistré', () {
    expect(
        sbomPredicateType(SbomFormat.cyclonedx), 'https://cyclonedx.org/bom');
    expect(sbomPredicateType(SbomFormat.spdx2), 'https://spdx.dev/Document');
    expect(sbomPredicateType(SbomFormat.spdx3), isNull);
    expect(cosignAttestType('https://cyclonedx.org/bom'), 'cyclonedx');
    expect(cosignAttestType(slsaProvenanceType), 'slsaprovenance1');
  });

  test('sha256OfFile', () async {
    final f = File('${tmp.path}/a')..writeAsStringSync('abc');
    expect(await sha256OfFile(f.path),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  test('déclaration in-toto v1', () {
    final st = buildStatement(
      subjects: {'app': 'f' * 64},
      predicateType: 'https://cyclonedx.org/bom',
      predicate: {'bomFormat': 'CycloneDX'},
    );
    expect(st['_type'], intotoStatementType);
    expect((st['subject'] as List).single['digest'], {'sha256': 'f' * 64});
    expect(jsonDecode(encodeStatement(st)), st);
  });

  test('provenance SLSA : builder, matière SBOM, dates UTC', () {
    final p = buildProvenance(
      builderId: 'https://ci.example/builder',
      buildType: 'https://example/build/v1',
      sbomName: 'sbom.cdx.json',
      sbomSha256: 'a' * 64,
      invocationId: 'run-42',
      startedOn: DateTime.utc(2026, 1, 1, 10),
      finishedOn: DateTime.utc(2026, 1, 1, 11),
    );
    expect(p['runDetails']['builder']['id'], 'https://ci.example/builder');
    expect(p['runDetails']['metadata']['invocationId'], 'run-42');
    expect(
        p['runDetails']['metadata']['startedOn'], '2026-01-01T10:00:00.000Z');
    expect(
        p['buildDefinition']['resolvedDependencies'].single['digest']['sha256'],
        'a' * 64);
  });

  test('validateSubjects : vide, introuvable, doublon', () {
    expect(validateSubjects([]), isNotNull);
    expect(validateSubjects(['${tmp.path}/absent']), contains('absent'));
    File('${tmp.path}/x').writeAsStringSync('1');
    Directory('${tmp.path}/d').createSync();
    File('${tmp.path}/d/x').writeAsStringSync('2');
    expect(validateSubjects(['${tmp.path}/x', '${tmp.path}/d/x']),
        contains('même nom'));
    expect(validateSubjects(['${tmp.path}/x']), isNull);
  });
}
