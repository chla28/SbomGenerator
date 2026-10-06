import 'package:sbom_generator/cyclonedx_generator.dart';
import 'package:sbom_generator/models.dart';
import 'package:sbom_generator/schema_validator.dart';
import 'package:sbom_generator/spdx_generator.dart';
import 'package:test/test.dart';

RpmPackage _pkg(String name) => RpmPackage(
      name: name,
      version: '1.0',
      release: '1.el9',
      arch: 'x86_64',
      epoch: '(none)',
      license: 'MIT',
      vendor: 'ACME',
      url: '',
      buildTime: '',
      summary: '',
      requires: const [],
      provides: const [],
    );

void main() {
  test('schemaKeyFor : version supportée ou non', () {
    expect(
        SchemaValidator.schemaKeyFor(
            {'bomFormat': 'CycloneDX', 'specVersion': '1.6'}),
        'cyclonedx-1.6');
    expect(
        SchemaValidator.schemaKeyFor(
            {'bomFormat': 'CycloneDX', 'specVersion': '1.2'}),
        isNull);
    expect(
        SchemaValidator.schemaKeyFor({'spdxVersion': 'SPDX-2.3'}), 'spdx-2.3');
    expect(SchemaValidator.schemaKeyFor({'foo': 1}), isNull);
  });

  test('CycloneDX 1.6 généré : conforme au schéma officiel', () {
    final doc =
        CycloneDxGenerator().generate([_pkg('foo'), _pkg('foo_bar')], []);
    expect(SchemaValidator.validate(doc), isEmpty);
  });

  test('SPDX 2.3 généré : conforme (SPDXID sans « _ », date sans fraction)',
      () {
    final doc = SpdxGenerator()
        .generate([_pkg('foo_bar'), _pkg('baz')], [], documentName: 'x');
    expect(SchemaValidator.validate(doc), isEmpty);
    final ids = [
      for (final p in doc['packages'] as List) p['SPDXID'] as String
    ];
    expect(ids.every((i) => !i.contains('_')), isTrue);
    expect((doc['creationInfo'] as Map)['created'],
        matches(RegExp(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')));
  });

  test('un document invalide est refusé avec le chemin de l\'erreur', () {
    final errors = SchemaValidator.validate({
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'components': [
        {'name': 'x'}, // « type » obligatoire
      ],
    })!;
    expect(errors, isNotEmpty);
    expect(errors.join('\n'), contains('/components/0'));
  });

  test('aucun schéma : null', () {
    expect(SchemaValidator.validate({'foo': 1}), isNull);
  });
}
