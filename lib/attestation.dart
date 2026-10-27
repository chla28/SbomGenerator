import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import 'i18n.dart';
import 'sbom_reader.dart';

const intotoStatementType = 'https://in-toto.io/Statement/v1';
const slsaProvenanceType = 'https://slsa.dev/provenance/v1';

/// Type de prédicat in-toto pour un SBOM, ou `null` si le format n'a pas de
/// type enregistré (SPDX 3.0 n'en a pas encore : convertir d'abord).
String? sbomPredicateType(SbomFormat format) => switch (format) {
      SbomFormat.cyclonedx => 'https://cyclonedx.org/bom',
      SbomFormat.spdx2 => 'https://spdx.dev/Document',
      _ => null,
    };

/// Type court de `cosign attest-blob --type` correspondant au prédicat.
String cosignAttestType(String predicateType) => switch (predicateType) {
      'https://cyclonedx.org/bom' => 'cyclonedx',
      'https://spdx.dev/Document' => 'spdxjson',
      'https://slsa.dev/provenance/v1' => 'slsaprovenance1',
      _ => predicateType,
    };

/// SHA-256 hexadécimal d'un fichier, lu en flux.
Future<String> sha256OfFile(String path) async =>
    (await sha256.bind(File(path).openRead()).first).toString();

/// Déclaration in-toto v1 : [subjects] (nom → SHA-256) atteste [predicate].
Map<String, dynamic> buildStatement({
  required Map<String, String> subjects,
  required String predicateType,
  required Map<String, dynamic> predicate,
}) =>
    {
      '_type': intotoStatementType,
      'subject': [
        for (final e in subjects.entries)
          {
            'name': e.key,
            'digest': {'sha256': e.value}
          },
      ],
      'predicateType': predicateType,
      'predicate': predicate,
    };

/// Prédicat de provenance SLSA v1 : le SBOM est la matière d'entrée, la
/// construction est attribuée à [builderId].
Map<String, dynamic> buildProvenance({
  required String builderId,
  required String buildType,
  required String sbomName,
  required String sbomSha256,
  Map<String, String> externalParameters = const {},
  String? invocationId,
  DateTime? startedOn,
  DateTime? finishedOn,
}) {
  final finished = (finishedOn ?? DateTime.now()).toUtc();
  final started = (startedOn ?? finished).toUtc();
  return {
    'buildDefinition': {
      'buildType': buildType,
      'externalParameters': externalParameters,
      'resolvedDependencies': [
        {
          'name': sbomName,
          'digest': {'sha256': sbomSha256}
        },
      ],
    },
    'runDetails': {
      'builder': {'id': builderId},
      'metadata': {
        if (invocationId != null) 'invocationId': invocationId,
        'startedOn': started.toIso8601String(),
        'finishedOn': finished.toIso8601String(),
      },
    },
  };
}

/// Valide les sujets : fichiers existants et noms uniques (sinon une
/// déclaration ambiguë serait signée).
String? validateSubjects(List<String> paths) {
  if (paths.isEmpty) return tr('au moins un --subject est requis.');
  final names = <String>{};
  for (final p in paths) {
    if (!File(p).existsSync()) {
      return tr('sujet introuvable : {path}', {'path': p});
    }
    if (!names.add(p.split('/').last)) {
      return tr('deux sujets portent le même nom : {name}',
          {'name': p.split('/').last});
    }
  }
  return null;
}

String encodeStatement(Map<String, dynamic> statement) =>
    const JsonEncoder.withIndent('  ').convert(statement);
