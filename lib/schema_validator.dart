import 'dart:convert';
import 'dart:io';

import 'package:json_schema/json_schema.dart';

import 'i18n.dart';
import 'sbom_reader.dart';
import 'schemas_data.dart';

/// Validation d'un SBOM par rapport aux schémas JSON **officiels** (CycloneDX
/// 1.4–1.7, SPDX 2.3, SPDX 3.0), embarqués dans l'exécutable
/// (`schemas_data.dart`, généré par `tool/embed_schemas.dart`).
class SchemaValidator {
  static final Map<String, Map<String, dynamic>> _raw = {};
  static final Map<String, JsonSchema> _compiled = {};

  static Map<String, dynamic> _load(String key) => _raw.putIfAbsent(
      key,
      () => _clean(jsonDecode(utf8.decode(
          gzip.decode(base64.decode(embeddedSchemas[key]!))))) as Map<String,
          dynamic>);

  /// Retire les annotations `meta:enum` de CycloneDX : leurs clés (ex.
  /// `required`) sont prises pour des mots-clés de schéma par la bibliothèque.
  static Object? _clean(Object? v) {
    if (v is Map) {
      return <String, dynamic>{
        for (final e in v.entries)
          if (e.key != 'meta:enum') '${e.key}': _clean(e.value),
      };
    }
    if (v is List) return [for (final x in v) _clean(x)];
    return v;
  }

  /// Clé du schéma applicable à [sbom], ou `null` si aucun n'est embarqué
  /// (format inconnu ou version de spécification non supportée).
  static String? schemaKeyFor(Map<String, dynamic> sbom) {
    switch (SbomReader.detectFormat(sbom)) {
      case SbomFormat.cyclonedx:
        final v = '${sbom['specVersion'] ?? ''}';
        final key = 'cyclonedx-$v';
        return embeddedSchemas.containsKey(key) ? key : null;
      case SbomFormat.spdx2:
        final v = '${sbom['spdxVersion'] ?? ''}';
        return v == 'SPDX-2.3' ? 'spdx-2.3' : null;
      case SbomFormat.spdx3:
        return 'spdx3-3.0.0';
      case SbomFormat.unknown:
        return null;
    }
  }

  /// Les schémas CycloneDX renvoient vers deux schémas externes
  /// (`spdx.schema.json`, `jsf-0.82.schema.json`) par des définitions qui ne
  /// sont elles-mêmes que des `$ref` : la bibliothèque ne sait pas les
  /// enchaîner. On les inline dans les définitions du schéma principal.
  static Map<String, dynamic> _inlineExternalRefs(Map<String, dynamic> bom) {
    final defs = Map<String, dynamic>.from(bom['definitions'] as Map);
    final jsf = _load('cyclonedx-jsf')['definitions'] as Map;
    for (final e in jsf.entries) {
      defs['${e.key}'] = e.value;
    }
    final crypto = _load('cyclonedx-crypto')['definitions'] as Map;
    for (final e in crypto.entries) {
      defs['${e.key}'] = e.value;
    }
    final spdx = Map<String, dynamic>.from(_load('cyclonedx-spdx'))
      ..remove(r'$schema')
      ..remove(r'$id');
    defs['spdxLicenseId'] = spdx;
    Object? fix(Object? v) {
      if (v is Map) {
        return <String, dynamic>{
          for (final e in v.entries)
            '${e.key}': e.key == r'$ref' && e.value is String
                ? _fixRef(e.value as String)
                : fix(e.value),
        };
      }
      if (v is List) return [for (final x in v) fix(x)];
      return v;
    }

    return fix({...bom, 'definitions': defs}) as Map<String, dynamic>;
  }

  static String _fixRef(String ref) {
    if (ref.startsWith('jsf-0.82.schema.json#')) {
      return ref.substring('jsf-0.82.schema.json'.length);
    }
    if (ref.startsWith('cryptography-defs.schema.json#')) {
      return ref.substring('cryptography-defs.schema.json'.length);
    }
    if (ref == 'spdx.schema.json') return '#/definitions/spdxLicenseId';
    return ref;
  }

  static JsonSchema _schema(String key) => _compiled.putIfAbsent(key, () {
        final raw = _load(key);
        return JsonSchema.create(
            key.startsWith('cyclonedx-') ? _inlineExternalRefs(raw) : raw);
      });

  /// Erreurs de conformité au schéma (vide si le document est valide) ;
  /// `null` si aucun schéma n'est disponible pour ce document.
  static List<String>? validate(Map<String, dynamic> sbom, {int max = 50}) {
    final key = schemaKeyFor(sbom);
    if (key == null) return null;
    final result = _schema(key).validate(sbom);
    if (result.isValid) return const [];
    final errors = <String>[];
    for (final e in result.errors) {
      final path = e.instancePath.isEmpty ? '/' : e.instancePath;
      errors.add('$path : ${e.message}');
      if (errors.length >= max) {
        errors.add(tr('… (liste tronquée à $max erreurs)',
            '… (list truncated to $max errors)'));
        break;
      }
    }
    return errors;
  }
}
