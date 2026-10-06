// Télécharge les schémas JSON officiels (CycloneDX, SPDX) et les embarque,
// compressés (gzip + base64), dans lib/schemas_data.dart pour que `validate`
// fonctionne hors-ligne dans l'exécutable compilé.
//
//   dart run tool/embed_schemas.dart
//
// Sources : CycloneDX/specification (Apache-2.0), spdx/spdx-spec (CC0-1.0 pour
// les schémas), spdx.org/schema.
import 'dart:convert';
import 'dart:io';

const _cdx =
    'https://raw.githubusercontent.com/CycloneDX/specification/master/schema';

const _sources = <String, String>{
  'cyclonedx-1.4': '$_cdx/bom-1.4.schema.json',
  'cyclonedx-1.5': '$_cdx/bom-1.5.schema.json',
  'cyclonedx-1.6': '$_cdx/bom-1.6.schema.json',
  'cyclonedx-1.7': '$_cdx/bom-1.7.schema.json',
  'cyclonedx-spdx': '$_cdx/spdx.schema.json',
  'cyclonedx-jsf': '$_cdx/jsf-0.82.schema.json',
  'cyclonedx-crypto': '$_cdx/cryptography-defs.schema.json',
  'spdx-2.3':
      'https://raw.githubusercontent.com/spdx/spdx-spec/support/2.3/schemas/spdx-schema.json',
  'spdx3-3.0.0': 'https://spdx.org/schema/3.0.0/spdx-json-schema.json',
};

Future<void> main() async {
  final client = HttpClient();
  final out = StringBuffer()
    ..writeln('// GÉNÉRÉ par tool/embed_schemas.dart — ne pas modifier à la main.')
    ..writeln('// Schémas JSON officiels CycloneDX (Apache-2.0) et SPDX, minifiés,')
    ..writeln('// compressés en gzip puis encodés en base64.')
    ..writeln()
    ..writeln('const embeddedSchemas = <String, String>{');
  for (final e in _sources.entries) {
    final req = await client.getUrl(Uri.parse(e.value));
    final res = await req.close();
    if (res.statusCode != 200) {
      stderr.writeln('${e.value} : HTTP ${res.statusCode}');
      exit(1);
    }
    final body = await utf8.decodeStream(res);
    final min = jsonEncode(jsonDecode(body));
    final b64 = base64.encode(gzip.encode(utf8.encode(min)));
    out.writeln("  '${e.key}': '$b64',");
    stderr.writeln('${e.key}: ${body.length} → ${b64.length}');
  }
  out.writeln('};');
  File('lib/schemas_data.dart').writeAsStringSync(out.toString());
  client.close();
}
