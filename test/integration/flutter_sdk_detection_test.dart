/// `pubspec.lock` : la version du SDK Flutter est détectée par projet (FVM) ;
/// `--sdk-version` explicite prime toujours.
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() {
    tmp = Directory.systemTemp.createTempSync('flutter_sdk_');
    Directory('${tmp.path}/nobin').createSync();
  });
  tearDown(() => tmp.deleteSync(recursive: true));

  const lock = '''
packages:
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
''';

  Future<ProcessResult> gen(Directory proj, [List<String> extra = const []]) =>
      Process.run(
        Platform.resolvedExecutable,
        [
          'run', 'bin/sbom_generator.dart', '--lang', 'en', //
          '-i', '${proj.path}/pubspec.lock', '-f', 'cyclonedx',
          '-o', '${proj.path}/out', ...extra,
        ],
        // Aucun Flutter global : seule la détection par projet peut répondre.
        environment: {
          'FLUTTER_ROOT': '',
          'PATH': Directory('${tmp.path}/nobin').path
        },
      );

  String? flutterVersion(Directory proj) {
    final j =
        jsonDecode(File('${proj.path}/out.cdx.json').readAsStringSync()) as Map;
    for (final c in j['components'] as List) {
      if (c['name'] == 'flutter') return c['version'] as String?;
    }
    return null;
  }

  test('.fvmrc du projet → version du composant flutter', () async {
    final proj = Directory('${tmp.path}/p')..createSync();
    File('${proj.path}/pubspec.lock').writeAsStringSync(lock);
    File('${proj.path}/.fvmrc').writeAsStringSync('{"flutter":"3.41.2"}');
    final r = await gen(proj);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(flutterVersion(proj), '3.41.2');
    expect(r.stderr, contains('Flutter SDK version detected'));
  });

  test('--sdk-version explicite prime sur .fvmrc', () async {
    final proj = Directory('${tmp.path}/p')..createSync();
    File('${proj.path}/pubspec.lock').writeAsStringSync(lock);
    File('${proj.path}/.fvmrc').writeAsStringSync('{"flutter":"3.41.2"}');
    final r = await gen(proj, ['--sdk-version', 'flutter=3.50.0']);
    expect(flutterVersion(proj), '3.50.0');
    expect(r.stderr, isNot(contains('detected')));
  });

  test('aucune détection possible : avertissement, composant sans version',
      () async {
    final proj = Directory('${tmp.path}/p')..createSync();
    File('${proj.path}/pubspec.lock').writeAsStringSync(lock);
    final r = await gen(proj);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(flutterVersion(proj), anyOf(isNull, isEmpty));
    expect(r.stderr, contains('Flutter SDK version unknown'));
  });
}
