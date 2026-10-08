import 'dart:io';

import 'package:sbom_generator/pubspec_parser.dart';
import 'package:test/test.dart';

void main() {
  late Directory root;
  setUp(() => root = Directory.systemTemp.createTempSync('flutter_root_'));
  tearDown(() => root.deleteSync(recursive: true));

  Directory cache() =>
      Directory('${root.path}/bin/cache')..createSync(recursive: true);

  test('lit frameworkVersion dans bin/cache/flutter.version.json', () {
    File('${cache().path}/flutter.version.json')
        .writeAsStringSync('{"frameworkVersion":"3.47.5","channel":"stable"}');
    expect(
        detectFlutterVersion(flutterRoot: root.path, path: '', env: const {}),
        '3.47.5');
  });

  test('repli sur le fichier « version » des anciennes installations', () {
    File('${root.path}/version').writeAsStringSync('3.19.6\n');
    expect(
        detectFlutterVersion(flutterRoot: root.path, path: '', env: const {}),
        '3.19.6');
  });

  test('JSON illisible : repli sur « version », sinon null', () {
    File('${cache().path}/flutter.version.json').writeAsStringSync('{pas json');
    expect(
        detectFlutterVersion(flutterRoot: root.path, path: '', env: const {}),
        isNull);
    File('${root.path}/version').writeAsStringSync('3.10.0');
    expect(
        detectFlutterVersion(flutterRoot: root.path, path: '', env: const {}),
        '3.10.0');
  });

  test('racine déduite de l\'exécutable flutter du PATH', () {
    final bin = Directory('${root.path}/bin')..createSync(recursive: true);
    File('${bin.path}/flutter').writeAsStringSync('#!/bin/sh\n');
    File('${root.path}/version').writeAsStringSync('3.22.1');
    expect(detectFlutterVersion(path: bin.path, env: const {}), '3.22.1');
  });

  group('projet épinglé avec FVM', () {
    late Directory proj;
    setUp(() =>
        proj = Directory('${root.path}/proj/sub')..createSync(recursive: true));

    String? detect({Map<String, String> env = const {}}) =>
        detectFlutterVersion(
            flutterRoot: root.path, path: '', env: env, projectDir: proj.path);

    test('.fvmrc avec une version : prime sur le Flutter global', () {
      File('${root.path}/version').writeAsStringSync('3.47.5');
      File('${root.path}/proj/.fvmrc')
          .writeAsStringSync('{"flutter": "3.41.2"}');
      expect(detect(), '3.41.2', reason: 'cherché aussi dans les parents');
    });

    test('.fvmrc « 3.41.2@beta » : suffixe de canal retiré', () {
      File('${proj.path}/.fvmrc')
          .writeAsStringSync('{"flutter":"3.41.2@beta"}');
      expect(detect(), '3.41.2');
    });

    test('.fvmrc avec un canal : version lue dans le cache FVM', () {
      final cache = Directory('${root.path}/fvmcache/versions/stable/bin/cache')
        ..createSync(recursive: true);
      File('${cache.path}/flutter.version.json')
          .writeAsStringSync('{"frameworkVersion":"3.44.0"}');
      File('${proj.path}/.fvmrc').writeAsStringSync('{"flutter":"stable"}');
      expect(
          detect(env: {'FVM_CACHE_PATH': '${root.path}/fvmcache'}), '3.44.0');
    });

    test('.fvm/flutter_sdk (lien) : version du SDK pointé', () {
      final sdk = Directory('${root.path}/sdk37')..createSync();
      File('${sdk.path}/version').writeAsStringSync('3.7.12');
      Directory('${proj.path}/.fvm').createSync();
      Link('${proj.path}/.fvm/flutter_sdk').createSync(sdk.path);
      expect(detect(), '3.7.12');
    });

    test('ancien .fvm/fvm_config.json', () {
      Directory('${proj.path}/.fvm').createSync();
      File('${proj.path}/.fvm/fvm_config.json')
          .writeAsStringSync('{"flutterSdkVersion":"3.3.10"}');
      expect(detect(), '3.3.10');
    });

    test('sans épinglage : Flutter global', () {
      File('${root.path}/version').writeAsStringSync('3.47.5');
      expect(detect(), '3.47.5');
    });
  });

  test('sdk absent : les pubspec.lock sans --sdk-version restent sans version',
      () {
    final lock = File('${root.path}/pubspec.lock')..writeAsStringSync('''
packages:
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
''');
    final pkgs = PubspecParser().parsePubspecLock(lock.path);
    expect(pkgs.single.name, 'flutter');
    expect(pkgs.single.version, isEmpty);
    final withSdk = PubspecParser()
        .parsePubspecLock(lock.path, sdkVersions: {'flutter': '3.47.5'});
    expect(withSdk.single.version, '3.47.5');
  });
}
