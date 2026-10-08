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
