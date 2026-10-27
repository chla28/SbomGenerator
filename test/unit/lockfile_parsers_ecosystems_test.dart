import 'dart:convert';
import 'dart:io';

import 'package:sbom_generator/nuget_parser.dart';
import 'package:sbom_generator/python_lock_parser.dart';
import 'package:sbom_generator/swift_parser.dart';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('lockfiles2_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  String write(String name, String content) {
    final f = File('${tmp.path}/$name')..writeAsStringSync(content);
    return f.path;
  }

  final sha256 = 'a' * 64;
  final sri = 'sha512-${base64.encode(List.filled(64, 9))}';

  group('NugetParser', () {
    test('packages.lock.json : projets exclus, doublons entre TFM fusionnés',
        () {
      final path = write(
          'packages.lock.json',
          jsonEncode({
            'version': 1,
            'dependencies': {
              'net8.0': {
                'Newtonsoft.Json': {
                  'type': 'Direct',
                  'resolved': '13.0.1',
                  'contentHash': base64.encode(List.filled(64, 9)),
                },
                'MonProjet': {'type': 'Project'},
              },
              'net6.0': {
                'Newtonsoft.Json': {'type': 'Direct', 'resolved': '13.0.1'},
              },
            },
          }));
      final pkgs = NugetParser().parsePackagesLock(path);
      expect(pkgs.map((p) => '${p.name}@${p.version}'),
          ['Newtonsoft.Json@13.0.1']);
      // La casse du nom est conservée dans le PURL NuGet.
      expect(pkgs.single.purl, 'pkg:nuget/Newtonsoft.Json@13.0.1');
      expect(pkgs.single.hashes.single.alg, 'SHA-512');
    });

    test('deps.json : seuls les éléments de type package', () {
      final path = write(
          'app.deps.json',
          jsonEncode({
            'libraries': {
              'app/1.0.0': {'type': 'project'},
              'Serilog/3.1.1': {'type': 'package', 'sha512': sri},
            },
          }));
      final pkgs = NugetParser().parseDepsJson(path);
      expect(pkgs.map((p) => '${p.name}@${p.version}'), ['Serilog@3.1.1']);
      expect(pkgs.single.hashes, hasLength(1));
    });

    test('csproj : attribut, élément enfant, bornes de plage, propriétés', () {
      final path = write('app.csproj', r'''
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Dapper" Version="2.1.35" />
    <PackageReference Include="Polly">
      <Version>8.2.0</Version>
    </PackageReference>
    <PackageReference Include="Humanizer" Version="[2.14.1,3.0)" />
    <PackageReference Include="Calculee" Version="$(CalcVersion)" />
    <PackageReference Update="Dapper" Version="9.9.9" />
  </ItemGroup>
</Project>
''');
      final pkgs = NugetParser().parseProject(path);
      expect(pkgs.map((p) => '${p.name}@${p.version}'),
          ['Dapper@2.1.35', 'Polly@8.2.0', 'Humanizer@2.14.1']);
    });
  });

  group('PythonLockParser', () {
    test('uv.lock : projet virtuel/éditable écartés, sdist hashé', () {
      final path = write('uv.lock', '''
version = 1

[[package]]
name = "mon-projet"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files/requests-2.31.0.tar.gz", hash = "sha256:$sha256", size = 1 }
wheels = [
    { url = "https://files/requests-2.31.0-py3-none-any.whl", hash = "sha256:${'b' * 64}", size = 2 },
]

[[package]]
name = "local-lib"
version = "1.0.0"
source = { editable = "../local-lib" }
''');
      final pkgs = PythonLockParser().parseLock(path);
      expect(pkgs.map((p) => '${p.name}@${p.version}'), ['requests@2.31.0']);
      expect(pkgs.single.purl, 'pkg:pypi/requests@2.31.0');
      expect(pkgs.single.hashes.single.content, sha256);
    });

    test('poetry.lock : sous-tables ignorées, source directory écartée', () {
      final path = write('poetry.lock', '''
[[package]]
name = "flask"
version = "3.0.0"
description = "Web"
files = [
    {file = "flask-3.0.0-py3-none-any.whl", hash = "sha256:${'c' * 64}"},
    {file = "flask-3.0.0.tar.gz", hash = "sha256:$sha256"},
]

[package.dependencies]
version = ">=1"
Werkzeug = ">=3.0"

[[package]]
name = "interne"
version = "0.0.1"

[package.source]
type = "directory"
url = "../interne"
''');
      final pkgs = PythonLockParser().parseLock(path);
      expect(pkgs.map((p) => '${p.name}@${p.version}'), ['flask@3.0.0']);
      expect(pkgs.single.hashes.single.content, sha256);
    });

    test('pdm.lock : fichiers hashés en ligne', () {
      final path = write('pdm.lock', '''
[[package]]
name = "idna"
version = "3.6"
files = [
    {file = "idna-3.6.tar.gz", hash = "sha256:$sha256"},
]
''');
      expect(
          PythonLockParser().parseLock(path).single.purl, 'pkg:pypi/idna@3.6');
    });
  });

  group('SwiftParser', () {
    test('format v2 : version, sinon commit', () {
      final path = write(
          'Package.resolved',
          jsonEncode({
            'version': 2,
            'pins': [
              {
                'identity': 'swift-nio',
                'location': 'https://github.com/apple/swift-nio.git',
                'state': {'revision': 'abc123', 'version': '2.62.0'},
              },
              {
                'identity': 'branchy',
                'location': 'git@github.com:org/branchy.git',
                'state': {'branch': 'main', 'revision': 'deadbeef'},
              },
            ],
          }));
      final pkgs = SwiftParser().parsePackageResolved(path);
      expect(pkgs.map((p) => p.purl), [
        'pkg:swift/github.com/apple/swift-nio@2.62.0',
        'pkg:swift/github.com/org/branchy@deadbeef',
      ]);
    });

    test('format v1 : object.pins', () {
      final path = write(
          'Package.resolved',
          jsonEncode({
            'version': 1,
            'object': {
              'pins': [
                {
                  'package': 'Yams',
                  'repositoryURL': 'https://github.com/jpsim/Yams.git',
                  'state': {
                    'branch': null,
                    'revision': 'r1',
                    'version': '5.0.6'
                  },
                },
              ],
            },
          }));
      expect(SwiftParser().parsePackageResolved(path).single.purl,
          'pkg:swift/github.com/jpsim/Yams@5.0.6');
    });
  });
}
