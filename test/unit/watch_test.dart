import 'dart:io';

import 'package:sbom_generator/watch.dart';
import 'package:test/test.dart';

Map<String, dynamic> _report(List<(String, String)> found) => {
      'findings': [
        for (final (id, pkg) in found)
          {'id': id, 'package': pkg, 'severity': 'High'},
      ],
    };

void main() {
  group('parseWatchInterval', () {
    test('unités s, m, h, d', () {
      expect(parseWatchInterval('90s'), const Duration(seconds: 90));
      expect(parseWatchInterval('30m'), const Duration(minutes: 30));
      expect(parseWatchInterval('6h'), const Duration(hours: 6));
      expect(parseWatchInterval(' 1d '), const Duration(days: 1));
    });

    test('valeurs invalides refusées', () {
      for (final bad in ['', 'x', '10', '0h', '5w', '-3m', '1.5h']) {
        expect(() => parseWatchInterval(bad), throwsFormatException,
            reason: bad);
      }
    });
  });

  group('diffScans', () {
    test('nouvelles et corrigées', () {
      final d = diffScans(
        _report([('CVE-1', 'a@1'), ('CVE-2', 'b@1')]),
        _report([('CVE-2', 'b@1'), ('CVE-3', 'c@1')]),
      );
      expect(d.added.map((f) => f['id']), ['CVE-3']);
      expect(d.resolved, 1);
      expect(d.total, 2);
    });

    test('même CVE sur une nouvelle version du paquet : pas nouvelle', () {
      final d =
          diffScans(_report([('CVE-1', 'a@1')]), _report([('CVE-1', 'a@2')]));
      expect(d.added, isEmpty);
    });

    test('même CVE sur un autre paquet : nouvelle', () {
      final d = diffScans(_report([('CVE-1', 'a@1')]),
          _report([('CVE-1', 'a@1'), ('CVE-1', 'b@1')]));
      expect(d.added.map((f) => f['package']), ['b@1']);
    });

    test('rapport sans findings : FormatException', () {
      expect(() => diffScans({}, _report([])), throwsFormatException);
    });
  });

  group('collectWatchedSboms / watchStateFile', () {
    late Directory tmp;
    setUp(() => tmp = Directory.systemTemp.createTempSync('watch_'));
    tearDown(() => tmp.deleteSync(recursive: true));

    test('dossier récursif filtré par extension, fichier explicite conservé',
        () {
      Directory('${tmp.path}/sub').createSync();
      for (final f in ['a.cdx.json', 'sub/b.spdx3.jsonld', 'c.txt', 'd.json']) {
        File('${tmp.path}/$f').writeAsStringSync('{}');
      }
      final found = collectWatchedSboms([tmp.path, '${tmp.path}/d.json']);
      expect(found.map((p) => p.split('/').last).toList()..sort(),
          ['a.cdx.json', 'b.spdx3.jsonld', 'd.json']);
    });

    test('même nom dans deux dossiers : états distincts', () {
      Directory('${tmp.path}/x').createSync();
      Directory('${tmp.path}/y').createSync();
      File('${tmp.path}/x/s.cdx.json').writeAsStringSync('{}');
      File('${tmp.path}/y/s.cdx.json').writeAsStringSync('{}');
      final a = watchStateFile('st', '${tmp.path}/x/s.cdx.json');
      final b = watchStateFile('st', '${tmp.path}/y/s.cdx.json');
      expect(a, isNot(b));
      expect(a, startsWith('st/s.cdx.json-'));
    });
  });
}
