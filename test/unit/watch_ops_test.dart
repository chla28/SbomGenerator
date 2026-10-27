import 'dart:convert';
import 'dart:io';

import 'package:sbom_generator/offline_bundle.dart';
import 'package:sbom_generator/watch_history.dart';
import 'package:sbom_generator/watch_schedule.dart';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('watch_ops_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  group('historique', () {
    test('entrée issue d\'un scan : sévérités en minuscules', () {
      final e = historyEntryFromScan({
        'findings': [
          {'severity': 'Critical'},
          {'severity': 'High'},
          {'severity': 'high'},
          {},
        ]
      }, added: 2, resolved: 1, now: DateTime.utc(2026, 1, 1));
      expect(e.total, 4);
      expect(e.bySeverity, {'critical': 1, 'high': 2, 'unknown': 1});
    });

    test('ajout puis relecture ; lignes corrompues ignorées', () {
      final state = '${tmp.path}/app.cdx.json-1234.json';
      appendHistory(state,
          HistoryEntry(at: DateTime.utc(2026, 1, 1), total: 3, added: 3));
      File(historyFileFor(state))
          .writeAsStringSync('pas du json\n', mode: FileMode.append);
      appendHistory(state,
          HistoryEntry(at: DateTime.utc(2026, 1, 2), total: 2, resolved: 1));
      final h = readHistory(historyFileFor(state));
      expect(h.map((e) => e.total), [3, 2]);
      expect(
          historyFileFor(state), endsWith('app.cdx.json-1234.history.jsonl'));
    });

    test('historique borné aux plus récents', () {
      final state = '${tmp.path}/s.json';
      for (var i = 0; i < maxHistoryEntries + 5; i++) {
        appendHistory(
            state, HistoryEntry(at: DateTime.utc(2026, 1, 1), total: i));
      }
      final h = readHistory(historyFileFor(state));
      expect(h, hasLength(maxHistoryEntries));
      expect(h.last.total, maxHistoryEntries + 4);
      expect(h.first.total, 5);
    });

    test('fichier absent : liste vide', () {
      expect(readHistory('${tmp.path}/absent.jsonl'), isEmpty);
    });
  });

  group('planification', () {
    test('cron', () {
      expect(cronExpression(const Duration(minutes: 30)), '*/30 * * * *');
      expect(cronExpression(const Duration(hours: 6)), '0 */6 * * *');
      expect(cronExpression(const Duration(days: 1)), '0 3 * * *');
      expect(cronExpression(const Duration(days: 7)), '0 3 */7 * *');
      for (final bad in [
        const Duration(seconds: 30),
        const Duration(minutes: 7),
        const Duration(hours: 5),
        const Duration(hours: 36),
      ]) {
        expect(() => cronExpression(bad), throwsFormatException,
            reason: '$bad');
      }
    });

    test('quote shell : espaces et apostrophes', () {
      expect(shellQuote('a-b/c.json'), 'a-b/c.json');
      expect(shellQuote('mon dossier'), "'mon dossier'");
      expect(shellQuote("l'a"), r"'l'\''a'");
      expect(commandLine(['x', 'a b']), "x 'a b'");
    });

    test('systemd : oneshot, code 3 accepté, minuterie', () {
      final svc =
          systemdService(['/usr/bin/sbom_generator', 'watch', 'sbom dir']);
      expect(
          svc, contains("ExecStart=/usr/bin/sbom_generator watch 'sbom dir'"));
      expect(svc, contains('SuccessExitStatus=3'));
      expect(svc, contains('Type=oneshot'));
      expect(systemdTimer(const Duration(hours: 6)),
          contains('OnUnitActiveSec=6h'));
      expect(systemdTimer(const Duration(minutes: 90)),
          contains('OnUnitActiveSec=90min'));
      expect(systemdTimer(const Duration(days: 1)),
          contains('OnUnitActiveSec=1d'));
    });
  });

  group('bundle hors-ligne', () {
    Directory cache(String name, Map<String, Object> files) {
      final d = Directory('${tmp.path}/$name')..createSync();
      files.forEach(
          (n, c) => File('${d.path}/$n').writeAsStringSync(jsonEncode(c)));
      return d;
    }

    test('export puis import dans un cache vide', () {
      final src = cache('src', {
        'kev.json': {
          'fetchedAt': '2026-01-02T00:00:00Z',
          'cves': {'CVE-1': {}}
        },
        'epss.json': {
          'CVE-1': {'score': 0.5, 'fetchedAt': '2026-01-02T00:00:00Z'}
        },
      });
      final out = '${tmp.path}/b.json.gz';
      expect(exportOfflineBundle(src, out), ['kev.json', 'epss.json']);
      final dst = Directory('${tmp.path}/dst');
      expect(importOfflineBundle(out, dst), ['kev.json', 'epss.json']);
      expect(cacheStatus(dst).map((i) => '${i.name}:${i.entries}'),
          ['kev.json:1', 'epss.json:1']);
    });

    test('import : KEV plus récent conservé, EPSS fusionné par CVE', () {
      final src = cache('src', {
        'kev.json': {
          'fetchedAt': '2026-01-01T00:00:00Z',
          'cves': {'OLD': {}}
        },
        'epss.json': {
          'CVE-1': {'score': 0.1, 'fetchedAt': '2026-01-01T00:00:00Z'},
          'CVE-2': {'score': 0.9, 'fetchedAt': '2026-03-01T00:00:00Z'},
        },
      });
      final out = '${tmp.path}/b.json.gz';
      exportOfflineBundle(src, out);
      final dst = cache('dst', {
        'kev.json': {
          'fetchedAt': '2026-02-01T00:00:00Z',
          'cves': {'NEW': {}}
        },
        'epss.json': {
          'CVE-1': {'score': 0.7, 'fetchedAt': '2026-02-01T00:00:00Z'},
          'CVE-2': {'score': 0.2, 'fetchedAt': '2026-02-01T00:00:00Z'},
          'CVE-3': {'score': 0.3, 'fetchedAt': '2026-02-01T00:00:00Z'},
        },
      });
      importOfflineBundle(out, dst);
      final kev = jsonDecode(File('${dst.path}/kev.json').readAsStringSync());
      expect((kev['cves'] as Map).keys, ['NEW']); // le local est plus récent
      final epss =
          jsonDecode(File('${dst.path}/epss.json').readAsStringSync()) as Map;
      expect(epss['CVE-1']['score'], 0.7); // local plus récent
      expect(epss['CVE-2']['score'], 0.9); // bundle plus récent
      expect(epss.containsKey('CVE-3'), isTrue); // conservé
    });

    test('cache sans KEV : export refusé', () {
      final src = cache('src', {'epss.json': {}});
      expect(() => exportOfflineBundle(src, '${tmp.path}/x.gz'),
          throwsA(isA<OfflineException>()));
    });

    test('bundle altéré, nom inattendu, illisible : refusés sans écriture', () {
      Map<String, dynamic> doc(Map<String, dynamic> files) =>
          {'format': 'sbom-generator-offline/v1', 'files': files};
      String write(Map<String, dynamic> d) {
        final p = '${tmp.path}/${d.hashCode}.gz';
        File(p).writeAsBytesSync(gzip.encode(utf8.encode(jsonEncode(d))));
        return p;
      }

      final dst = Directory('${tmp.path}/dst');
      final tampered = write(doc({
        'kev.json': {'sha256': 'f' * 64, 'content': '{}'}
      }));
      expect(() => importOfflineBundle(tampered, dst),
          throwsA(isA<OfflineException>()));
      final traversal = write(doc({
        '../evil.json': {'sha256': 'x', 'content': '{}'}
      }));
      expect(() => importOfflineBundle(traversal, dst),
          throwsA(isA<OfflineException>()));
      File('${tmp.path}/junk.gz').writeAsStringSync('pas un gzip');
      expect(() => importOfflineBundle('${tmp.path}/junk.gz', dst),
          throwsA(isA<OfflineException>()));
      expect(dst.existsSync(), isFalse);
      expect(File('${tmp.path}/evil.json').existsSync(), isFalse);
    });
  });
}
