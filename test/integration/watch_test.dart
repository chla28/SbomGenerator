/// `watch` : état initial, détection des nouvelles CVE, notification et code
/// de retour — avec un faux `grype` dont la sortie change entre deux passages.
@TestOn('posix')
library;

import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  late Map<String, String> env;
  late String sbom;
  late File grype;

  /// Réécrit le faux grype pour qu'il signale ces CVE.
  void grypeFinds(List<String> ids) {
    final json = jsonEncode({
      'matches': [
        for (final id in ids)
          {
            'vulnerability': {'id': id, 'severity': 'High'},
            'artifact': {'name': 'liba', 'version': '1.0'},
          },
      ],
    });
    grype.writeAsStringSync('#!/bin/sh\n'
        'if [ "\$1" = "version" ]; then echo "Version: 0.99.0"; exit 0; fi\n'
        "cat <<'EOF'\n$json\nEOF\n"
        'exit 1\n');
  }

  setUp(() {
    tmp = Directory.systemTemp.createTempSync('watch_it_');
    final bin = Directory('${tmp.path}/bin')..createSync();
    grype = File('${bin.path}/grype');
    grypeFinds(['CVE-2024-0001']);
    Process.runSync('chmod', ['+x', grype.path]);
    env = {
      'PATH': '${bin.path}:${Platform.environment['PATH']}',
      'SBOMGEN_OFFLINE': '1',
      'XDG_CACHE_HOME': '${tmp.path}/cache',
    };
    sbom = '${tmp.path}/s.cdx.json';
    File(sbom).writeAsStringSync(jsonEncode({
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'components': [
        {
          'type': 'library',
          'name': 'liba',
          'version': '1.0',
          'purl': 'pkg:generic/liba@1.0',
        },
      ],
    }));
  });
  tearDown(() => tmp.deleteSync(recursive: true));

  Future<ProcessResult> watch(List<String> extra) => Process.run(
      'dart',
      [
        'run',
        'bin/sbom_generator.dart',
        '--lang',
        'en',
        'watch',
        sbom,
        '--state-dir',
        '${tmp.path}/state',
        '--scan-arg=--no-enrich',
        ...extra,
      ],
      environment: env);

  test('premier passage : état initial, code 0 ; second identique : code 0',
      () async {
    var r = await watch([]);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(r.stdout, contains('initial state recorded'));
    r = await watch([]);
    expect(r.exitCode, 0, reason: '${r.stderr}');
    expect(r.stdout, contains('no new CVE'));
  });

  test('nouvelle CVE : listée, code 3, puis plus signalée au passage suivant',
      () async {
    await watch([]);
    grypeFinds(['CVE-2024-0001', 'CVE-2024-0002']);
    var r = await watch([]);
    expect(r.exitCode, 3, reason: '${r.stderr}');
    expect(r.stdout, contains('CVE-2024-0002'));
    expect(r.stdout, isNot(contains('+ CVE-2024-0001')));
    r = await watch([]);
    expect(r.exitCode, 0);
  });

  test('--notify-cmd reçoit le nombre et le rapport des nouvelles CVE',
      () async {
    await watch([]);
    grypeFinds(['CVE-2024-0001', 'CVE-2024-0009']);
    final out = '${tmp.path}/notified';
    final r = await watch([
      '--notify-cmd',
      'echo "\$SBOMGEN_WATCH_NEW" > $out; cat "\$SBOMGEN_WATCH_REPORT" >> $out',
    ]);
    expect(r.exitCode, 3, reason: '${r.stderr}');
    final text = File(out).readAsStringSync();
    expect(text, startsWith('1\n'));
    expect(text, contains('CVE-2024-0009'));
  });

  test('notification en échec : code 1 et état conservé (nouvel essai)',
      () async {
    await watch([]);
    grypeFinds(['CVE-2024-0001', 'CVE-2024-0002']);
    var r = await watch(['--notify-cmd', 'exit 7']);
    expect(r.exitCode, 1);
    expect(r.stdout, contains('notify-cmd failed'));
    r = await watch([]); // sans notification : la CVE est encore « nouvelle »
    expect(r.exitCode, 3);
    expect(r.stdout, contains('CVE-2024-0002'));
  });

  test('sortie json : un événement par SBOM', () async {
    await watch([]);
    grypeFinds(['CVE-2024-0001', 'CVE-2024-0003']);
    final r = await watch(['-f', 'json']);
    final event = jsonDecode((r.stdout as String).trim().split('\n').last)
        as Map<String, dynamic>;
    expect(event['status'], 'changed');
    expect((event['new'] as List).single['id'], 'CVE-2024-0003');
  });

  test('SBOM absent : erreur, code 1', () async {
    final r = await Process.run(
        'dart',
        [
          'run',
          'bin/sbom_generator.dart',
          '--lang',
          'en',
          'watch',
          '${tmp.path}/nope.cdx.json',
          '-d',
          '${tmp.path}/state',
        ],
        environment: env);
    expect(r.exitCode, 1);
    expect(r.stdout, contains('file not found'));
  });

  test('intervalle invalide : erreur d\'usage', () async {
    final r = await watch(['--interval', 'bientôt']);
    expect(r.exitCode, 1);
    expect(r.stderr, contains('--interval'));
  });

  group('notifications et historique', () {
    test('webhook : reçoit les nouvelles CVE ; en échec, l\'état est conservé',
        () async {
      await watch([]);
      grypeFinds(['CVE-2024-0001', 'CVE-2024-0002']);
      final received = <Map<String, dynamic>>[];
      var status = 500;
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      server.listen((req) async {
        received.add(jsonDecode(await utf8.decoder.bind(req).join())
            as Map<String, dynamic>);
        req.response.statusCode = status;
        await req.response.close();
      });
      final url = 'http://127.0.0.1:${server.port}/hook?token=SECRET';

      var r = await watch(['--notify-webhook', url]);
      expect(r.exitCode, 1); // webhook en échec
      expect('${r.stdout}${r.stderr}', isNot(contains('SECRET')));
      expect(received.single['newCount'], 1);
      expect(received.single['text'], contains('CVE-2024-0002'));

      status = 200;
      r = await watch(['--notify-webhook', url]);
      expect(r.exitCode, 3, reason: '${r.stderr}'); // renvoyé car état conservé
      expect(received, hasLength(2));
      r = await watch(['--notify-webhook', url]);
      expect(r.exitCode, 0);
      expect(received, hasLength(2));
    });

    test('SMTP sans chiffrement : message remis au relais', () async {
      await watch([]);
      grypeFinds(['CVE-2024-0001', 'CVE-2024-0002']);
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(server.close);
      final commands = <String>[];
      server.listen((sock) {
        void send(String l) => sock.write('$l\r\n');
        send('220 hi');
        var inData = false;
        utf8.decoder.bind(sock).transform(const LineSplitter()).listen((l) {
          if (inData) {
            if (l == '.') {
              inData = false;
              send('250 ok');
            }
            return;
          }
          commands.add(l);
          if (l.startsWith('EHLO')) {
            send('250 hi');
          } else if (l == 'DATA') {
            inData = true;
            send('354 go');
          } else if (l == 'QUIT') {
            send('221 bye');
            sock.close();
          } else {
            send('250 ok');
          }
        });
      });
      final r = await watch([
        '--notify-smtp',
        '127.0.0.1:${server.port}',
        '--smtp-security',
        'none',
        '--notify-from',
        'watch@example.org',
        '--notify-to',
        'ops@example.org',
      ]);
      expect(r.exitCode, 3, reason: '${r.stderr}');
      expect(commands, contains('RCPT TO:<ops@example.org>'));
    });

    test('--notify-smtp sans destinataire : erreur d\'usage', () async {
      final r = await watch(['--notify-smtp', 'localhost']);
      expect(r.exitCode, 1);
      expect(r.stderr, contains('--notify-from'));
    });

    test('historique : une ligne par passage, nouvelle CVE comptée', () async {
      await watch([]);
      await watch([]);
      grypeFinds(['CVE-2024-0001', 'CVE-2024-0002']);
      await watch([]);
      final h = Directory('${tmp.path}/state')
          .listSync()
          .whereType<File>()
          .singleWhere((f) => f.path.endsWith('.history.jsonl'));
      final lines = h.readAsLinesSync().map(jsonDecode).toList();
      expect(lines.map((l) => l['total']), [1, 1, 2]);
      expect(lines.last['added'], 1);
      expect(lines.last['bySeverity'], {'high': 2});
    });
  });

  group('--print-schedule', () {
    test('systemd : service sans --interval, minuterie, code 3 accepté',
        () async {
      final r =
          await watch(['--interval', '6h', '--print-schedule', 'systemd']);
      expect(r.exitCode, 0, reason: '${r.stderr}');
      final out = r.stdout as String;
      expect(out, contains('sbom-generator-watch.service'));
      expect(out, contains('OnUnitActiveSec=6h'));
      expect(out, contains('SuccessExitStatus=3'));
      expect(out, contains('ExecStart='));
      expect(out, contains('watch'));
      expect(out, isNot(contains('--interval')));
      expect(out, isNot(contains('--print-schedule')));
    });

    test('cron : expression et répertoire de travail', () async {
      final r = await watch(['-i', '30m', '--print-schedule', 'cron']);
      expect(r.exitCode, 0, reason: '${r.stderr}');
      expect(r.stdout, startsWith('*/30 * * * * cd '));
    });

    test('intervalle absent ou non exprimable en cron : erreur', () async {
      expect((await watch(['--print-schedule', 'cron'])).exitCode, 1);
      expect(
          (await watch(['-i', '7m', '--print-schedule', 'cron'])).exitCode, 1);
    });
  });
}
