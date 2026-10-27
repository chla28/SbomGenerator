import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:sbom_generator/notify.dart';
import 'package:test/test.dart';

const _alert = WatchAlert(
    'sbom/app.cdx.json',
    [
      {'id': 'CVE-2024-0001', 'package': 'liba@1.0', 'severity': 'Critical'},
      {'id': 'CVE-2024-0002', 'package': 'libb@2.0'},
    ],
    5,
    1);

/// Serveur SMTP minimal sur RawSocket (comme le client, pour pouvoir passer
/// en TLS au milieu de la conversation). Enregistre les commandes reçues.
class FakeSmtp {
  final RawServerSocket _server;
  final SecurityContext? tlsContext;
  final bool implicitTls;
  final bool advertiseStarttls;
  final commands = <String>[];
  String data = '';
  int authCode;

  FakeSmtp._(this._server, this.tlsContext, this.implicitTls,
      this.advertiseStarttls, this.authCode);

  static Future<FakeSmtp> start(
      {SecurityContext? tls,
      bool implicitTls = false,
      bool advertiseStarttls = true,
      int authCode = 235}) async {
    final s = await RawServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final f = FakeSmtp._(s, tls, implicitTls, advertiseStarttls, authCode);
    s.listen(f._serve);
    return f;
  }

  int get port => _server.port;

  Future<void> _serve(RawSocket raw) async {
    var socket = raw;
    var secured = false;
    var sub = raw.listen(null);
    if (implicitTls) {
      socket = await RawSecureSocket.secureServer(raw, tlsContext,
          subscription: sub);
      secured = true;
      sub = socket.listen(null);
    }
    var pending = '';
    Completer<void>? wake;
    void attach() {
      sub.onData((e) {
        if (e == RawSocketEvent.read) {
          final d = socket.read();
          if (d != null) pending += utf8.decode(d);
          wake?.complete();
        }
      });
    }

    attach();
    void send(String s) {
      try {
        socket.write(utf8.encode('$s\r\n'));
      } catch (_) {}
    }

    Future<String> line() async {
      while (!pending.contains('\n')) {
        wake = Completer<void>();
        await wake!.future.timeout(const Duration(seconds: 5));
      }
      final i = pending.indexOf('\n');
      final l = pending.substring(0, i).replaceAll('\r', '');
      pending = pending.substring(i + 1);
      return l;
    }

    send('220 fake ESMTP');
    var inData = false;
    final body = StringBuffer();
    try {
      while (true) {
        final l = await line();
        if (inData) {
          if (l == '.') {
            inData = false;
            data = body.toString();
            send('250 queued');
          } else {
            body.writeln(l);
          }
          continue;
        }
        commands.add(l);
        if (l.startsWith('EHLO')) {
          send('250-fake');
          if (advertiseStarttls && !secured && tlsContext != null) {
            send('250-STARTTLS');
          }
          send('250 AUTH PLAIN');
        } else if (l == 'STARTTLS') {
          send('220 go');
          socket = await RawSecureSocket.secureServer(socket, tlsContext,
              subscription: sub);
          secured = true;
          sub = socket.listen(null);
          attach();
        } else if (l.startsWith('AUTH PLAIN')) {
          send('$authCode auth');
        } else if (l == 'DATA') {
          inData = true;
          send('354 go');
        } else if (l == 'QUIT') {
          send('221 bye');
          break;
        } else {
          send('250 ok');
        }
      }
    } catch (_) {}
    await socket.close();
  }

  Future<void> stop() => _server.close();
}

void main() {
  group('WatchAlert', () {
    test('charge utile : text pour Slack/Teams + détail', () {
      final p = _alert.toPayload();
      expect(p['text'], contains('CVE-2024-0001'));
      expect(p['newCount'], 2);
      expect((p['new'] as List).first['severity'], 'Critical');
    });
  });

  group('postWebhook', () {
    late HttpServer server;
    final bodies = <Map<String, dynamic>>[];
    var status = 200;

    setUp(() async {
      bodies.clear();
      status = 200;
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((req) async {
        bodies.add(jsonDecode(await utf8.decoder.bind(req).join())
            as Map<String, dynamic>);
        req.response.statusCode = status;
        await req.response.close();
      });
    });
    tearDown(() => server.close(force: true));

    test('POST JSON', () async {
      await postWebhook(
          Uri.parse('http://127.0.0.1:${server.port}/hook?token=secret'),
          _alert.toPayload());
      expect(bodies.single['sbom'], 'sbom/app.cdx.json');
    });

    test('HTTP 500 : erreur sans l\'URL complète', () async {
      status = 500;
      await expectLater(
          postWebhook(
              Uri.parse('http://127.0.0.1:${server.port}/hook?token=secret'),
              _alert.toPayload()),
          throwsA(isA<NotifyException>()
              .having((e) => e.message, 'message', contains('500'))
              .having((e) => e.message, 'message', isNot(contains('secret')))));
    });

    test('schéma non http : refusé', () async {
      await expectLater(postWebhook(Uri.parse('file:///tmp/x'), {}),
          throwsA(isA<NotifyException>()));
    });
  });

  group('parseSmtpTarget', () {
    test('ports par défaut selon la sécurité', () {
      expect(parseSmtpTarget('mail.example', SmtpSecurity.starttls),
          ('mail.example', 587));
      expect(parseSmtpTarget('mail.example', SmtpSecurity.tls),
          ('mail.example', 465));
      expect(parseSmtpTarget('mail.example', SmtpSecurity.none),
          ('mail.example', 25));
      expect(parseSmtpTarget('mail.example:2525', SmtpSecurity.none),
          ('mail.example', 2525));
    });
  });

  group('sendMail', () {
    test('sans chiffrement : enveloppe et corps base64', () async {
      final smtp = await FakeSmtp.start();
      addTearDown(smtp.stop);
      await sendMail(
        SmtpConfig(
            host: '127.0.0.1',
            port: smtp.port,
            security: SmtpSecurity.none,
            from: 'watch@example.org',
            to: ['a@example.org', 'b@example.org']),
        subject: 'Nouvelles CVE — éàü',
        body: _alert.text,
      );
      expect(smtp.commands, contains('MAIL FROM:<watch@example.org>'));
      expect(smtp.commands, contains('RCPT TO:<b@example.org>'));
      final encoded =
          smtp.data.split('\n\n').last.replaceAll(RegExp(r'\s'), '');
      expect(utf8.decode(base64.decode(encoded)), contains('CVE-2024-0001'));
      expect(smtp.data, contains('Subject: =?UTF-8?B?'));
    });

    test('identifiants sans chiffrement : refusés avant toute connexion',
        () async {
      await expectLater(
          sendMail(
              const SmtpConfig(
                  host: '127.0.0.1',
                  port: 1,
                  security: SmtpSecurity.none,
                  from: 'a@b',
                  to: ['c@d'],
                  user: 'u',
                  password: 'p'),
              subject: 's',
              body: 'b'),
          throwsA(isA<NotifyException>()));
    });

    test('injection dans les adresses neutralisée', () async {
      final smtp = await FakeSmtp.start();
      addTearDown(smtp.stop);
      await sendMail(
        SmtpConfig(
            host: '127.0.0.1',
            port: smtp.port,
            security: SmtpSecurity.none,
            from: 'a@b>\r\nRCPT TO:<evil@x',
            to: ['c@d']),
        subject: 's',
        body: 'b',
      );
      expect(smtp.commands.where((c) => c.contains('evil')), hasLength(1));
      expect(
          smtp.commands.where((c) => c.startsWith('RCPT TO:<evil')), isEmpty);
    });

    test('réponse d\'erreur du serveur : NotifyException', () async {
      final smtp = await FakeSmtp.start(authCode: 535);
      addTearDown(smtp.stop);
      // Authentification refusée mais sans TLS : rejetée avant. On vérifie
      // ici le chemin « STARTTLS non proposé ».
      await expectLater(
          sendMail(
              SmtpConfig(
                  host: '127.0.0.1',
                  port: smtp.port,
                  security: SmtpSecurity.starttls,
                  from: 'a@b',
                  to: const ['c@d']),
              subject: 's',
              body: 'b'),
          throwsA(isA<NotifyException>()
              .having((e) => e.message, 'message', contains('STARTTLS'))));
    });

    group('TLS (certificat auto-signé)', () {
      late Directory dir;
      SecurityContext? server, client;

      setUpAll(() async {
        dir = Directory.systemTemp.createTempSync('smtp_tls_');
        final r = await Process.run('openssl', [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-days',
          '2',
          '-subj',
          '/CN=localhost',
          '-addext',
          'subjectAltName=DNS:localhost,IP:127.0.0.1',
          '-keyout',
          '${dir.path}/k.pem',
          '-out',
          '${dir.path}/c.pem',
        ]).catchError((_) => ProcessResult(0, 127, '', ''));
        if (r.exitCode != 0) return;
        server = SecurityContext()
          ..useCertificateChain('${dir.path}/c.pem')
          ..usePrivateKey('${dir.path}/k.pem');
        client = SecurityContext(withTrustedRoots: false)
          ..setTrustedCertificates('${dir.path}/c.pem');
      });
      tearDownAll(() => dir.deleteSync(recursive: true));

      test('STARTTLS puis AUTH PLAIN', () async {
        if (server == null) return markTestSkipped('openssl absent');
        final smtp = await FakeSmtp.start(tls: server);
        addTearDown(smtp.stop);
        await sendMail(
          SmtpConfig(
              host: '127.0.0.1',
              port: smtp.port,
              security: SmtpSecurity.starttls,
              from: 'a@b',
              to: const ['c@d'],
              user: 'u',
              password: 'p',
              context: client),
          subject: 's',
          body: 'b',
        );
        final starttls = smtp.commands.indexOf('STARTTLS');
        final auth =
            smtp.commands.indexWhere((c) => c.startsWith('AUTH PLAIN'));
        expect(starttls, greaterThan(-1));
        expect(auth, greaterThan(starttls)); // identifiants après chiffrement
        expect(smtp.commands.where((c) => c.startsWith('EHLO')), hasLength(2));
      });

      test('TLS implicite', () async {
        if (server == null) return markTestSkipped('openssl absent');
        final smtp = await FakeSmtp.start(tls: server, implicitTls: true);
        addTearDown(smtp.stop);
        await sendMail(
          SmtpConfig(
              host: '127.0.0.1',
              port: smtp.port,
              security: SmtpSecurity.tls,
              from: 'a@b',
              to: const ['c@d'],
              context: client),
          subject: 's',
          body: 'b',
        );
        expect(smtp.commands, contains('DATA'));
      });

      test('certificat non reconnu : échec', () async {
        if (server == null) return markTestSkipped('openssl absent');
        final smtp = await FakeSmtp.start(tls: server);
        addTearDown(smtp.stop);
        await expectLater(
            sendMail(
                SmtpConfig(
                    host: '127.0.0.1',
                    port: smtp.port,
                    security: SmtpSecurity.starttls,
                    from: 'a@b',
                    to: const ['c@d'],
                    context: SecurityContext(withTrustedRoots: false)),
                subject: 's',
                body: 'b'),
            throwsA(isA<NotifyException>()));
      });
    });
  });
}
