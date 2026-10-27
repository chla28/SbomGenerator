import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'i18n.dart';

/// Échec d'une notification ; le message ne contient jamais l'URL complète
/// d'un webhook (elle porte souvent un secret).
class NotifyException implements Exception {
  final String message;
  NotifyException(this.message);
  @override
  String toString() => message;
}

/// Contenu d'une alerte `watch` pour un SBOM.
class WatchAlert {
  final String sbom;
  final List<Map<String, dynamic>> added;
  final int total;
  final int resolved;

  const WatchAlert(this.sbom, this.added, this.total, this.resolved);

  String get summary => tr('{sbom} : {n} nouvelle(s) CVE ({total} au total)',
      {'sbom': sbom, 'n': added.length, 'total': total});

  String get text => [
        summary,
        for (final f in added)
          '  + ${f['id']}  ${f['package']}  ${f['severity'] ?? ''}'.trimRight(),
      ].join('\n');

  /// Charge utile générique : `text` est lu tel quel par les webhooks entrants
  /// de Slack, Mattermost et Teams ; les autres clés servent aux outils maison.
  Map<String, dynamic> toPayload() => {
        'text': text,
        'sbom': sbom,
        'newCount': added.length,
        'total': total,
        'resolved': resolved,
        'new': [
          for (final f in added)
            {
              'id': f['id'],
              'package': f['package'],
              if (f['severity'] != null) 'severity': f['severity'],
            },
        ],
      };
}

// ── Webhook ───────────────────────────────────────────────────────────────────

/// Envoie [payload] en JSON (POST) à [url] (http ou https).
Future<void> postWebhook(
  Uri url,
  Map<String, dynamic> payload, {
  Duration timeout = const Duration(seconds: 10),
  HttpClient Function()? clientFactory,
}) async {
  if (url.scheme != 'http' && url.scheme != 'https') {
    throw NotifyException(tr('webhook : schéma non pris en charge ({scheme})',
        {'scheme': url.scheme}));
  }
  final client = (clientFactory ?? HttpClient.new)();
  try {
    client.connectionTimeout = timeout;
    final req = await client.postUrl(url).timeout(timeout);
    req.headers.contentType =
        ContentType('application', 'json', charset: 'utf-8');
    req.add(utf8.encode(jsonEncode(payload)));
    final resp = await req.close().timeout(timeout);
    await resp.drain<void>();
    if (resp.statusCode >= 300) {
      throw NotifyException(tr('webhook {host} : réponse HTTP {code}',
          {'host': url.host, 'code': resp.statusCode}));
    }
  } on NotifyException {
    rethrow;
  } catch (e) {
    throw NotifyException(
        tr('webhook {host} : {e}', {'host': url.host, 'e': e}));
  } finally {
    client.close(force: true);
  }
}

// ── SMTP ──────────────────────────────────────────────────────────────────────

enum SmtpSecurity { none, starttls, tls }

class SmtpConfig {
  final String host;
  final int port;
  final SmtpSecurity security;
  final String from;
  final List<String> to;
  final String? user;
  final String? password;

  /// Contexte TLS (certificat d'une autorité privée) ; défaut : racines système.
  final SecurityContext? context;

  const SmtpConfig({
    required this.host,
    required this.port,
    required this.from,
    required this.to,
    this.security = SmtpSecurity.starttls,
    this.user,
    this.password,
    this.context,
  });
}

/// `hote:port` (port facultatif : 587 en STARTTLS, 465 en TLS, 25 sinon).
(String, int) parseSmtpTarget(String text, SmtpSecurity security) {
  final m = RegExp(r'^(.+?)(?::(\d{1,5}))?$').firstMatch(text.trim());
  if (m == null || m.group(1)!.isEmpty) {
    throw FormatException(tr(
        'adresse SMTP invalide : « {text} » (attendu : hote[:port])',
        {'text': text}));
  }
  final port = m.group(2) != null
      ? int.parse(m.group(2)!)
      : switch (security) {
          SmtpSecurity.tls => 465,
          SmtpSecurity.starttls => 587,
          SmtpSecurity.none => 25,
        };
  return (m.group(1)!, port);
}

/// Envoie un message texte. Les identifiants ne partent jamais sur une
/// connexion non chiffrée.
Future<void> sendMail(
  SmtpConfig c, {
  required String subject,
  required String body,
  Duration timeout = const Duration(seconds: 15),
}) async {
  if (c.user != null && c.security == SmtpSecurity.none) {
    throw NotifyException(tr(
        'smtp : refus d\'envoyer des identifiants sans chiffrement (utiliser --smtp-security starttls ou tls)'));
  }
  _SmtpChannel? ch;
  try {
    final raw = c.security == SmtpSecurity.tls
        ? await RawSecureSocket.connect(c.host, c.port,
            context: c.context, timeout: timeout)
        : await RawSocket.connect(c.host, c.port, timeout: timeout);
    ch = _SmtpChannel(raw, timeout);
    await ch.expect(220);
    var caps = await ch.command('EHLO sbom-generator', 250);
    if (c.security == SmtpSecurity.starttls) {
      if (!caps.contains('STARTTLS')) {
        throw NotifyException(tr('smtp : le serveur ne propose pas STARTTLS'));
      }
      await ch.command('STARTTLS', 220);
      await ch.upgrade(c.host, c.context);
      caps = await ch.command('EHLO sbom-generator', 250);
    }
    if (c.user != null) {
      final cred = base64
          .encode(utf8.encode('\u0000${c.user}\u0000${c.password ?? ''}'));
      await ch.command('AUTH PLAIN $cred', 235);
    }
    await ch.command('MAIL FROM:<${_addr(c.from)}>', 250);
    for (final r in c.to) {
      await ch.command('RCPT TO:<${_addr(r)}>', 250);
    }
    await ch.command('DATA', 354);
    await ch.command(_message(c, subject, body) + '\r\n.', 250);
    // Le message est accepté (250) : un échec de fermeture n'est pas une erreur.
    try {
      await ch.command('QUIT', 221);
    } catch (_) {}
  } on NotifyException {
    rethrow;
  } catch (e) {
    throw NotifyException(tr('smtp {host} : {e}', {'host': c.host, 'e': e}));
  } finally {
    await ch?.close();
  }
}

/// Retire tout ce qui permettrait d'injecter une commande SMTP.
String _addr(String a) => a.replaceAll(RegExp(r'[\r\n<>]'), '');

/// Message MIME : corps en base64 (UTF-8), donc sans ligne trop longue ni
/// ligne commençant par un point à échapper.
String _message(SmtpConfig c, String subject, String body) {
  String b64(String s) => base64.encode(utf8.encode(s));
  final lines = RegExp(r'.{1,76}').allMatches(b64(body)).map((m) => m[0]!);
  return [
    'From: ${_addr(c.from)}',
    'To: ${c.to.map(_addr).join(', ')}',
    'Subject: =?UTF-8?B?${b64(subject.replaceAll(RegExp(r'[\r\n]'), ' '))}?=',
    'Date: ${HttpDate.format(DateTime.now().toUtc()).replaceFirst('GMT', '+0000')}',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    ...lines,
  ].join('\r\n');
}

/// Canal SMTP sur RawSocket : seul moyen d'enchaîner lecture de lignes puis
/// mise à niveau STARTTLS sans perdre l'abonnement aux événements.
class _SmtpChannel {
  RawSocket _raw;
  late StreamSubscription<RawSocketEvent> _sub;
  final Duration timeout;
  var _pending = '';
  var _closed = false;
  Completer<void>? _wake;

  _SmtpChannel(this._raw, this.timeout) {
    _listen();
  }

  void _listen() {
    _sub = _raw.listen(_onEvent,
        onError: (_) => _markClosed(), onDone: _markClosed);
  }

  void _markClosed() {
    _closed = true;
    _wake?.complete();
  }

  void _onEvent(RawSocketEvent e) {
    if (e == RawSocketEvent.read) {
      final d = _raw.read();
      if (d != null) {
        _pending += utf8.decode(d, allowMalformed: true);
        _wake?.complete();
      }
    } else if (e == RawSocketEvent.readClosed || e == RawSocketEvent.closed) {
      _markClosed();
    }
  }

  Future<String> _line() async {
    while (true) {
      final i = _pending.indexOf('\n');
      if (i >= 0) {
        final line = _pending.substring(0, i).replaceAll('\r', '');
        _pending = _pending.substring(i + 1);
        return line;
      }
      if (_closed)
        throw NotifyException(tr('connexion SMTP fermée par le serveur'));
      _wake = Completer<void>();
      await _wake!.future.timeout(timeout,
          onTimeout: () => throw NotifyException(tr('délai SMTP dépassé')));
      _wake = null;
    }
  }

  /// Lit une réponse (éventuellement sur plusieurs lignes) ; renvoie ses lignes.
  Future<List<String>> _reply(int code) async {
    final lines = <String>[];
    while (true) {
      final l = await _line();
      lines.add(l);
      if (l.length < 4 || l[3] != '-') {
        final got = int.tryParse(l.length >= 3 ? l.substring(0, 3) : '') ?? 0;
        if (got != code) {
          throw NotifyException(
              tr('réponse SMTP inattendue : {line}', {'line': l}));
        }
        return lines;
      }
    }
  }

  Future<void> expect(int code) async => _reply(code);

  /// Envoie [cmd] et renvoie les capacités (texte des lignes de réponse).
  Future<String> command(String cmd, int code) async {
    await write('$cmd\r\n');
    return (await _reply(code)).join('\n').toUpperCase();
  }

  Future<void> write(String s) async {
    final bytes = utf8.encode(s);
    var off = 0;
    while (off < bytes.length) {
      final n = _raw.write(bytes, off);
      off += n;
      if (n == 0) await Future<void>.delayed(const Duration(milliseconds: 10));
    }
  }

  Future<void> upgrade(String host, SecurityContext? context) async {
    final secure = await RawSecureSocket.secure(_raw,
        host: host, context: context, subscription: _sub);
    _raw = secure;
    _listen();
  }

  Future<void> close() async {
    try {
      await _sub.cancel();
      await _raw.close();
    } catch (_) {}
  }
}
