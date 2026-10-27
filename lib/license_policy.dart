import 'i18n.dart';
import 'models.dart';

/// Une exception à la politique : un paquet précis, avec justification.
class LicenseException {
  /// PURL, préfixe de PURL ou nom de paquet.
  final String package;
  final DateTime? expires;
  final String? reason;

  const LicenseException(this.package, {this.expires, this.reason});

  bool isExpired(DateTime now) => expires != null && now.isAfter(expires!);
}

class LicenseViolationItem {
  final Package package;
  final String reason;
  const LicenseViolationItem(this.package, this.reason);
}

/// Politique de licences d'un projet : liste blanche, liste noire et
/// traitement des licences inconnues.
///
/// Format du fichier, une clé par ligne (`#` = commentaire) :
///
///     allow: MIT, Apache-2.0, BSD-*
///     deny: GPL-*, AGPL-*
///     unknown: fail                    # fail (défaut) | warn | allow
///     except: pkg:npm/foo; expires=2027-01-01; reason=Dual-licence négociée
///
/// Les motifs acceptent `*` ; la casse est ignorée. Sans `allow`, tout ce
/// qui n'est pas refusé est accepté.
class LicensePolicy {
  final List<String> allow;
  final List<String> deny;
  final String unknown;
  final List<LicenseException> exceptions;
  final List<String> warnings;

  const LicensePolicy({
    this.allow = const [],
    this.deny = const [],
    this.unknown = 'fail',
    this.exceptions = const [],
    this.warnings = const [],
  });

  factory LicensePolicy.parse(String text) {
    final allow = <String>[],
        deny = <String>[],
        exceptions = <LicenseException>[];
    final warnings = <String>[];
    var unknown = 'fail';
    var n = 0;
    for (final raw in text.split('\n')) {
      n++;
      final line = raw.split(RegExp(r'\s#')).first.trim();
      if (line.isEmpty || line.startsWith('#')) continue;
      final colon = line.indexOf(':');
      if (colon <= 0) {
        warnings.add(tr('ligne {n} ignorée (clé: valeur attendu)', {'n': n}));
        continue;
      }
      final key = line.substring(0, colon).trim().toLowerCase();
      final value = line.substring(colon + 1).trim();
      List<String> list() => value
          .split(',')
          .map((e) => e.trim())
          .where((e) => e.isNotEmpty)
          .toList();
      switch (key) {
        case 'allow':
          allow.addAll(list());
        case 'deny':
          deny.addAll(list());
        case 'unknown':
          if (const {'fail', 'warn', 'allow'}.contains(value)) {
            unknown = value;
          } else {
            warnings.add(tr(
                'ligne {n} : unknown doit valoir fail, warn ou allow',
                {'n': n}));
          }
        case 'except':
          final parts = value.split(';').map((e) => e.trim()).toList();
          DateTime? expires;
          String? reason;
          for (final p in parts.skip(1)) {
            if (p.startsWith('expires=')) {
              expires = DateTime.tryParse(p.substring(8));
              if (expires == null) {
                warnings.add(tr('ligne {n} : date illisible', {'n': n}));
              }
            } else if (p.startsWith('reason=')) {
              reason = p.substring(7);
            }
          }
          if (parts.first.isNotEmpty) {
            exceptions.add(LicenseException(parts.first,
                expires: expires, reason: reason));
          }
        default:
          warnings.add(
              tr('ligne {n} : clé inconnue « {key} »', {'n': n, 'key': key}));
      }
    }
    return LicensePolicy(
        allow: allow,
        deny: deny,
        unknown: unknown,
        exceptions: exceptions,
        warnings: warnings);
  }

  /// Violations parmi [packages] ; les exceptions non expirées les écartent.
  /// Les exceptions expirées sont signalées dans [expiredOut].
  List<LicenseViolationItem> evaluate(List<Package> packages,
      {DateTime? now, List<LicenseException>? expiredOut}) {
    final today = now ?? DateTime.now();
    final out = <LicenseViolationItem>[];
    for (final pkg in packages) {
      final reason = _check(pkg.license.trim());
      if (reason == null) continue;
      final ex = _exceptionFor(pkg);
      if (ex != null) {
        if (!ex.isExpired(today)) continue;
        expiredOut?.add(ex);
      }
      out.add(LicenseViolationItem(pkg, reason));
    }
    return out;
  }

  /// Licence absente ou `NOASSERTION` (signalée en avertissement avec `unknown: warn`).
  bool isUnknown(String license) => _isUnknown(license);

  LicenseException? _exceptionFor(Package p) {
    for (final e in exceptions) {
      if (p.purl == e.package ||
          p.purl.startsWith('${e.package}@') ||
          p.name == e.package) {
        return e;
      }
    }
    return null;
  }

  static bool _isUnknown(String l) =>
      l.isEmpty || l == 'NOASSERTION' || l == 'NONE';

  /// `null` si la licence est acceptée, sinon la raison du refus.
  String? _check(String license) {
    if (_isUnknown(license)) {
      return unknown == 'fail' ? tr('licence inconnue') : null;
    }
    return _evalExpression(_tokenize(license));
  }

  // Une expression SPDX : « A OR B » est acceptée si l'un des choix l'est,
  // « A AND B » seulement si les deux le sont. `WITH exception` est ignoré :
  // l'exception ne change pas la licence de base évaluée.
  static List<String> _tokenize(String expr) => RegExp(r'\(|\)|[^\s()]+')
      .allMatches(expr)
      .map((m) => m.group(0)!)
      .toList();

  String? _evalExpression(List<String> tokens) =>
      _ExprEval(tokens, _checkLicenseId).parseOr();

  String? _checkLicenseId(String id) {
    final bare = id.endsWith('+') ? id.substring(0, id.length - 1) : id;
    for (final d in deny) {
      if (_glob(d, id) || _glob(d, bare)) {
        return tr('licence refusée : {id}', {'id': id});
      }
    }
    if (allow.isNotEmpty && !allow.any((a) => _glob(a, id) || _glob(a, bare))) {
      return tr('licence hors liste autorisée : {id}', {'id': id});
    }
    return null;
  }

  static bool _glob(String pattern, String value) {
    final re = RegExp('^${pattern.split('*').map(RegExp.escape).join('.*')}\$',
        caseSensitive: false);
    return re.hasMatch(value);
  }
}

/// Descente récursive sur les jetons d'une expression SPDX ; [check] renvoie
/// la raison du refus d'un identifiant, ou `null` s'il est accepté.
class _ExprEval {
  final List<String> tokens;
  final String? Function(String) check;
  var pos = 0;

  _ExprEval(this.tokens, this.check);

  bool _peekIs(String word) =>
      pos < tokens.length && tokens[pos].toUpperCase() == word;

  String? parseOr() {
    var res = parseAnd();
    while (_peekIs('OR')) {
      pos++;
      final next = parseAnd();
      res = (res == null || next == null) ? null : '$res / $next';
    }
    return res;
  }

  String? parseAnd() {
    var res = parseAtom();
    while (_peekIs('AND')) {
      pos++;
      final next =
          parseAtom(); // toujours consommé, même si res est déjà refusé
      res ??= next;
    }
    return res;
  }

  String? parseAtom() {
    if (pos >= tokens.length) return null;
    final t = tokens[pos++];
    if (t == '(') {
      final r = parseOr();
      if (pos < tokens.length && tokens[pos] == ')') pos++;
      return r;
    }
    if (_peekIs('WITH')) pos += 2;
    return check(t);
  }
}
