import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import 'i18n.dart';
import 'vex.dart' show splitPackage;

// ── Sévérités ────────────────────────────────────────────────────────────────

const severityLevels = ['critical', 'high', 'medium', 'low'];

/// Rang d'une sévérité (4 = critique … 1 = faible, 0 = inconnue/négligeable).
int severityRank(String severity) => switch (severity.toLowerCase()) {
      'critical' => 4,
      'high' => 3,
      'medium' || 'moderate' => 2,
      'low' => 1,
      _ => 0,
    };

// ── Ignorer des CVE (--ignore) ───────────────────────────────────────────────

class IgnoreEntry {
  final String id;

  /// Nom de paquet (sans version) ; `null` = tous les paquets.
  final String? package;
  final DateTime? expires;
  final String? reason;
  final int line;

  const IgnoreEntry({
    required this.id,
    this.package,
    this.expires,
    this.reason,
    required this.line,
  });

  bool isExpired(DateTime now) => expires != null && now.isAfter(expires!);
}

class IgnoreList {
  final List<IgnoreEntry> entries;

  /// Problèmes de lecture (ligne invalide, date illisible, justification
  /// manquante) — à afficher en avertissement.
  final List<String> warnings;

  const IgnoreList(this.entries, this.warnings);

  /// Format, une règle par ligne (`#` = commentaire) :
  ///
  ///     CVE-2024-1234; package=openssl; expires=2026-12-31; reason=Non joignable
  ///
  /// Seul l'identifiant est obligatoire ; `expires` (AAAA-MM-JJ, inclus) et
  /// `reason` sont fortement conseillés.
  factory IgnoreList.parse(String text) {
    final entries = <IgnoreEntry>[];
    final warnings = <String>[];
    final lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
      final raw = lines[i].trim();
      if (raw.isEmpty || raw.startsWith('#')) continue;
      final parts = raw.split(';').map((p) => p.trim()).toList();
      final id = parts.first;
      if (id.isEmpty || id.contains('=') || id.contains(' ')) {
        warnings.add(tr(
            'ligne ${i + 1} ignorée (identifiant attendu en premier)',
            'line ${i + 1} skipped (identifier expected first)'));
        continue;
      }
      String? pkg, reason;
      DateTime? expires;
      for (final p in parts.skip(1)) {
        final eq = p.indexOf('=');
        if (eq < 1) continue;
        final k = p.substring(0, eq).trim().toLowerCase();
        final v = p.substring(eq + 1).trim();
        switch (k) {
          case 'package':
            pkg = v.isEmpty ? null : v;
          case 'reason':
            reason = v;
          case 'expires':
            final d = DateTime.tryParse(v);
            if (d == null) {
              warnings.add(tr(
                  'ligne ${i + 1} : date « $v » illisible (attendu AAAA-MM-JJ), règle sans expiration',
                  'line ${i + 1}: unreadable date "$v" (expected YYYY-MM-DD), rule has no expiry'));
            } else {
              // Inclusif : valable jusqu'à la fin du jour indiqué.
              expires = DateTime(d.year, d.month, d.day, 23, 59, 59);
            }
        }
      }
      if (reason == null || reason.isEmpty) {
        warnings.add(tr('ligne ${i + 1} ($id) : aucune justification (reason=)',
            'line ${i + 1} ($id): no justification (reason=)'));
      }
      entries.add(IgnoreEntry(
          id: id, package: pkg, expires: expires, reason: reason, line: i + 1));
    }
    return IgnoreList(entries, warnings);
  }

  static IgnoreList load(String path) =>
      IgnoreList.parse(File(path).readAsStringSync());

  /// Règles encore valables à la date [now].
  List<IgnoreEntry> active(DateTime now) =>
      entries.where((e) => !e.isExpired(now)).toList();

  List<IgnoreEntry> expired(DateTime now) =>
      entries.where((e) => e.isExpired(now)).toList();

  /// Règle qui écarte [vulnId] pour le paquet `nom@version`, ou `null`.
  IgnoreEntry? match(String vulnId, String package, DateTime now) {
    final (name, _) = splitPackage(package);
    for (final e in entries) {
      if (e.isExpired(now)) continue;
      if (e.id.toUpperCase() != vulnId.toUpperCase()) continue;
      if (e.package != null && e.package!.toLowerCase() != name.toLowerCase()) {
        continue;
      }
      return e;
    }
    return null;
  }
}

// ── Référence (--baseline) ───────────────────────────────────────────────────

/// Ensemble des (CVE, paquet) déjà connus, lu dans un rapport
/// `scan --format json` antérieur.
class Baseline {
  final Set<String> _keys;
  const Baseline(this._keys);

  static String key(String vulnId, String package) {
    final (name, _) = splitPackage(package);
    return '${vulnId.toUpperCase()}|${name.toLowerCase()}';
  }

  factory Baseline.fromJson(Map<String, dynamic> json) {
    final findings = json['findings'];
    if (findings is! List) {
      throw FormatException(tr(
          'référence invalide : tableau "findings" absent (produire le fichier avec `scan --format json`)',
          'invalid baseline: "findings" array missing (produce the file with `scan --format json`)'));
    }
    return Baseline({
      for (final f in findings)
        if (f is Map) key('${f['id'] ?? ''}', '${f['package'] ?? ''}'),
    });
  }

  static Baseline load(String path) => Baseline.fromJson(
      jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>);

  bool contains(String vulnId, String package) =>
      _keys.contains(key(vulnId, package));

  int get length => _keys.length;
}

// ── Cache des résultats de scanner (--cache) ─────────────────────────────────

/// Cache sur disque des résultats bruts d'un scanner, indexé par le contenu
/// du SBOM (liste triée des composants, indépendante des horodatages et UUID),
/// le scanner et sa version. Une entrée expire après [ttl] : la base de
/// vulnérabilités du scanner évolue.
class ScanCache {
  final Directory dir;
  final Duration ttl;
  ScanCache(this.dir, this.ttl);

  /// Répertoire par défaut : `$XDG_CACHE_HOME/sbom-generator/scan`
  /// (`~/.cache/sbom-generator/scan`).
  static Directory defaultDir() {
    final env = Platform.environment;
    final base = env['XDG_CACHE_HOME'] ??
        (env['HOME'] != null
            ? '${env['HOME']}/.cache'
            : Directory.systemTemp.path);
    return Directory('$base/sbom-generator/scan');
  }

  /// Empreinte du contenu d'un SBOM : composants (nom, version, purl)
  /// triés ; sans composants lisibles, empreinte des octets du fichier.
  static String sbomDigest(String sbomPath) {
    final bytes = File(sbomPath).readAsBytesSync();
    try {
      final j = jsonDecode(utf8.decode(bytes));
      if (j is Map) {
        final items = <String>[];
        void add(Object? c) {
          if (c is Map) {
            items.add(
                '${c['name']}|${c['version'] ?? c['versionInfo'] ?? c['software:packageVersion']}|${c['purl'] ?? ''}');
            for (final sub in (c['components'] as List? ?? const [])) {
              add(sub);
            }
          }
        }

        for (final c in (j['components'] as List? ?? const [])) {
          add(c);
        }
        for (final c in (j['packages'] as List? ?? const [])) {
          add(c);
        }
        for (final c in (j['@graph'] as List? ?? const [])) {
          if ('${(c as Map)['type']}'.endsWith('Package')) add(c);
        }
        if (items.isNotEmpty) {
          items.sort();
          return sha256.convert(utf8.encode(items.join('\n'))).toString();
        }
      }
    } catch (_) {}
    return sha256.convert(bytes).toString();
  }

  File _file(String digest, String scanner, String scannerVersion) {
    final k = sha256
        .convert(utf8.encode('$digest|$scanner|$scannerVersion'))
        .toString();
    return File('${dir.path}/$k.json');
  }

  List<Map<String, dynamic>>? read(
      String digest, String scanner, String scannerVersion, DateTime now) {
    try {
      final f = _file(digest, scanner, scannerVersion);
      if (!f.existsSync()) return null;
      final j = jsonDecode(f.readAsStringSync()) as Map<String, dynamic>;
      final at = DateTime.parse(j['cachedAt'] as String);
      if (now.difference(at) > ttl) return null;
      return [
        for (final v in (j['vulns'] as List))
          Map<String, dynamic>.from(v as Map),
      ];
    } catch (_) {
      return null;
    }
  }

  void write(String digest, String scanner, String scannerVersion,
      List<Map<String, dynamic>> vulns, DateTime now) {
    try {
      dir.createSync(recursive: true);
      _file(digest, scanner, scannerVersion).writeAsStringSync(jsonEncode({
        'cachedAt': now.toUtc().toIso8601String(),
        'scanner': scanner,
        'scannerVersion': scannerVersion,
        'vulns': vulns,
      }));
    } catch (_) {
      // Cache best-effort : un échec d'écriture ne doit jamais faire échouer
      // le scan.
    }
  }
}
