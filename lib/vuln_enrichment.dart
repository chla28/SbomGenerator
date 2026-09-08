/// Enrichissement des CVE avec des signaux d'exploitabilité et d'exploitation
/// active, en complément de la sévérité rapportée par les scanners :
///
/// * **CISA KEV** — la CVE est activement exploitée dans la nature ;
/// * **EPSS** (FIRST.org) — probabilité d'exploitation à 30 jours ;
/// * **PoC / exploit public** — un exploit est réellement disponible
///   (dépôts GitHub recensés par nomi-sec + maturité `E:` du vecteur CVSS) ;
/// * **exploitabilité CVSS** — sous-score d'exploitabilité (AV/AC/PR/UI) calculé
///   localement depuis le vecteur fourni par un scanner.
///
/// Ce module est le seul du paquet, avec [renderAsciiDocToPdf], à faire des
/// entrées/sorties : requêtes HTTP best-effort (toute erreur réseau est avalée
/// et l'on retombe sur un cache éventuel) et un cache disque sous
/// `~/.cache/sbom-generator/`.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Graine fournie par un scanner pour une CVE : ce qu'il sait déjà, et qui
/// évite une requête réseau (Grype expose nativement KEV + EPSS + CVSS).
class CveSeed {
  final String? cvssVector;
  final double? cvssBaseScore;
  final bool kev;
  final DateTime? kevDateAdded;
  final DateTime? kevDueDate;
  final bool kevRansomware;
  final double? epssScore;
  final double? epssPercentile;

  const CveSeed({
    this.cvssVector,
    this.cvssBaseScore,
    this.kev = false,
    this.kevDateAdded,
    this.kevDueDate,
    this.kevRansomware = false,
    this.epssScore,
    this.epssPercentile,
  });

  /// Fusionne deux graines vues pour la même CVE (scanners différents) —
  /// on garde la première valeur non nulle / non fausse.
  CveSeed merge(CveSeed other) => CveSeed(
        cvssVector: cvssVector ?? other.cvssVector,
        cvssBaseScore: cvssBaseScore ?? other.cvssBaseScore,
        kev: kev || other.kev,
        kevDateAdded: kevDateAdded ?? other.kevDateAdded,
        kevDueDate: kevDueDate ?? other.kevDueDate,
        kevRansomware: kevRansomware || other.kevRansomware,
        epssScore: epssScore ?? other.epssScore,
        epssPercentile: epssPercentile ?? other.epssPercentile,
      );
}

/// Résultat de l'enrichissement pour une CVE.
class ExploitInfo {
  final bool inKev;
  final DateTime? kevDateAdded;
  final DateTime? kevDueDate;
  final bool kevRansomware;

  /// Score EPSS 0..1 (probabilité d'exploitation à 30 jours).
  final double? epssScore;

  /// Percentile EPSS 0..1 (rang relatif parmi toutes les CVE).
  final double? epssPercentile;

  /// Un exploit / PoC public est recensé (dépôt GitHub ou maturité CVSS ≥ PoC).
  final bool pocKnown;
  final int pocCount;
  final List<String> pocUrls;

  final double? cvssBaseScore;

  /// Sous-score d'exploitabilité CVSS v3.x (0..3.9), calculé depuis le vecteur.
  final double? cvssExploitabilityScore;
  final String? cvssVector;

  /// Maturité de l'exploit (métrique temporelle `E:` du vecteur), si fournie :
  /// `High` / `Functional` / `Proof-of-Concept` / `Unproven`.
  final String? exploitMaturity;

  const ExploitInfo({
    this.inKev = false,
    this.kevDateAdded,
    this.kevDueDate,
    this.kevRansomware = false,
    this.epssScore,
    this.epssPercentile,
    this.pocKnown = false,
    this.pocCount = 0,
    this.pocUrls = const [],
    this.cvssBaseScore,
    this.cvssExploitabilityScore,
    this.cvssVector,
    this.exploitMaturity,
  });

  static const empty = ExploitInfo();

  bool get hasAnySignal =>
      inKev || pocKnown || epssScore != null || cvssExploitabilityScore != null;

  /// Clé de tri décroissante pour une priorisation par risque : KEV domine,
  /// puis EPSS, puis la sévérité, puis la présence d'un PoC. Plus c'est haut,
  /// plus c'est prioritaire.
  double riskScore(String severity) {
    var s = 0.0;
    if (inKev) s += 1000;
    if (epssScore != null) s += epssScore! * 100;
    s += switch (severity.toLowerCase()) {
      'critical' => 4,
      'high' => 3,
      'medium' => 2,
      'low' => 1,
      _ => 0,
    };
    if (pocKnown) s += 0.5;
    return s;
  }
}

/// Sous-score d'exploitabilité CVSS v3.0/v3.1 et maturité de l'exploit,
/// extraits d'un vecteur (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/...[/E:H]`).
///
/// L'exploitabilité vaut `8.22 × AV × AC × PR × UI` (arrondie au dixième) ;
/// `null` si une métrique de base manque ou si le vecteur n'est pas du CVSS
/// v3.x (v2, v4 : seule la maturité `E:` est extraite quand elle existe).
({double? exploitability, String? maturity}) parseCvssVector(String? vector) {
  if (vector == null || vector.trim().isEmpty) {
    return (exploitability: null, maturity: null);
  }
  final parts = <String, String>{};
  for (final seg in vector.split('/')) {
    final i = seg.indexOf(':');
    if (i > 0) parts[seg.substring(0, i).toUpperCase()] = seg.substring(i + 1);
  }

  final maturity = switch (parts['E']) {
    'H' => 'High',
    'F' => 'Functional',
    'P' || 'POC' => 'Proof-of-Concept',
    'U' => 'Unproven',
    'A' => 'High', // CVSS v4 : "Attacked"
    _ => null,
  };

  final version = parts['CVSS'] ?? '';
  if (!version.startsWith('3')) {
    return (exploitability: null, maturity: maturity);
  }

  final av = switch (parts['AV']) {
    'N' => 0.85,
    'A' => 0.62,
    'L' => 0.55,
    'P' => 0.2,
    _ => null,
  };
  final ac = switch (parts['AC']) {
    'L' => 0.77,
    'H' => 0.44,
    _ => null,
  };
  final ui = switch (parts['UI']) {
    'N' => 0.85,
    'R' => 0.62,
    _ => null,
  };
  final scopeChanged = parts['S'] == 'C';
  final pr = switch (parts['PR']) {
    'N' => 0.85,
    'L' => scopeChanged ? 0.68 : 0.62,
    'H' => scopeChanged ? 0.5 : 0.27,
    _ => null,
  };
  if (av == null || ac == null || ui == null || pr == null) {
    return (exploitability: null, maturity: maturity);
  }
  final raw = 8.22 * av * ac * pr * ui;
  return (
    exploitability: double.parse(raw.toStringAsFixed(1)),
    maturity: maturity,
  );
}

class _KevEntry {
  final DateTime? dateAdded;
  final DateTime? dueDate;
  final bool ransomware;
  const _KevEntry(this.dateAdded, this.dueDate, this.ransomware);
}

class _EpssEntry {
  final double? score;
  final double? percentile;
  const _EpssEntry(this.score, this.percentile);
}

class _PocEntry {
  final int count;
  final List<String> urls;
  const _PocEntry(this.count, this.urls);
}

/// Récupère et met en cache les signaux d'exploitabilité, puis les combine avec
/// ce que les scanners fournissent déjà ([CveSeed]).
class VulnEnricher {
  /// Autoriser les requêtes réseau (sinon : lecture du cache seul).
  final bool enableNetwork;

  /// Interroger la source PoC tierce (nomi-sec). Sans effet sur KEV/EPSS.
  final bool enablePoc;

  /// Délai maximal par requête réseau.
  final Duration timeout;

  /// Âge maximal d'une entrée de cache avant rafraîchissement.
  final Duration cacheTtl;

  final Directory _cacheDir;
  final Uri _kevFeedUrl;
  final Uri _epssApiUrl;
  final Uri _pocApiBase;
  final HttpClient Function() _clientFactory;

  VulnEnricher({
    this.enableNetwork = true,
    this.enablePoc = true,
    this.timeout = const Duration(seconds: 8),
    this.cacheTtl = const Duration(hours: 24),
    Directory? cacheDir,
    Uri? kevFeedUrl,
    Uri? epssApiUrl,
    Uri? pocApiBase,
    HttpClient Function()? httpClientFactory,
  })  : _cacheDir = cacheDir ?? _defaultCacheDir(),
        _kevFeedUrl = kevFeedUrl ??
            Uri.parse('https://www.cisa.gov/sites/default/files/feeds/'
                'known_exploited_vulnerabilities.json'),
        _epssApiUrl =
            epssApiUrl ?? Uri.parse('https://api.first.org/data/v1/epss'),
        _pocApiBase = pocApiBase ??
            Uri.parse('https://poc-in-github.motikan2010.net/api/v1/'),
        _clientFactory = httpClientFactory ?? HttpClient.new;

  static Directory _defaultCacheDir() {
    final env = Platform.environment;
    final base = env['XDG_CACHE_HOME'] ??
        (env['HOME'] != null ? '${env['HOME']}/.cache' : null) ??
        Directory.systemTemp.path;
    return Directory('$base/sbom-generator');
  }

  /// Enrichit chaque CVE de [cveIds]. [seed] apporte ce que les scanners
  /// savent déjà (clé = identifiant normalisé, cf. `_normalizeId`).
  Future<Map<String, ExploitInfo>> enrich(
    Set<String> cveIds, {
    Map<String, CveSeed> seed = const {},
  }) async {
    final cves =
        cveIds.where((c) => c.toUpperCase().startsWith('CVE-')).toSet();

    Map<String, _KevEntry> kev = const {};
    Map<String, _EpssEntry> epss = const {};
    Map<String, _PocEntry> poc = const {};

    if (enableNetwork) {
      kev = await _loadKev();
      epss = await _loadEpss(cves);
      if (enablePoc) poc = await _loadPoc(cves);
    } else {
      kev = await _readKevCache() ?? const {};
      epss = _pick(await _readEpssCache(), cves);
      if (enablePoc) poc = _pick(await _readPocCache(), cves);
    }

    final out = <String, ExploitInfo>{};
    for (final id in cveIds) {
      final sd = seed[id] ?? const CveSeed();
      final k = kev[id];
      final e = epss[id];
      final p = poc[id];
      final parsed = parseCvssVector(sd.cvssVector);

      final inKev = k != null || sd.kev;
      final maturity = parsed.maturity;
      final pocFromMaturity = maturity == 'High' ||
          maturity == 'Functional' ||
          maturity == 'Proof-of-Concept';

      out[id] = ExploitInfo(
        inKev: inKev,
        kevDateAdded: k?.dateAdded ?? sd.kevDateAdded,
        kevDueDate: k?.dueDate ?? sd.kevDueDate,
        kevRansomware: (k?.ransomware ?? false) || sd.kevRansomware,
        epssScore: e?.score ?? sd.epssScore,
        epssPercentile: e?.percentile ?? sd.epssPercentile,
        pocKnown: (p?.count ?? 0) > 0 || pocFromMaturity,
        pocCount: p?.count ?? 0,
        pocUrls: p?.urls ?? const [],
        cvssBaseScore: sd.cvssBaseScore,
        cvssExploitabilityScore: parsed.exploitability,
        cvssVector: sd.cvssVector,
        exploitMaturity: maturity,
      );
    }
    return out;
  }

  static Map<String, T> _pick<T>(Map<String, T>? all, Set<String> ids) {
    if (all == null) return {};
    return {
      for (final id in ids)
        if (all.containsKey(id)) id: all[id] as T,
    };
  }

  // ── HTTP ────────────────────────────────────────────────────────────────

  Future<String?> _get(Uri url) async {
    final client = _clientFactory();
    try {
      client.connectionTimeout = timeout;
      final req = await client.getUrl(url).timeout(timeout);
      req.headers.set(HttpHeaders.userAgentHeader, 'sbom-generator');
      req.headers.set(HttpHeaders.acceptHeader, 'application/json');
      final resp = await req.close().timeout(timeout);
      if (resp.statusCode != 200) {
        await resp.drain<void>();
        return null;
      }
      return await resp.transform(utf8.decoder).join().timeout(timeout);
    } catch (_) {
      return null;
    } finally {
      client.close(force: true);
    }
  }

  // ── CISA KEV ────────────────────────────────────────────────────────────

  File get _kevCacheFile => File('${_cacheDir.path}/kev.json');
  File get _epssCacheFile => File('${_cacheDir.path}/epss.json');
  File get _pocCacheFile => File('${_cacheDir.path}/poc.json');

  Future<Map<String, _KevEntry>> _loadKev() async {
    final cached = await _readRawCache(_kevCacheFile);
    if (cached != null && _fresh(cached['fetchedAt'] as String?)) {
      return _parseKevCache(cached);
    }
    final body = await _get(_kevFeedUrl);
    if (body == null) {
      // Réseau indisponible : cache périmé s'il existe, sinon rien.
      return cached != null ? _parseKevCache(cached) : const {};
    }
    try {
      final data = jsonDecode(body) as Map<String, dynamic>;
      final vulns = (data['vulnerabilities'] as List?) ?? const [];
      final entries = <String, Map<String, dynamic>>{};
      for (final v in vulns) {
        final m = v as Map<String, dynamic>;
        final id = (m['cveID'] as String?)?.toUpperCase();
        if (id == null || id.isEmpty) continue;
        entries[id] = {
          'dateAdded': m['dateAdded'],
          'dueDate': m['dueDate'],
          'ransomware': ((m['knownRansomwareCampaignUse'] as String?) ?? '')
                  .toLowerCase() ==
              'known',
        };
      }
      await _writeRawCache(_kevCacheFile, {
        'fetchedAt': DateTime.now().toUtc().toIso8601String(),
        'cves': entries,
      });
      return {
        for (final e in entries.entries)
          e.key: _KevEntry(
            _tryDate(e.value['dateAdded'] as String?),
            _tryDate(e.value['dueDate'] as String?),
            e.value['ransomware'] as bool? ?? false,
          ),
      };
    } catch (_) {
      return cached != null ? _parseKevCache(cached) : const {};
    }
  }

  Future<Map<String, _KevEntry>?> _readKevCache() async {
    final cached = await _readRawCache(_kevCacheFile);
    return cached == null ? null : _parseKevCache(cached);
  }

  Map<String, _KevEntry> _parseKevCache(Map<String, dynamic> cached) {
    final cves = (cached['cves'] as Map?)?.cast<String, dynamic>() ?? const {};
    return {
      for (final e in cves.entries)
        e.key: _KevEntry(
          _tryDate((e.value as Map)['dateAdded'] as String?),
          _tryDate((e.value as Map)['dueDate'] as String?),
          (e.value as Map)['ransomware'] as bool? ?? false,
        ),
    };
  }

  // ── EPSS (FIRST.org) ────────────────────────────────────────────────────

  Future<Map<String, _EpssEntry>> _loadEpss(Set<String> ids) async {
    if (ids.isEmpty) return const {};
    final cache = await _readEpssRawCache() ?? {};
    final result = <String, _EpssEntry>{};
    final missing = <String>[];

    for (final id in ids) {
      final c = cache[id];
      if (c != null && _fresh(c['fetchedAt'] as String?)) {
        result[id] = _EpssEntry(
          (c['score'] as num?)?.toDouble(),
          (c['percentile'] as num?)?.toDouble(),
        );
      } else {
        missing.add(id);
      }
    }
    if (missing.isEmpty) return result;

    final now = DateTime.now().toUtc().toIso8601String();
    var networkFailed = false;
    for (var i = 0; i < missing.length; i += 100) {
      final batch = missing.sublist(i, (i + 100).clamp(0, missing.length));
      final url = _epssApiUrl.replace(queryParameters: {
        'cve': batch.join(','),
        'limit': '100',
      });
      final body = await _get(url);
      if (body == null) {
        networkFailed = true;
        continue;
      }
      try {
        final data = jsonDecode(body) as Map<String, dynamic>;
        for (final row in (data['data'] as List? ?? const [])) {
          final m = row as Map<String, dynamic>;
          final id = (m['cve'] as String?)?.toUpperCase();
          if (id == null) continue;
          final score = double.tryParse('${m['epss']}');
          final pct = double.tryParse('${m['percentile']}');
          result[id] = _EpssEntry(score, pct);
          cache[id] = {
            'score': score,
            'percentile': pct,
            'fetchedAt': now,
          };
        }
      } catch (_) {
        networkFailed = true;
      }
    }
    // Repli sur le cache périmé pour ce qui n'a pas pu être rafraîchi.
    if (networkFailed) {
      for (final id in missing) {
        if (result.containsKey(id)) continue;
        final c = cache[id];
        if (c != null) {
          result[id] = _EpssEntry(
            (c['score'] as num?)?.toDouble(),
            (c['percentile'] as num?)?.toDouble(),
          );
        }
      }
    }
    await _writeRawCache(_epssCacheFile, cache);
    return result;
  }

  Future<Map<String, _EpssEntry>?> _readEpssCache() async {
    final cache = await _readEpssRawCache();
    if (cache == null) return null;
    return {
      for (final e in cache.entries)
        e.key: _EpssEntry(
          (e.value['score'] as num?)?.toDouble(),
          (e.value['percentile'] as num?)?.toDouble(),
        ),
    };
  }

  Future<Map<String, Map<String, dynamic>>?> _readEpssRawCache() async {
    final raw = await _readRawCache(_epssCacheFile);
    return raw?.map((k, v) => MapEntry(k, (v as Map).cast<String, dynamic>()));
  }

  // ── PoC public (nomi-sec poc-in-github) ─────────────────────────────────

  Future<Map<String, _PocEntry>> _loadPoc(Set<String> ids) async {
    if (ids.isEmpty) return const {};
    final cache = await _readPocRawCache() ?? {};
    final result = <String, _PocEntry>{};
    final missing = <String>[];

    for (final id in ids) {
      final c = cache[id];
      if (c != null && _fresh(c['fetchedAt'] as String?)) {
        result[id] = _PocEntry(
          (c['count'] as num?)?.toInt() ?? 0,
          ((c['urls'] as List?) ?? const []).cast<String>(),
        );
      } else {
        missing.add(id);
      }
    }
    if (missing.isEmpty) return result;

    final now = DateTime.now().toUtc().toIso8601String();
    // Petit pool de concurrence : la source répond une CVE à la fois.
    const poolSize = 6;
    for (var i = 0; i < missing.length; i += poolSize) {
      final slice = missing.sublist(i, (i + poolSize).clamp(0, missing.length));
      await Future.wait(slice.map((id) async {
        final url = _pocApiBase.replace(queryParameters: {'cve_id': id});
        final body = await _get(url);
        if (body == null) return;
        try {
          final data = jsonDecode(body) as Map<String, dynamic>;
          final pocs = (data['pocs'] as List?) ?? const [];
          final urls = <String>[
            for (final p in pocs)
              if ((p as Map)['html_url'] is String) p['html_url'] as String,
          ];
          result[id] = _PocEntry(pocs.length, urls.take(3).toList());
          cache[id] = {
            'count': pocs.length,
            'urls': urls.take(3).toList(),
            'fetchedAt': now,
          };
        } catch (_) {}
      }));
    }
    // Repli cache périmé.
    for (final id in missing) {
      if (result.containsKey(id)) continue;
      final c = cache[id];
      if (c != null) {
        result[id] = _PocEntry(
          (c['count'] as num?)?.toInt() ?? 0,
          ((c['urls'] as List?) ?? const []).cast<String>(),
        );
      }
    }
    await _writeRawCache(_pocCacheFile, cache);
    return result;
  }

  Future<Map<String, _PocEntry>?> _readPocCache() async {
    final cache = await _readPocRawCache();
    if (cache == null) return null;
    return {
      for (final e in cache.entries)
        e.key: _PocEntry(
          (e.value['count'] as num?)?.toInt() ?? 0,
          ((e.value['urls'] as List?) ?? const []).cast<String>(),
        ),
    };
  }

  Future<Map<String, Map<String, dynamic>>?> _readPocRawCache() async {
    final raw = await _readRawCache(_pocCacheFile);
    return raw?.map((k, v) => MapEntry(k, (v as Map).cast<String, dynamic>()));
  }

  // ── Cache disque ────────────────────────────────────────────────────────

  Future<Map<String, dynamic>?> _readRawCache(File f) async {
    try {
      if (!await f.exists()) return null;
      return jsonDecode(await f.readAsString()) as Map<String, dynamic>;
    } catch (_) {
      return null;
    }
  }

  Future<void> _writeRawCache(File f, Map<String, dynamic> data) async {
    try {
      await _cacheDir.create(recursive: true);
      await f.writeAsString(jsonEncode(data));
    } catch (_) {
      // Cache best-effort : un échec d'écriture ne doit pas casser le scan.
    }
  }

  bool _fresh(String? iso) {
    final t = _tryDate(iso);
    if (t == null) return false;
    return DateTime.now().toUtc().difference(t.toUtc()) < cacheTtl;
  }

  static DateTime? _tryDate(String? s) {
    if (s == null || s.isEmpty) return null;
    try {
      return DateTime.parse(s);
    } catch (_) {
      return null;
    }
  }
}
