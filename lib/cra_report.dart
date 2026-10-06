/// Rapport de conformité *Cyber Resilience Act* (Règlement (UE) 2024/2847).
///
/// Portée délibérément limitée : ce générateur ne couvre que les éléments
/// **vérifiables automatiquement** à partir d'un SBOM et d'une analyse de
/// vulnérabilités connues —
///
/// * qualité et complétude du SBOM (Annexe I §2 point 1 ; BSI TR-03183-2 ;
///   éléments minimaux NTIA 2021) ;
/// * inventaire des vulnérabilités connues et disponibilité des correctifs
///   (Annexe I §2 points 1-2) ;
/// * vulnérabilités activement exploitées → déclencheur de notification à
///   l'ENISA / au CSIRT coordinateur sous 24 h (art. 14).
///
/// Les autres exigences du CRA (mécanisme de mise à jour sécurisé, politique
/// de divulgation coordonnée *effective*, secure-by-default, tests réguliers,
/// notifications réglementaires…) relèvent du fabricant et sont seulement
/// listées, non évaluées.
library;

import 'dart:convert';

import 'sbom_reader.dart';
import 'vuln_enrichment.dart';
import 'i18n.dart';

// `cra` réutilise le rendu PDF partagé de `scan_report_generator.dart`.
export 'scan_report_generator.dart' show renderAsciiDocToPdf;

/// Métadonnées fabricant / produit d'un rapport CRA (fichier `cra.yaml`,
/// options CLI, ou déduites du SBOM).
class CraMetadata {
  final String? manufacturer;
  final String? product;
  final String? productVersion;

  /// Date de fin de support (ISO `AAAA-MM-JJ`) — CRA art. 13 §8.
  final String? supportUntil;

  /// Adresse (e-mail ou URL) de signalement des vulnérabilités — Annexe I
  /// §2 point 6.
  final String? vulnerabilityContact;

  /// URL de la politique de divulgation coordonnée — Annexe I §2 point 5.
  final String? cvdPolicyUrl;

  const CraMetadata({
    this.manufacturer,
    this.product,
    this.productVersion,
    this.supportUntil,
    this.vulnerabilityContact,
    this.cvdPolicyUrl,
  });

  /// Fusionne : `this` prioritaire, `other` en complément (les valeurs nulles
  /// ou vides de `this` sont remplacées).
  CraMetadata merge(CraMetadata other) {
    String? pick(String? a, String? b) =>
        (a != null && a.trim().isNotEmpty) ? a : b;
    return CraMetadata(
      manufacturer: pick(manufacturer, other.manufacturer),
      product: pick(product, other.product),
      productVersion: pick(productVersion, other.productVersion),
      supportUntil: pick(supportUntil, other.supportUntil),
      vulnerabilityContact:
          pick(vulnerabilityContact, other.vulnerabilityContact),
      cvdPolicyUrl: pick(cvdPolicyUrl, other.cvdPolicyUrl),
    );
  }

  /// Parse un `cra.yaml` plat (`clé: valeur` par ligne, `#` = commentaire) —
  /// pas de dépendance `yaml`, la structure est volontairement à plat.
  static CraMetadata parseConfig(String text) {
    final m = <String, String>{};
    for (var line in text.split('\n')) {
      final hash = line.indexOf('#');
      if (hash >= 0) line = line.substring(0, hash);
      final i = line.indexOf(':');
      if (i <= 0) continue;
      final key = line.substring(0, i).trim().toLowerCase();
      var val = line.substring(i + 1).trim();
      if (val.length >= 2 &&
          ((val.startsWith('"') && val.endsWith('"')) ||
              (val.startsWith("'") && val.endsWith("'")))) {
        val = val.substring(1, val.length - 1);
      }
      if (val.isNotEmpty) m[key] = val;
    }
    return CraMetadata(
      manufacturer: m['manufacturer'] ?? m['fabricant'],
      product: m['product'] ?? m['produit'],
      productVersion: m['product_version'] ?? m['version'],
      supportUntil: m['support_until'] ?? m['fin_de_support'],
      vulnerabilityContact: m['vulnerability_contact'] ??
          m['contact'] ??
          m['contact_vulnerabilites'],
      cvdPolicyUrl: m['cvd_policy_url'] ?? m['politique_cvd'],
    );
  }
}

/// Statut d'une exigence : conforme, partiel, non conforme, non évalué.
enum CraStatus { ok, partial, fail, na }

extension _CraStatusX on CraStatus {
  String get badge => switch (this) {
        CraStatus.ok =>
          tr('[.verdict-ok]*Conforme*', '[.verdict-ok]*Compliant*'),
        CraStatus.partial =>
          tr('[.verdict-watch]*Partiel*', '[.verdict-watch]*Partial*'),
        CraStatus.fail => tr('[.verdict-urgent]*Non conforme*',
            '[.verdict-urgent]*Non-compliant*'),
        CraStatus.na => tr('[.muted]_Non évalué_', '[.muted]_Not assessed_'),
      };
  String get json => name;
}

/// Résultat de la vérification d'un champ SBOM donné.
class _FieldCheck {
  /// Identifiant stable (indépendant de la langue) ; [label] est traduit.
  final String id;
  final String label;
  final bool mandatory;
  final int covered;
  final int total;
  final List<String> offenders; // composants sans le champ (tronqué)

  _FieldCheck(this.id, this.label, this.mandatory, this.covered, this.total,
      this.offenders);

  double get ratio => total == 0 ? 0 : covered / total;
  CraStatus get status {
    if (total == 0) return CraStatus.na;
    if (covered == total) return CraStatus.ok;
    if (!mandatory) return CraStatus.partial;
    return ratio >= 0.9 ? CraStatus.partial : CraStatus.fail;
  }

  String get coverage =>
      total == 0 ? '—' : '$covered / $total (${(ratio * 100).round()} %)';
}

class CraReportGenerator {
  final String sbomPath;
  final Map<String, dynamic> sbom;
  final CraMetadata meta;

  /// Résultats de scan par outil (même forme que `sbom_generator scan`), ou
  /// `null` si l'analyse de vulnérabilités n'a pas été lancée.
  final Map<String, List<Map<String, dynamic>>>? scanResults;
  final Map<String, ExploitInfo> exploitById;
  final Map<String, String?> toolVersions;

  /// Sortie brute de `sbomqs score` (facultatif) — reprise telle quelle.
  final String? sbomqsOutput;

  final DateTime generatedAt;

  CraReportGenerator({
    required this.sbomPath,
    required this.sbom,
    required this.meta,
    this.scanResults,
    this.exploitById = const {},
    this.toolVersions = const {},
    this.sbomqsOutput,
    DateTime? generatedAt,
  }) : generatedAt = generatedAt ?? DateTime.now();

  static final RegExp _distroCveRe = RegExp(r'^[A-Z]+-(CVE-\d{4}-\d+)$');
  static String _normId(String id) =>
      _distroCveRe.firstMatch(id)?.group(1) ?? id;

  SbomFormat get _format => SbomReader.detectFormat(sbom);

  String get _formatLabel {
    switch (_format) {
      case SbomFormat.cyclonedx:
        return 'CycloneDX ${sbom['specVersion'] ?? '?'}';
      case SbomFormat.spdx2:
        return '${sbom['spdxVersion'] ?? 'SPDX'}';
      case SbomFormat.spdx3:
        return 'SPDX 3.0 (JSON-LD)';
      case SbomFormat.unknown:
        return 'inconnu';
    }
  }

  /// Format « d'usage courant, lisible par machine » (Annexe I §2 point 1).
  bool get _machineReadable => _format != SbomFormat.unknown;

  // ── Composants ──────────────────────────────────────────────────────────

  /// Liste des composants (hors composant racine) sous forme de maps brutes.
  List<Map<String, dynamic>> get _components {
    switch (_format) {
      case SbomFormat.cyclonedx:
        return ((sbom['components'] as List?) ?? const [])
            .whereType<Map>()
            .map((e) => e.cast<String, dynamic>())
            .toList();
      case SbomFormat.spdx2:
        final rootId = _spdxRootId;
        return ((sbom['packages'] as List?) ?? const [])
            .whereType<Map>()
            .map((e) => e.cast<String, dynamic>())
            .where((p) => p['SPDXID'] != rootId)
            .toList();
      case SbomFormat.spdx3:
        return _spdx3Nodes
            .where((n) => '${n['type']}'.endsWith('Package'))
            .toList();
      case SbomFormat.unknown:
        return const [];
    }
  }

  /// Nœuds du graphe JSON-LD d'un SBOM SPDX 3.0.
  List<Map<String, dynamic>> get _spdx3Nodes =>
      ((sbom['@graph'] as List?) ?? const [])
          .whereType<Map>()
          .map((e) => e.cast<String, dynamic>())
          .toList();

  Iterable<Map<String, dynamic>> _spdx3Of(String type) =>
      _spdx3Nodes.where((n) => n['type'] == type);

  String? get _spdxRootId {
    final describes = (sbom['documentDescribes'] as List?)?.cast<String>();
    if (describes != null && describes.isNotEmpty) return describes.first;
    for (final r in ((sbom['relationships'] as List?) ?? const [])) {
      if ((r as Map)['relationshipType'] == 'DESCRIBES') {
        return r['relatedSpdxElement'] as String?;
      }
    }
    return null;
  }

  int get _dependencyRelations {
    switch (_format) {
      case SbomFormat.cyclonedx:
        return ((sbom['dependencies'] as List?) ?? const [])
            .whereType<Map>()
            .where((d) => ((d['dependsOn'] as List?) ?? const []).isNotEmpty)
            .length;
      case SbomFormat.spdx2:
        return ((sbom['relationships'] as List?) ?? const [])
            .whereType<Map>()
            .where((r) =>
                (r['relationshipType'] as String?)?.contains('DEPENDS') ??
                false)
            .length;
      case SbomFormat.spdx3:
        return _spdx3Of('Relationship')
            .where(
                (r) => '${r['relationshipType']}'.toLowerCase() == 'dependson')
            .length;
      case SbomFormat.unknown:
        return 0;
    }
  }

  // ── A. Champs de données par composant (BSI TR-03183-2 / NTIA) ──────────

  List<_FieldCheck> get fieldChecks {
    final comps = _components;
    final total = comps.length;
    if (total == 0) return const [];

    final cdx = _format == SbomFormat.cyclonedx;
    final s3 = _format == SbomFormat.spdx3;

    bool hasSupplier(Map<String, dynamic> c) => s3
        ? _nonEmpty(c['suppliedBy'])
        : cdx
            ? _nonEmpty(c['supplier']) ||
                _nonEmpty(c['publisher']) ||
                _nonEmpty(c['author'])
            : _nonEmptyStr(c['supplier']) &&
                c['supplier'] != 'NOASSERTION' &&
                c['supplier'] != 'NONE';
    bool hasName(Map<String, dynamic> c) => _nonEmptyStr(c['name']);
    bool hasVersion(Map<String, dynamic> c) => s3
        ? _nonEmptyStr(c['software:packageVersion'])
        : cdx
            ? _nonEmptyStr(c['version'])
            : _nonEmptyStr(c['versionInfo']);
    bool hasId(Map<String, dynamic> c) {
      if (s3) {
        return ((c['externalIdentifier'] as List?) ?? const []).any((r) {
          final t = '${(r as Map)['externalIdentifierType']}';
          return t == 'purl' || t.contains('cpe');
        });
      }
      if (cdx) return _nonEmptyStr(c['purl']) || _nonEmptyStr(c['cpe']);
      final refs = (c['externalRefs'] as List?) ?? const [];
      return refs.any((r) =>
          (r as Map)['referenceType'] == 'purl' ||
          '${r['referenceType']}'.contains('cpe'));
    }

    bool hasHash(Map<String, dynamic> c) => s3
        ? ((c['verifiedUsing'] as List?) ?? const []).isNotEmpty
        : cdx
            ? ((c['hashes'] as List?) ?? const []).isNotEmpty
            : ((c['checksums'] as List?) ?? const []).isNotEmpty;
    bool hasLicense(Map<String, dynamic> c) {
      if (s3) {
        bool ok(Object? v) =>
            v != null &&
            !(v is String &&
                (v.trim().isEmpty ||
                    v.endsWith('NoAssertion') ||
                    v.endsWith('NoneLicense') ||
                    v == 'NOASSERTION' ||
                    v == 'NONE')) &&
            !(v is Map && v.isEmpty);
        return ok(c['concludedLicense']) || ok(c['declaredLicense']);
      }
      if (cdx) return ((c['licenses'] as List?) ?? const []).isNotEmpty;
      final lc = c['licenseConcluded'], ld = c['licenseDeclared'];
      bool ok(v) => _nonEmptyStr(v) && v != 'NOASSERTION' && v != 'NONE';
      return ok(lc) || ok(ld);
    }

    final verKey = s3
        ? 'software:packageVersion'
        : cdx
            ? 'version'
            : 'versionInfo';
    String nameOf(Map<String, dynamic> c) =>
        '${c['name'] ?? c['SPDXID'] ?? c['spdxId'] ?? '?'}'
        '${_nonEmptyStr(c[verKey]) ? '@${c[verKey]}' : ''}';

    _FieldCheck check(String id, String label, bool mandatory,
        bool Function(Map<String, dynamic>) pred) {
      var covered = 0;
      final offenders = <String>[];
      for (final c in comps) {
        if (pred(c)) {
          covered++;
        } else if (offenders.length < 15) {
          offenders.add(nameOf(c));
        }
      }
      return _FieldCheck(id, label, mandatory, covered, total, offenders);
    }

    return [
      check('name', tr('Nom du composant', 'Component name'), true, hasName),
      check('version', 'Version', true, hasVersion),
      check('supplier', tr('Fournisseur / créateur', 'Supplier / creator'),
          true, hasSupplier),
      check(
          'identifier',
          tr('Identifiant unique (PURL / CPE)',
              'Unique identifier (PURL / CPE)'),
          true,
          hasId),
      check(
          'hash',
          tr('Empreinte cryptographique (hash)', 'Cryptographic hash'),
          true,
          hasHash),
      check('license', tr('Licence', 'License'), true, hasLicense),
    ];
  }

  /// Relations de dépendance présentes (Annexe I §2 point 1 : « au moins les
  /// dépendances de premier niveau »).
  CraStatus get dependencyStatus =>
      _dependencyRelations > 0 ? CraStatus.ok : CraStatus.fail;

  // ── C. Métadonnées de document / éléments minimaux NTIA ─────────────────

  bool get _hasAuthor {
    switch (_format) {
      case SbomFormat.cyclonedx:
        final md = (sbom['metadata'] as Map?) ?? const {};
        return ((md['authors'] as List?) ?? const []).isNotEmpty ||
            ((md['tools'] as Map?)?['components'] as List?)?.isNotEmpty ==
                true ||
            ((md['tools'] as List?) ?? const []).isNotEmpty;
      case SbomFormat.spdx2:
        return ((sbom['creationInfo'] as Map?)?['creators'] as List?)
                ?.isNotEmpty ==
            true;
      case SbomFormat.spdx3:
        return _spdx3Of('CreationInfo')
            .any((ci) => ((ci['createdBy'] as List?) ?? const []).isNotEmpty);
      case SbomFormat.unknown:
        return false;
    }
  }

  String? get _timestamp {
    switch (_format) {
      case SbomFormat.cyclonedx:
        return (sbom['metadata'] as Map?)?['timestamp'] as String?;
      case SbomFormat.spdx2:
        return (sbom['creationInfo'] as Map?)?['created'] as String?;
      case SbomFormat.spdx3:
        for (final ci in _spdx3Of('CreationInfo')) {
          if (ci['created'] is String) return ci['created'] as String;
        }
        return null;
      case SbomFormat.unknown:
        return null;
    }
  }

  bool get _hasPrimaryComponent {
    switch (_format) {
      case SbomFormat.cyclonedx:
        return _nonEmpty((sbom['metadata'] as Map?)?['component']);
      case SbomFormat.spdx2:
        return _spdxRootId != null;
      case SbomFormat.spdx3:
        return _spdx3Of('SpdxDocument')
            .any((d) => ((d['rootElement'] as List?) ?? const []).isNotEmpty);
      case SbomFormat.unknown:
        return false;
    }
  }

  /// Les 7 éléments minimaux NTIA (2021) : (libellé, statut).
  List<(String, CraStatus)> get ntiaElements =>
      [for (final (_, label, st) in _ntia) (label, st)];

  /// Idem, avec l'identifiant stable (utilisé comme clé dans le JSON).
  List<(String, String, CraStatus)> get _ntia {
    final fc = {for (final c in fieldChecks) c.id: c};
    CraStatus f(String id) => fc[id]?.status ?? CraStatus.na;
    return [
      (
        'supplierName',
        tr('Nom du fournisseur', 'Supplier name'),
        f('supplier')
      ),
      ('componentName', tr('Nom du composant', 'Component name'), f('name')),
      (
        'componentVersion',
        tr('Version du composant', 'Component version'),
        f('version')
      ),
      (
        'otherUniqueIdentifiers',
        tr('Autres identifiants uniques', 'Other unique identifiers'),
        f('identifier')
      ),
      (
        'dependencyRelationship',
        tr('Relation de dépendance', 'Dependency relationship'),
        dependencyStatus
      ),
      (
        'sbomAuthor',
        tr('Auteur des données SBOM', 'Author of SBOM data'),
        _hasAuthor ? CraStatus.ok : CraStatus.fail
      ),
      (
        'timestamp',
        tr('Horodatage', 'Timestamp'),
        _timestamp != null ? CraStatus.ok : CraStatus.fail
      ),
    ];
  }

  // ── B. Gestion des vulnérabilités ──────────────────────────────────────

  bool get scanRun => scanResults != null && scanResults!.isNotEmpty;

  /// CVE dédupliquées : id normalisé → (pire sévérité, correctif dispo).
  Map<String, ({String severity, bool hasFix})> get _cves {
    final out = <String, ({String severity, bool hasFix})>{};
    for (final findings in (scanResults ?? const {}).values) {
      for (final v in findings) {
        final id = _normId((v['id'] as String?) ?? '');
        if (id.isEmpty) continue;
        final sev = (v['severity'] as String?) ?? 'Unknown';
        final fixState = ((v['fixState'] as String?) ?? '').toLowerCase();
        final fixVers = (v['fixedVersions'] as List?) ?? const [];
        final hasFix = fixState == 'fixed' || fixVers.isNotEmpty;
        final cur = out[id];
        out[id] = (
          severity: cur == null || _sevOrd(sev) < _sevOrd(cur.severity)
              ? sev
              : cur.severity,
          hasFix: (cur?.hasFix ?? false) || hasFix,
        );
      }
    }
    return out;
  }

  static int _sevOrd(String s) => switch (s.toLowerCase()) {
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        'low' => 3,
        _ => 4,
      };

  int get totalCves => _cves.length;
  int sevCount(String level) =>
      _cves.values.where((c) => c.severity.toLowerCase() == level).length;

  /// CVE sans correctif disponible (Annexe I §2 point 2 : à adresser sans délai).
  List<String> get cvesWithoutFix =>
      (_cves.entries.where((e) => !e.value.hasFix).map((e) => e.key).toList()
        ..sort());

  ExploitInfo _ex(String id) => exploitById[id] ?? ExploitInfo.empty;

  /// CVE activement exploitées (CISA KEV) → déclencheur art. 14.
  List<String> get kevCves =>
      (_cves.keys.where((id) => _ex(id).inKev).toList()..sort());

  // ── Verdict ─────────────────────────────────────────────────────────────

  List<String> get blockers {
    final b = <String>[];
    if (!_machineReadable) {
      b.add(tr(
          'Le SBOM n\'est pas dans un format d\'usage courant lisible par '
              'machine (Annexe I §2 point 1).',
          'The SBOM is not in a commonly used machine-readable format '
              '(Annex I §2 point 1).'));
    }
    if (dependencyStatus == CraStatus.fail) {
      b.add(tr(
          'Le SBOM ne décrit aucune relation de dépendance (Annexe I §2 '
              'point 1 : au moins les dépendances de premier niveau).',
          'The SBOM describes no dependency relationship (Annex I §2 '
              'point 1: at least the first-level dependencies).'));
    }
    for (final c in fieldChecks) {
      if (c.status == CraStatus.fail) {
        b.add(tr(
            'Champ SBOM obligatoire insuffisamment renseigné : '
                '${c.label} (${c.coverage}).',
            'Mandatory SBOM field insufficiently filled in: '
                '${c.label} (${c.coverage}).'));
      }
    }
    if (scanRun && cvesWithoutFix.isNotEmpty) {
      b.add(tr(
          '${cvesWithoutFix.length} vulnérabilité(s) connue(s) sans '
              'correctif disponible (Annexe I §2 point 2).',
          '${cvesWithoutFix.length} known vulnerability(ies) without an '
              'available fix (Annex I §2 point 2).'));
    }
    if (scanRun && kevCves.isNotEmpty) {
      b.add(tr(
          '${kevCves.length} vulnérabilité(s) activement exploitée(s) — '
              'notification à l\'ENISA / au CSIRT coordinateur requise sous 24 h '
              '(art. 14).',
          '${kevCves.length} actively exploited vulnerability(ies) — '
              'notification to ENISA / the coordinating CSIRT required within 24 h '
              '(art. 14).'));
    }
    return b;
  }

  CraStatus get verdict {
    if (blockers.isNotEmpty) return CraStatus.fail;
    final anyPartial =
        fieldChecks.any((c) => c.status == CraStatus.partial) || (!scanRun);
    return anyPartial ? CraStatus.partial : CraStatus.ok;
  }

  String get verdictSentence => switch (verdict) {
        CraStatus.ok => tr(
            'Conforme sur le périmètre vérifié automatiquement (SBOM et '
                'vulnérabilités connues).',
            'Compliant within the automatically verified scope (SBOM and '
                'known vulnerabilities).'),
        CraStatus.partial => tr(
            'Conforme avec réserves sur le périmètre vérifié : des champs SBOM '
                'sont incomplets ou l\'analyse de vulnérabilités n\'a pas été '
                'exécutée.',
            'Compliant with reservations within the verified scope: some SBOM '
                'fields are incomplete or the vulnerability scan was not '
                'run.'),
        CraStatus.fail => tr(
            'Non conforme sur le périmètre vérifié : ${blockers.length} point(s) '
                'bloquant(s) — voir la conclusion.',
            'Non-compliant within the verified scope: ${blockers.length} '
                'blocking item(s) — see the conclusion.'),
        CraStatus.na => tr('Non évalué.', 'Not assessed.'),
      };

  // ── Helpers ─────────────────────────────────────────────────────────────

  static bool _nonEmptyStr(Object? v) => v is String && v.trim().isNotEmpty;
  static bool _nonEmpty(Object? v) {
    if (v == null) return false;
    if (v is String) return v.trim().isNotEmpty;
    if (v is Map) return v.isNotEmpty;
    if (v is List) return v.isNotEmpty;
    return true;
  }

  static String _esc(String s) => s.replaceAll('|', r'\|');
  String _frDate() {
    if (currentLang == Lang.en) {
      const en = [
        'January',
        'February',
        'March',
        'April',
        'May',
        'June',
        'July',
        'August',
        'September',
        'October',
        'November',
        'December'
      ];
      final d = generatedAt;
      return '${d.day} ${en[d.month - 1]} ${d.year}';
    }
    const m = [
      'janvier',
      'février',
      'mars',
      'avril',
      'mai',
      'juin',
      'juillet',
      'août',
      'septembre',
      'octobre',
      'novembre',
      'décembre'
    ];
    final d = generatedAt;
    return '${d.day} ${m[d.month - 1]} ${d.year}';
  }

  String _md(String? v) => (v == null || v.trim().isEmpty)
      ? tr(
          '[.verdict-urgent]*non renseigné*', '[.verdict-urgent]*not provided*')
      : _esc(v);

  // ── Rendu AsciiDoc ─────────────────────────────────────────────────────

  String toAsciiDoc() {
    final b = StringBuffer();
    final prod = [
      meta.manufacturer,
      meta.product,
      meta.productVersion,
    ].where((s) => s != null && s.trim().isNotEmpty).join(' — ');

    b.writeln(tr('= Rapport de conformité: Cyber Resilience Act',
        '= Compliance report: Cyber Resilience Act'));
    b.writeln('sbom-generator');
    b.writeln(':doctype: article');
    b.writeln(':title-page:');
    b.writeln(':toc:');
    b.writeln(tr(':toc-title: Sommaire', ':toc-title: Contents'));
    b.writeln(':toclevels: 2');
    b.writeln(':revdate: ${_frDate()}');
    if (prod.isNotEmpty) b.writeln(':revremark: ${_esc(prod)}');
    b.writeln(':icons: font');
    b.writeln();

    // ── Portée ──
    b.writeln(tr('== Portée et limites', '== Scope and limits'));
    b.writeln();
    b.writeln('[IMPORTANT]');
    b.writeln('====');
    b.writeln(tr(
        'Ce rapport ne couvre que les exigences du Règlement (UE) '
            '2024/2847 *vérifiables automatiquement* à partir d\'un SBOM et d\'une '
            'analyse de vulnérabilités connues : format et complétude du SBOM '
            '(Annexe I §2 point 1 ; BSI TR-03183-2 ; éléments minimaux NTIA), '
            'inventaire des vulnérabilités et disponibilité des correctifs '
            '(Annexe I §2 points 1-2), vulnérabilités activement exploitées '
            '(art. 14).',
        'This report only covers the requirements of Regulation (EU) '
            '2024/2847 that can be *verified automatically* from an SBOM and a '
            'scan of known vulnerabilities: SBOM format and completeness '
            '(Annex I §2 point 1; BSI TR-03183-2; NTIA minimum elements), '
            'inventory of vulnerabilities and availability of fixes '
            '(Annex I §2 points 1-2), actively exploited vulnerabilities '
            '(art. 14).'));
    b.writeln();
    b.writeln(tr(
        'Les autres obligations du CRA — mécanisme de diffusion sécurisé '
            'des mises à jour, politique de divulgation coordonnée *effective*, '
            'conception sûre par défaut, tests et revues réguliers, notifications '
            'réglementaires, déclaration UE de conformité — relèvent du fabricant '
            'et ne sont pas évaluées ici. Ce document n\'est pas une déclaration '
            'de conformité.',
        'The other CRA obligations — secure update distribution mechanism, '
            '*effective* coordinated vulnerability disclosure policy, '
            'secure by default design, regular tests and reviews, regulatory '
            'notifications, EU declaration of conformity — are the '
            'manufacturer\'s responsibility and are not assessed here. This '
            'document is not a declaration of conformity.'));
    b.writeln('====');
    b.writeln();

    // ── Résumé exécutif ──
    b.writeln(tr('== Résumé exécutif', '== Executive summary'));
    b.writeln();
    b.writeln('${tr('*SBOM évalué*', '*Assessed SBOM*')} : '
        '`${_esc(sbomPath.split(RegExp(r"[/\\]")).last)}` '
        '($_formatLabel, ${_components.length} ${tr('composants', 'components')}) +');
    b.writeln('${tr('*Analyse de vulnérabilités*', '*Vulnerability scan*')} : '
        '${scanRun ? toolVersions.keys.join(', ') : tr('non exécutée', 'not run')}');
    b.writeln();

    final mandatoryOk =
        fieldChecks.where((c) => c.status == CraStatus.ok).length;
    b.writeln('[cols="^1,^1,^1,^1",frame=none,grid=cols]');
    b.writeln('|===');
    b.writeln(tr(
        'h| Champs SBOM conformes h| Éléments NTIA h| Vuln. sans '
            'correctif h| CVE exploitées (KEV)',
        'h| Compliant SBOM fields h| NTIA elements h| Vulns. without '
            'fix h| Exploited CVEs (KEV)'));
    b.writeln('| [.h1-num]*$mandatoryOk / ${fieldChecks.length}* '
        '| [.h1-num]*${ntiaElements.where((e) => e.$2 == CraStatus.ok).length}'
        ' / 7* '
        '| [.${scanRun && cvesWithoutFix.isNotEmpty ? 'h1-num-alert' : 'h1-num'}]'
        '*${scanRun ? '${cvesWithoutFix.length}' : '—'}* '
        '| [.${kevCves.isNotEmpty ? 'h1-num-alert' : 'h1-num'}]'
        '*${scanRun ? '${kevCves.length}' : '—'}*');
    b.writeln('|===');
    b.writeln();

    final vRole = switch (verdict) {
      CraStatus.ok => 'verdict-ok',
      CraStatus.partial => 'verdict-watch',
      _ => 'verdict-urgent',
    };
    b.writeln(
        '[.$vRole]*${tr('Verdict (périmètre vérifié)', 'Verdict (verified scope)')}* : $verdictSentence');
    b.writeln();

    // ── Identification produit ──
    b.writeln(tr('== Identification du produit', '== Product identification'));
    b.writeln();
    b.writeln(tr(
        'CRA art. 13 §§ 8, 15-19 et Annexe II — informations à fournir '
            'aux utilisateurs.',
        'CRA art. 13 §§ 8, 15-19 and Annex II — information to be provided '
            'to users.'));
    b.writeln();
    b.writeln('[cols="<1,<2",options="header"]');
    b.writeln('|===');
    b.writeln(tr('| Élément | Valeur', '| Item | Value'));
    b.writeln(
        '| ${tr('Fabricant', 'Manufacturer')} | ${_md(meta.manufacturer)}');
    b.writeln('| ${tr('Produit', 'Product')} | ${_md(meta.product)}');
    b.writeln('| Version | ${_md(meta.productVersion)}');
    b.writeln(
        '| ${tr('Fin de la période de support', 'End of support period')} | ${_md(meta.supportUntil)}');
    b.writeln(
        '| ${tr('Contact de signalement des vulnérabilités', 'Vulnerability reporting contact')} '
        '| ${_md(meta.vulnerabilityContact)}');
    b.writeln(
        '| ${tr('Politique de divulgation coordonnée', 'Coordinated vulnerability disclosure policy')} '
        '| ${_md(meta.cvdPolicyUrl)}');
    b.writeln('|===');
    b.writeln();

    // ── SBOM ──
    b.writeln(
        tr('== SBOM — format et contenu', '== SBOM — format and content'));
    b.writeln();
    b.writeln(tr('=== Format lisible par machine (Annexe I §2 point 1)',
        '=== Machine-readable format (Annex I §2 point 1)'));
    b.writeln();
    b.writeln('${tr('Format détecté', 'Detected format')} : *$_formatLabel* → '
        '${_machineReadable ? tr('[.verdict-ok]*format d\'usage courant, lisible par machine*', '[.verdict-ok]*commonly used, machine-readable format*') : tr('[.verdict-urgent]*format non reconnu*', '[.verdict-urgent]*unrecognised format*')}.');
    b.writeln();
    b.writeln(
        '${tr('Relations de dépendance', 'Dependency relationships')} : $_dependencyRelations → '
        '${dependencyStatus.badge} '
        '${tr('(exigence : au moins les dépendances de premier niveau)', '(requirement: at least the first-level dependencies)')}.');
    b.writeln();

    b.writeln(tr('=== Champs de données par composant (BSI TR-03183-2)',
        '=== Data fields per component (BSI TR-03183-2)'));
    b.writeln();
    if (fieldChecks.isEmpty) {
      b.writeln(tr('_Aucun composant listé dans le SBOM._',
          '_No component listed in the SBOM._'));
      b.writeln();
    } else {
      b.writeln('[cols="<2,^1,<1,^1",options="header"]');
      b.writeln('|===');
      b.writeln(tr('| Champ | Obligatoire | Couverture | Statut',
          '| Field | Mandatory | Coverage | Status'));
      for (final c in fieldChecks) {
        b.writeln(
            '| ${_esc(c.label)} | ${c.mandatory ? tr('oui', 'yes') : tr('recommandé', 'recommended')} '
            '| ${c.coverage} | ${c.status.badge}');
      }
      b.writeln('|===');
      b.writeln();
      final incomplete =
          fieldChecks.where((c) => c.offenders.isNotEmpty).toList();
      if (incomplete.isNotEmpty) {
        b.writeln(tr('Composants incomplets (échantillon) :',
            'Incomplete components (sample):'));
        b.writeln();
        for (final c in incomplete) {
          b.writeln(
              '* *${_esc(c.label)}* — ${_esc(c.offenders.take(8).join(', '))}'
              '${c.total - c.covered > 8 ? ', … (+${c.total - c.covered - 8})' : ''}');
        }
        b.writeln();
      }
    }

    b.writeln(tr(
        '=== Métadonnées du document (NTIA)', '=== Document metadata (NTIA)'));
    b.writeln();
    b.writeln('[cols="<2,^1",options="header"]');
    b.writeln('|===');
    b.writeln(tr('| Élément | Statut', '| Item | Status'));
    b.writeln('| ${tr('Auteur du SBOM', 'SBOM author')} | '
        '${(_hasAuthor ? CraStatus.ok : CraStatus.fail).badge}');
    b.writeln(
        '| ${tr('Horodatage', 'Timestamp')}${_timestamp != null ? ' (${_esc(_timestamp!)})' : ''} '
        '| ${(_timestamp != null ? CraStatus.ok : CraStatus.fail).badge}');
    b.writeln(
        '| ${tr('Composant primaire déclaré', 'Primary component declared')} | '
        '${(_hasPrimaryComponent ? CraStatus.ok : CraStatus.partial).badge}');
    b.writeln('|===');
    b.writeln();

    b.writeln(tr(
        '== Éléments minimaux NTIA (2021)', '== NTIA minimum elements (2021)'));
    b.writeln();
    b.writeln('[cols="<2,^1",options="header"]');
    b.writeln('|===');
    b.writeln(tr('| Élément | Statut', '| Item | Status'));
    for (final (label, st) in ntiaElements) {
      b.writeln('| ${_esc(label)} | ${st.badge}');
    }
    b.writeln('|===');
    b.writeln();
    if (sbomqsOutput != null && sbomqsOutput!.trim().isNotEmpty) {
      b.writeln(tr('Score `sbomqs` (au moment de l\'évaluation) :',
          '`sbomqs` score (at assessment time):'));
      b.writeln();
      b.writeln('----');
      b.writeln(sbomqsOutput!.trim());
      b.writeln('----');
      b.writeln();
    }

    // ── Vulnérabilités ──
    b.writeln(tr('== Gestion des vulnérabilités (Annexe I §2)',
        '== Vulnerability handling (Annex I §2)'));
    b.writeln();
    if (!scanRun) {
      b.writeln('[WARNING]');
      b.writeln('====');
      b.writeln(tr(
          'L\'analyse de vulnérabilités n\'a pas été exécutée. '
              'L\'inventaire des vulnérabilités connues (Annexe I §2 point 1) et '
              'la disponibilité des correctifs (point 2) ne peuvent pas être '
              'attestés. Relancer avec l\'option `--scan`.',
          'The vulnerability scan was not run. '
              'The inventory of known vulnerabilities (Annex I §2 point 1) and '
              'the availability of fixes (point 2) cannot be '
              'attested. Re-run with the `--scan` option.'));
      b.writeln('====');
      b.writeln();
    } else {
      b.writeln(tr('=== Inventaire des vulnérabilités connues (point 1)',
          '=== Inventory of known vulnerabilities (point 1)'));
      b.writeln();
      b.writeln(
          '${tr('Outils', 'Tools')} : ${toolVersions.entries.map((e) => '${e.key} ${e.value ?? '?'}').join(', ')} +');
      b.writeln(tr(
          'Total : *$totalCves* CVE uniques — '
              '${sevCount('critical')} critiques, ${sevCount('high')} élevées, '
              '${sevCount('medium')} moyennes, ${sevCount('low')} faibles.',
          'Total: *$totalCves* unique CVEs — '
              '${sevCount('critical')} critical, ${sevCount('high')} high, '
              '${sevCount('medium')} medium, ${sevCount('low')} low.'));
      b.writeln();

      b.writeln(tr('=== Disponibilité des correctifs (point 2)',
          '=== Availability of fixes (point 2)'));
      b.writeln();
      final noFix = cvesWithoutFix;
      if (noFix.isEmpty) {
        b.writeln(tr(
            '[.verdict-ok]*Toutes les vulnérabilités connues disposent '
                'd\'une version corrigée.*',
            '[.verdict-ok]*All known vulnerabilities have a fixed '
                'version.*'));
      } else {
        b.writeln(tr(
            '[.verdict-urgent]*${noFix.length} vulnérabilité(s) sans '
                'correctif disponible* — à adresser et remédier sans délai '
                '(Annexe I §2 point 2) :',
            '[.verdict-urgent]*${noFix.length} vulnerability(ies) without an '
                'available fix* — to be addressed and remedied without delay '
                '(Annex I §2 point 2):'));
        b.writeln();
        b.writeln(noFix.take(40).map((id) => '`$id`').join(', ') +
            (noFix.length > 40 ? ', … (+${noFix.length - 40})' : ''));
      }
      b.writeln();

      b.writeln(tr(
          '=== Vulnérabilités activement exploitées — notification '
              'réglementaire (art. 14)',
          '=== Actively exploited vulnerabilities — regulatory '
              'notification (art. 14)'));
      b.writeln();
      final kev = kevCves;
      if (kev.isEmpty) {
        b.writeln(tr(
            '[.verdict-ok]*Aucune vulnérabilité du produit n\'est au '
                'catalogue CISA KEV des vulnérabilités activement exploitées.*',
            '[.verdict-ok]*No vulnerability of the product is in the '
                'CISA KEV catalog of actively exploited vulnerabilities.*'));
        b.writeln();
      } else {
        b.writeln(tr(
            '[.verdict-urgent]*${kev.length} vulnérabilité(s) activement '
                'exploitée(s) (catalogue CISA KEV).*',
            '[.verdict-urgent]*${kev.length} actively exploited '
                'vulnerability(ies) (CISA KEV catalog).*'));
        b.writeln();
        b.writeln('[cols="<2,^1,^1",options="header"]');
        b.writeln('|===');
        b.writeln(tr('| CVE | Ajoutée au KEV | Correctif disponible',
            '| CVE | Added to KEV | Fix available'));
        for (final id in kev) {
          final e = _ex(id);
          final d = e.kevDateAdded;
          b.writeln('| `$id` '
              '| ${d != null ? '${d.year}-${d.month.toString().padLeft(2, '0')}-${d.day.toString().padLeft(2, '0')}' : '—'} '
              '| ${(_cves[id]?.hasFix ?? false) ? tr('oui', 'yes') : tr('[.verdict-urgent]*non*', '[.verdict-urgent]*no*')}');
        }
        b.writeln('|===');
        b.writeln();
        b.writeln('[CAUTION]');
        b.writeln('====');
        b.writeln(tr(
            'CRA art. 14 : le fabricant notifie au CSIRT désigné comme '
                'coordinateur et à l\'ENISA toute vulnérabilité activement '
                'exploitée contenue dans le produit — *alerte précoce sous 24 h*, '
                'notification sous 72 h, rapport final sous 14 jours après mise à '
                'disposition d\'une mesure corrective ou d\'atténuation.',
            'CRA art. 14: the manufacturer notifies the CSIRT designated as '
                'coordinator and ENISA of any actively exploited '
                'vulnerability contained in the product — *early warning within 24 h*, '
                'notification within 72 h, final report within 14 days after a '
                'corrective or mitigating measure is made available.'));
        b.writeln('====');
        b.writeln();
      }
    }

    // ── Exigences fabricant ──
    b.writeln(tr('== Exigences relevant du fabricant (non évaluées)',
        '== Manufacturer requirements (not assessed)'));
    b.writeln();
    b.writeln(tr(
        'Éléments à attester par le fabricant dans sa documentation '
            'technique (Annexe VII) et sa déclaration UE de conformité (Annexe V).',
        'Items to be attested by the manufacturer in its technical '
            'documentation (Annex VII) and its EU declaration of conformity (Annex V).'));
    b.writeln();
    b.writeln('[cols="<3,^1",options="header"]');
    b.writeln('|===');
    b.writeln(
        tr('| Exigence | Élément fourni', '| Requirement | Item provided'));
    final toAttest = tr('_à attester_', '_to be attested_');
    b.writeln(
        '| ${tr('Politique de divulgation coordonnée effective (Annexe I §2 point 5)', 'Effective coordinated vulnerability disclosure policy (Annex I §2 point 5)')} '
        '| ${meta.cvdPolicyUrl != null ? tr('URL fournie', 'URL provided') : tr('[.verdict-urgent]*non*', '[.verdict-urgent]*no*')}');
    b.writeln(
        '| ${tr('Adresse de signalement des vulnérabilités (point 6)', 'Vulnerability reporting address (point 6)')} '
        '| ${meta.vulnerabilityContact != null ? tr('fournie', 'provided') : tr('[.verdict-urgent]*non*', '[.verdict-urgent]*no*')}');
    b.writeln(
        '| ${tr('Diffusion des correctifs sans délai et gratuite (point 8)', 'Fixes distributed without delay and free of charge (point 8)')} '
        '| $toAttest');
    b.writeln(
        '| ${tr('Mécanisme de diffusion sécurisé des mises à jour (Annexe I §1 point 2 k)', 'Secure update distribution mechanism (Annex I §1 point 2 k)')} | $toAttest');
    b.writeln(
        '| ${tr('Tests et revues réguliers de sécurité (point 3)', 'Regular security tests and reviews (point 3)')} | $toAttest');
    b.writeln(
        '| ${tr('Divulgation publique des vulnérabilités corrigées (point 4)', 'Public disclosure of fixed vulnerabilities (point 4)')} '
        '| $toAttest');
    b.writeln(
        '| ${tr('Conception sûre par défaut (Annexe I §1)', 'Secure by default design (Annex I §1)')} | $toAttest');
    b.writeln('|===');
    b.writeln();

    // ── Conclusion ──
    b.writeln('== Conclusion');
    b.writeln();
    b.writeln('[.$vRole]*$verdictSentence*');
    b.writeln();
    if (blockers.isNotEmpty) {
      b.writeln(tr('Points bloquants sur le périmètre vérifié :',
          'Blocking items within the verified scope:'));
      b.writeln();
      for (final blk in blockers) {
        b.writeln('. ${_esc(blk)}');
      }
      b.writeln();
    }
    b.writeln(tr(
        '_Rapport généré par sbom-generator le ${_frDate()}. Périmètre '
            'automatique uniquement — ne se substitue pas à une évaluation de '
            'conformité par le fabricant ou un organisme notifié._',
        '_Report generated by sbom-generator on ${_frDate()}. Automatic '
            'scope only — does not replace a conformity assessment by the '
            'manufacturer or a notified body._'));
    return b.toString();
  }

  // ── Rendu JSON (compagnon machine-lisible) ─────────────────────────────

  Map<String, dynamic> toJson() => {
        'schema': 'sbom-generator/cra-report/1',
        'generatedAt': generatedAt.toUtc().toIso8601String(),
        'regulation': 'EU 2024/2847',
        'scope': 'automated-verifiable-subset',
        'product': {
          'manufacturer': meta.manufacturer,
          'name': meta.product,
          'version': meta.productVersion,
          'supportUntil': meta.supportUntil,
          'vulnerabilityContact': meta.vulnerabilityContact,
          'cvdPolicyUrl': meta.cvdPolicyUrl,
        },
        'sbom': {
          'path': sbomPath,
          'format': _formatLabel,
          'machineReadable': _machineReadable,
          'componentCount': _components.length,
          'dependencyRelations': _dependencyRelations,
          'fieldChecks': [
            for (final c in fieldChecks)
              {
                'id': c.id,
                'field': c.label,
                'mandatory': c.mandatory,
                'covered': c.covered,
                'total': c.total,
                'status': c.status.json,
              }
          ],
          'documentMetadata': {
            'author': _hasAuthor,
            'timestamp': _timestamp,
            'primaryComponent': _hasPrimaryComponent,
          },
        },
        'ntiaMinimumElements': {
          for (final (id, _, st) in _ntia) id: st.json,
        },
        'vulnerabilities': scanRun
            ? {
                'evaluated': true,
                'tools': toolVersions,
                'total': totalCves,
                'bySeverity': {
                  'critical': sevCount('critical'),
                  'high': sevCount('high'),
                  'medium': sevCount('medium'),
                  'low': sevCount('low'),
                },
                'withoutFix': cvesWithoutFix,
                'activelyExploited': [
                  for (final id in kevCves)
                    {
                      'cve': id,
                      'kevDateAdded': _ex(id)
                          .kevDateAdded
                          ?.toIso8601String()
                          .split('T')
                          .first,
                      'hasFix': _cves[id]?.hasFix ?? false,
                    }
                ],
                'article14NotificationRequired': kevCves.isNotEmpty,
              }
            : {'evaluated': false},
        'verdict': verdict.json,
        'verdictSentence': verdictSentence,
        'blockers': blockers,
      };

  String toJsonString() => const JsonEncoder.withIndent('  ').convert(toJson());
}
