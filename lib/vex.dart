import 'dart:convert';

import 'i18n.dart';
import 'models.dart' show generateUuidV4;

/// États VEX normalisés (vocabulaire OpenVEX).
const vexStatuses = {
  'not_affected',
  'affected',
  'fixed',
  'under_investigation',
};

/// Justifications OpenVEX (pour `not_affected`).
const openVexJustifications = {
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
};

/// OpenVEX → CycloneDX (`analysis.justification`).
const _cdxJustification = {
  'component_not_present': 'code_not_present',
  'vulnerable_code_not_present': 'code_not_present',
  'vulnerable_code_not_in_execute_path': 'code_not_reachable',
  'vulnerable_code_cannot_be_controlled_by_adversary': 'protected_at_perimeter',
  'inline_mitigations_already_exist': 'protected_by_mitigating_control',
};

const _cdxJustificationToOpenVex = {
  'code_not_present': 'vulnerable_code_not_present',
  'code_not_reachable': 'vulnerable_code_not_in_execute_path',
  'protected_at_perimeter': 'vulnerable_code_cannot_be_controlled_by_adversary',
  'protected_at_runtime': 'inline_mitigations_already_exist',
  'protected_by_compiler': 'inline_mitigations_already_exist',
  'protected_by_mitigating_control': 'inline_mitigations_already_exist',
  'requires_configuration': 'vulnerable_code_not_in_execute_path',
  'requires_dependency': 'vulnerable_code_not_in_execute_path',
  'requires_environment': 'vulnerable_code_not_in_execute_path',
};

/// Une déclaration VEX : « la vulnérabilité [vulnId] est [status] pour
/// [products] » (liste vide = tous les produits).
class VexStatement {
  final String vulnId;
  final List<String> products;
  final String status;
  final String? justification;
  final String? impactStatement;
  final String? actionStatement;

  /// Fichier VEX d'origine, renseigné quand plusieurs documents sont fusionnés.
  final String? source;

  const VexStatement({
    required this.vulnId,
    this.products = const [],
    required this.status,
    this.justification,
    this.impactStatement,
    this.actionStatement,
    this.source,
  });

  VexStatement withSource(String source) => VexStatement(
        vulnId: vulnId,
        products: products,
        status: status,
        justification: justification,
        impactStatement: impactStatement,
        actionStatement: actionStatement,
        source: source,
      );

  /// Une déclaration « non affecté » / « corrigé » écarte la CVE des résultats.
  bool get suppresses => status == 'not_affected' || status == 'fixed';

  /// Vrai si la déclaration vise le paquet `name@version` d'un résultat de
  /// scan (un identifiant de produit est un PURL, `nom` ou `nom@version`).
  bool appliesTo(String name, String version) {
    if (products.isEmpty) return true;
    return products.any((p) => _productMatches(p, name, version));
  }
}

bool _productMatches(String product, String name, String version) {
  var p = product.trim();
  if (p.isEmpty) return false;
  String pName;
  String pVersion = '';
  if (p.startsWith('pkg:')) {
    p = p.split('?').first.split('#').first;
    final at = p.lastIndexOf('@');
    if (at > p.indexOf('/')) {
      pVersion = Uri.decodeComponent(p.substring(at + 1));
      p = p.substring(0, at);
    }
    final segs = p.substring(4).split('/'); // type/ns…/name
    pName = Uri.decodeComponent(segs.last);
  } else {
    final at = p.lastIndexOf('@');
    if (at > 0) {
      pVersion = p.substring(at + 1);
      p = p.substring(0, at);
    }
    pName = p;
  }
  return pName.toLowerCase() == name.toLowerCase() &&
      (pVersion.isEmpty || pVersion == version);
}

/// Document VEX (OpenVEX, CycloneDX VEX ou CSAF 2.0 VEX), réduit à ses
/// déclarations.
class VexDocument {
  final List<VexStatement> statements;
  const VexDocument(this.statements);

  /// Lit un document OpenVEX (`@context` openvex.dev), CycloneDX (tableau
  /// `vulnerabilities`) ou CSAF 2.0 (`document.category` = `csaf_vex`).
  /// Lève [FormatException] pour tout autre contenu.
  factory VexDocument.parse(Map<String, dynamic> json) {
    final ctx = '${json['@context'] ?? ''}';
    if (ctx.contains('openvex')) return VexDocument(_parseOpenVex(json));
    if (isCsafVex(json)) return VexDocument(_parseCsaf(json));
    if (json['bomFormat'] == 'CycloneDX' && json['vulnerabilities'] is List) {
      return VexDocument(_parseCdx(json));
    }
    throw FormatException(tr('document VEX non reconnu (attendu : OpenVEX, CSAF VEX ou CycloneDX avec "vulnerabilities")'));
  }

  static List<VexStatement> _parseOpenVex(Map<String, dynamic> json) {
    final out = <VexStatement>[];
    for (final raw in (json['statements'] as List? ?? const [])) {
      if (raw is! Map) continue;
      final vuln = raw['vulnerability'];
      final id = vuln is Map ? '${vuln['name'] ?? vuln['@id'] ?? ''}' : '$vuln';
      if (id.isEmpty) continue;
      final status = '${raw['status'] ?? ''}';
      if (!vexStatuses.contains(status)) continue;
      out.add(VexStatement(
        vulnId: id,
        products: [
          for (final p in (raw['products'] as List? ?? const []))
            if (p is Map) ...[
              '${p['@id'] ?? ''}',
              ...[
                for (final sub in (p['subcomponents'] as List? ?? const []))
                  if (sub is Map) '${sub['@id'] ?? ''}',
              ],
            ] else
              '$p',
        ].where((e) => e.isNotEmpty).toList(),
        status: status,
        justification: raw['justification'] as String?,
        impactStatement: raw['impact_statement'] as String?,
        actionStatement: raw['action_statement'] as String?,
      ));
    }
    return out;
  }

  static List<VexStatement> _parseCdx(Map<String, dynamic> json) {
    final out = <VexStatement>[];
    for (final raw in (json['vulnerabilities'] as List)) {
      if (raw is! Map) continue;
      final id = '${raw['id'] ?? ''}';
      final analysis = raw['analysis'];
      if (id.isEmpty || analysis is! Map) continue;
      final status = switch ('${analysis['state']}') {
        'not_affected' || 'false_positive' => 'not_affected',
        'resolved' || 'resolved_with_pedigree' => 'fixed',
        'exploitable' => 'affected',
        'in_triage' => 'under_investigation',
        _ => '',
      };
      if (status.isEmpty) continue;
      final cdxJust = analysis['justification'] as String?;
      out.add(VexStatement(
        vulnId: id,
        products: [
          for (final a in (raw['affects'] as List? ?? const []))
            if (a is Map && '${a['ref'] ?? ''}'.isNotEmpty) '${a['ref']}',
        ],
        status: status,
        justification:
            cdxJust == null ? null : _cdxJustificationToOpenVex[cdxJust],
        impactStatement: analysis['detail'] as String?,
      ));
    }
    return out;
  }

  /// CSAF 2.0, profil VEX : les produits sont désignés par `product_id`, que
  /// l'arbre `product_tree` associe à un PURL (sinon au nom du produit).
  static List<VexStatement> _parseCsaf(Map<String, dynamic> json) {
    final products = _csafProducts(json['product_tree']);
    String name(Object? id) => products['$id'] ?? '$id';
    // Le produit joker écrit par [buildCsafVex] vaut « tous les produits ».
    List<String> resolve(Object? ids) => [
          for (final id in (ids as List? ?? const [])) name(id),
        ].where((p) => p != _csafAllProducts).toList();

    const statusMap = {
      'known_not_affected': 'not_affected',
      'fixed': 'fixed',
      'first_fixed': 'fixed',
      'known_affected': 'affected',
      'under_investigation': 'under_investigation',
    };
    final out = <VexStatement>[];
    for (final raw in (json['vulnerabilities'] as List? ?? const [])) {
      if (raw is! Map) continue;
      final ids = (raw['ids'] as List? ?? const []);
      final id =
          '${raw['cve'] ?? (ids.isNotEmpty && ids.first is Map ? (ids.first as Map)['text'] : '') ?? ''}';
      final status = raw['product_status'];
      if (id.isEmpty || status is! Map) continue;

      // Éléments rattachés à des produits (flags, threats, remediations) :
      // retenus pour une déclaration si leurs produits recoupent les siens.
      bool concerns(Object? entry, List<String> own) {
        final theirs = resolve((entry as Map)['product_ids']);
        return theirs.isEmpty || own.isEmpty || theirs.any(own.contains);
      }

      for (final e in statusMap.entries) {
        final listed = status[e.key];
        if (listed is! List || listed.isEmpty) continue;
        final own = resolve(listed);
        String? justification;
        for (final f in (raw['flags'] as List? ?? const [])) {
          if (f is Map &&
              openVexJustifications.contains(f['label']) &&
              concerns(f, own)) {
            justification = '${f['label']}';
            break;
          }
        }
        String? detail(String key, bool Function(Map) keep) {
          for (final t in (raw[key] as List? ?? const [])) {
            if (t is Map && keep(t) && concerns(t, own)) {
              return t['details'] as String?;
            }
          }
          return null;
        }

        out.add(VexStatement(
          vulnId: id,
          products: own,
          status: e.value,
          justification: justification,
          impactStatement: detail('threats', (t) => t['category'] == 'impact'),
          actionStatement: detail('remediations', (_) => true),
        ));
      }
    }
    return out;
  }

  /// Fusionne plusieurs documents (nom de fichier → document) en un seul ;
  /// chaque déclaration garde son fichier d'origine.
  factory VexDocument.merge(Map<String, VexDocument> docs) => VexDocument([
        for (final e in docs.entries)
          for (final s in e.value.statements) s.withSource(e.key),
      ]);

  /// Déclaration qui vise [vulnId] pour le paquet `name@version`.
  ///
  /// Si des documents se contredisent, la plus prudente l'emporte : une
  /// déclaration qui n'écarte pas la CVE (affected, under_investigation) prime
  /// sur « not_affected » / « fixed », pour ne jamais masquer un risque sur la
  /// foi d'un seul document.
  VexStatement? find(String vulnId, String name, String version) {
    final id = vulnId.toUpperCase();
    VexStatement? first;
    for (final s in statements) {
      if (s.vulnId.toUpperCase() != id || !s.appliesTo(name, version)) continue;
      if (!s.suppresses) return s;
      first ??= s;
    }
    return first;
  }
}

/// Vrai pour un document CSAF 2.0 du profil VEX.
bool isCsafVex(Map<String, dynamic> json) {
  final doc = json['document'];
  return doc is Map && doc['category'] == 'csaf_vex';
}

/// Nom du produit joker de [buildCsafVex] (CSAF ne sait pas dire « tous »).
const _csafAllProducts = '*';

/// `product_id` -> identifiant lisible (PURL de préférence, puis nom) pour tous
/// les produits de l'arbre CSAF, y compris ceux des `relationships`.
Map<String, String> _csafProducts(Object? tree) {
  final out = <String, String>{};
  if (tree is! Map) return out;

  void product(Object? p) {
    if (p is! Map) return;
    final id = p['product_id'];
    if (id == null) return;
    final helper = p['product_identification_helper'];
    final purl = helper is Map ? helper['purl'] : null;
    out['$id'] = '${purl ?? p['name'] ?? id}';
  }

  void branches(Object? list) {
    for (final b in (list as List? ?? const [])) {
      if (b is! Map) continue;
      product(b['product']);
      branches(b['branches']);
    }
  }

  for (final p in (tree['full_product_names'] as List? ?? const [])) {
    product(p);
  }
  branches(tree['branches']);

  // « composant installé sur plate-forme » : le produit visé est le composant.
  for (final r in (tree['relationships'] as List? ?? const [])) {
    if (r is! Map) continue;
    final combined = r['full_product_name'];
    final id = combined is Map ? combined['product_id'] : null;
    final ref = out['${r['product_reference']}'];
    if (id != null && ref != null) out['$id'] = ref;
  }
  return out;
}

/// Sépare `nom@version` (le dernier `@`, pour les paquets npm à portée).
(String, String) splitPackage(String pkg) {
  final at = pkg.lastIndexOf('@');
  if (at <= 0) return (pkg, '');
  return (pkg.substring(0, at), pkg.substring(at + 1));
}

String _now() => DateTime.now()
    .toUtc()
    .toIso8601String()
    .replaceFirst(RegExp(r'\.\d+Z$'), 'Z');

/// Document OpenVEX v0.2.0.
Map<String, dynamic> buildOpenVex({
  required List<VexStatement> statements,
  required String author,
  required String toolVersion,
  String role = 'Document Creator',
}) =>
    {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': 'urn:uuid:${generateUuidV4()}',
      'author': author,
      'role': role,
      'timestamp': _now(),
      'version': 1,
      'tooling': 'sbom-generator $toolVersion',
      'statements': [
        for (final s in statements)
          {
            'vulnerability': {'name': s.vulnId},
            if (s.products.isNotEmpty)
              'products': [
                for (final p in s.products) {'@id': p},
              ],
            'status': s.status,
            if (s.justification != null && s.status == 'not_affected')
              'justification': s.justification,
            if (s.impactStatement != null)
              'impact_statement': s.impactStatement,
            if (s.status == 'affected')
              'action_statement': s.actionStatement ??
                  tr('Voir les correctifs de l\'éditeur.'),
          },
      ],
    };

/// Document CycloneDX VEX (1.6) : un SBOM sans composants, avec
/// `vulnerabilities[].analysis`.
Map<String, dynamic> buildCycloneDxVex({
  required List<VexStatement> statements,
  required String author,
  required String toolVersion,
}) {
  final byId = <String, List<VexStatement>>{};
  for (final s in statements) {
    (byId[s.vulnId] ??= []).add(s);
  }
  return {
    'bomFormat': 'CycloneDX',
    'specVersion': '1.6',
    'serialNumber': 'urn:uuid:${generateUuidV4()}',
    'version': 1,
    'metadata': {
      'timestamp': _now(),
      'tools': {
        'components': [
          {
            'type': 'application',
            'name': 'sbom_generator',
            'version': toolVersion,
          }
        ],
      },
      'authors': [
        {'name': author}
      ],
    },
    'vulnerabilities': [
      for (final e in byId.entries)
        for (final s in e.value)
          {
            'id': e.key,
            'analysis': {
              'state': switch (s.status) {
                'not_affected' => 'not_affected',
                'fixed' => 'resolved',
                'affected' => 'exploitable',
                _ => 'in_triage',
              },
              if (s.status == 'not_affected' && s.justification != null)
                if (_cdxJustification[s.justification] != null)
                  'justification': _cdxJustification[s.justification],
              if (s.impactStatement != null) 'detail': s.impactStatement,
            },
            if (s.products.isNotEmpty)
              'affects': [
                for (final p in s.products) {'ref': p},
              ],
          },
    ],
  };
}

/// Document CSAF 2.0, profil VEX. Un produit sans PURL est désigné par son
/// seul nom ; « tous les produits » devient le produit joker `*`.
Map<String, dynamic> buildCsafVex({
  required List<VexStatement> statements,
  required String author,
  required String toolVersion,
}) {
  final now = _now();
  final ids = <String, String>{}; // identifiant lisible -> product_id
  String productId(String ref) => ids.putIfAbsent(
      ref, () => 'CSAFPID-${(ids.length + 1).toString().padLeft(4, '0')}');

  List<String> idsOf(VexStatement s) => [
        for (final p
            in s.products.isEmpty ? const [_csafAllProducts] : s.products)
          productId(p),
      ];

  final vulnerabilities = <Map<String, dynamic>>[];
  final byVuln = <String, List<VexStatement>>{};
  for (final s in statements) {
    (byVuln[s.vulnId] ??= []).add(s);
  }
  for (final e in byVuln.entries) {
    final status = <String, List<String>>{};
    final flags = <Map<String, dynamic>>[];
    final threats = <Map<String, dynamic>>[];
    final remediations = <Map<String, dynamic>>[];
    for (final s in e.value) {
      final pids = idsOf(s);
      final key = switch (s.status) {
        'not_affected' => 'known_not_affected',
        'fixed' => 'fixed',
        'affected' => 'known_affected',
        _ => 'under_investigation',
      };
      (status[key] ??= []).addAll(pids);
      if (s.status == 'not_affected' && s.justification != null) {
        flags.add({'label': s.justification, 'product_ids': pids});
      }
      if (s.impactStatement != null) {
        threats.add({
          'category': 'impact',
          'details': s.impactStatement,
          'product_ids': pids,
        });
      }
      if (s.actionStatement != null) {
        remediations.add({
          'category': 'mitigation',
          'details': s.actionStatement,
          'product_ids': pids,
        });
      }
    }
    final isCve = RegExp(r'^CVE-\d{4}-\d{4,}$').hasMatch(e.key);
    vulnerabilities.add({
      if (isCve)
        'cve': e.key
      else
        'ids': [
          {'system_name': 'vulnerability', 'text': e.key},
        ],
      'product_status': status,
      if (flags.isNotEmpty) 'flags': flags,
      if (threats.isNotEmpty) 'threats': threats,
      if (remediations.isNotEmpty) 'remediations': remediations,
    });
  }

  return {
    'document': {
      'category': 'csaf_vex',
      'csaf_version': '2.0',
      'title': 'VEX — $author',
      'publisher': {
        'category': 'other',
        'name': author,
        'namespace': 'https://sbom.local',
      },
      'tracking': {
        'id': 'sbom-generator-${generateUuidV4()}',
        'status': 'final',
        'version': '1',
        'initial_release_date': now,
        'current_release_date': now,
        'revision_history': [
          {'date': now, 'number': '1', 'summary': 'Initial version'},
        ],
        'generator': {
          'engine': {'name': 'sbom_generator', 'version': toolVersion},
        },
      },
    },
    'product_tree': {
      'full_product_names': [
        for (final e in ids.entries)
          {
            'product_id': e.value,
            'name': e.key,
            if (e.key.startsWith('pkg:'))
              'product_identification_helper': {'purl': e.key},
          },
      ],
    },
    'vulnerabilities': vulnerabilities,
  };
}

String encodeVex(Map<String, dynamic> doc) =>
    const JsonEncoder.withIndent('  ').convert(doc);
