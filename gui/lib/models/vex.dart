import 'dart:convert';
import 'dart:math';

// Noyau VEX de la GUI : lecture et écriture OpenVEX / CycloneDX VEX / CSAF. Reprend
// les règles de `lib/vex.dart` du CLI (états, justifications, correspondance
// des produits) — à garder cohérent avec lui.

/// États VEX (vocabulaire OpenVEX).
const vexStatuses = [
  'not_affected',
  'affected',
  'fixed',
  'under_investigation',
];

/// Justifications OpenVEX (pour `not_affected`).
const vexJustifications = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
];

const _cdxJustification = {
  'component_not_present': 'code_not_present',
  'vulnerable_code_not_present': 'code_not_present',
  'vulnerable_code_not_in_execute_path': 'code_not_reachable',
  'vulnerable_code_cannot_be_controlled_by_adversary': 'protected_at_perimeter',
  'inline_mitigations_already_exist': 'protected_by_mitigating_control',
};

const _cdxToOpenVex = {
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

/// « La vulnérabilité [vulnId] est [status] pour [products] » (liste vide =
/// tous les produits).
class VexStatement {
  final String vulnId;
  final List<String> products;
  final String status;
  final String? justification;
  final String? impactStatement;
  final String? actionStatement;

  const VexStatement({
    required this.vulnId,
    this.products = const [],
    required this.status,
    this.justification,
    this.impactStatement,
    this.actionStatement,
  });

  /// « Non affectée » ou « corrigée » : la CVE est écartée des résultats.
  bool get suppresses => status == 'not_affected' || status == 'fixed';

  bool appliesTo(String name, String version) =>
      products.isEmpty || products.any((p) => _matches(p, name, version));

  /// Même déclaration (CVE + produits) : remplacée par une nouvelle.
  bool sameTarget(VexStatement o) =>
      vulnId.toUpperCase() == o.vulnId.toUpperCase() &&
      _sorted(products) == _sorted(o.products);

  static String _sorted(List<String> l) => ([...l]..sort()).join('\u0000');
}

bool _matches(String product, String name, String version) {
  var p = product.trim();
  if (p.isEmpty) return false;
  String pName;
  var pVersion = '';
  if (p.startsWith('pkg:')) {
    p = p.split('?').first.split('#').first;
    final at = p.lastIndexOf('@');
    if (at > p.indexOf('/')) {
      pVersion = Uri.decodeComponent(p.substring(at + 1));
      p = p.substring(0, at);
    }
    pName = Uri.decodeComponent(p.substring(4).split('/').last);
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

/// Lit un document OpenVEX, CycloneDX VEX ou CSAF 2.0 VEX ; [FormatException]
/// sinon.
List<VexStatement> parseVex(Map<String, dynamic> json) {
  if (isCsafVex(json)) return _parseCsaf(json);
  if ('${json['@context'] ?? ''}'.contains('openvex')) {
    final out = <VexStatement>[];
    for (final raw in (json['statements'] as List? ?? const [])) {
      if (raw is! Map) continue;
      final vuln = raw['vulnerability'];
      final id = vuln is Map ? '${vuln['name'] ?? vuln['@id'] ?? ''}' : '$vuln';
      final status = '${raw['status'] ?? ''}';
      if (id.isEmpty || !vexStatuses.contains(status)) continue;
      out.add(
        VexStatement(
          vulnId: id,
          products: [
            for (final p in (raw['products'] as List? ?? const []))
              if (p is Map && '${p['@id'] ?? ''}'.isNotEmpty) '${p['@id']}',
          ],
          status: status,
          justification: raw['justification'] as String?,
          impactStatement: raw['impact_statement'] as String?,
          actionStatement: raw['action_statement'] as String?,
        ),
      );
    }
    return out;
  }
  if (json['bomFormat'] == 'CycloneDX' && json['vulnerabilities'] is List) {
    final out = <VexStatement>[];
    for (final raw in (json['vulnerabilities'] as List)) {
      if (raw is! Map || raw['analysis'] is! Map) continue;
      final analysis = raw['analysis'] as Map;
      final status = switch ('${analysis['state']}') {
        'not_affected' || 'false_positive' => 'not_affected',
        'resolved' || 'resolved_with_pedigree' => 'fixed',
        'exploitable' => 'affected',
        'in_triage' => 'under_investigation',
        _ => '',
      };
      final id = '${raw['id'] ?? ''}';
      if (id.isEmpty || status.isEmpty) continue;
      out.add(
        VexStatement(
          vulnId: id,
          products: [
            for (final a in (raw['affects'] as List? ?? const []))
              if (a is Map && '${a['ref'] ?? ''}'.isNotEmpty) '${a['ref']}',
          ],
          status: status,
          justification: _cdxToOpenVex['${analysis['justification']}'],
          impactStatement: analysis['detail'] as String?,
        ),
      );
    }
    return out;
  }
  throw const FormatException('not an OpenVEX, CSAF or CycloneDX VEX document');
}

String _now() => DateTime.now().toUtc().toIso8601String().replaceFirst(
  RegExp(r'\.\d+Z$'),
  'Z',
);

String _uuid() {
  final r = Random.secure();
  String hex(int n) =>
      List.generate(n, (_) => r.nextInt(16).toRadixString(16)).join();
  return '${hex(8)}-${hex(4)}-4${hex(3)}-'
      '${'89ab'[r.nextInt(4)]}${hex(3)}-${hex(12)}';
}

Map<String, dynamic> buildOpenVex(
  List<VexStatement> statements, {
  required String author,
  required String toolVersion,
}) => {
  '@context': 'https://openvex.dev/ns/v0.2.0',
  '@id': 'urn:uuid:${_uuid()}',
  'author': author,
  'role': 'Document Creator',
  'timestamp': _now(),
  'version': 1,
  'tooling': 'sbom-generator-gui $toolVersion',
  'statements': [
    for (final s in statements)
      {
        'vulnerability': {'name': s.vulnId},
        if (s.products.isNotEmpty)
          'products': [
            for (final p in s.products) {'@id': p},
          ],
        'status': s.status,
        if (s.status == 'not_affected' && s.justification != null)
          'justification': s.justification,
        if (s.impactStatement != null && s.impactStatement!.isNotEmpty)
          'impact_statement': s.impactStatement,
        if (s.status == 'affected')
          'action_statement': s.actionStatement ?? 'See the vendor fixes.',
      },
  ],
};

Map<String, dynamic> buildCycloneDxVex(
  List<VexStatement> statements, {
  required String author,
  required String toolVersion,
}) => {
  'bomFormat': 'CycloneDX',
  'specVersion': '1.6',
  'serialNumber': 'urn:uuid:${_uuid()}',
  'version': 1,
  'metadata': {
    'timestamp': _now(),
    'tools': {
      'components': [
        {
          'type': 'application',
          'name': 'sbom_generator_gui',
          'version': toolVersion,
        },
      ],
    },
    'authors': [
      {'name': author},
    ],
  },
  'vulnerabilities': [
    for (final s in statements)
      {
        'id': s.vulnId,
        'analysis': {
          'state': switch (s.status) {
            'not_affected' => 'not_affected',
            'fixed' => 'resolved',
            'affected' => 'exploitable',
            _ => 'in_triage',
          },
          if (s.status == 'not_affected' &&
              _cdxJustification[s.justification] != null)
            'justification': _cdxJustification[s.justification],
          if (s.impactStatement != null && s.impactStatement!.isNotEmpty)
            'detail': s.impactStatement,
        },
        if (s.products.isNotEmpty)
          'affects': [
            for (final p in s.products) {'ref': p},
          ],
      },
  ],
};

/// Vrai pour un document CSAF 2.0 du profil VEX.
bool isCsafVex(Map<String, dynamic> json) {
  final doc = json['document'];
  return doc is Map && doc['category'] == 'csaf_vex';
}

/// Produit joker de [buildCsafVex] : CSAF ne sait pas dire « tous ».
const _csafAllProducts = '*';

/// `product_id` -> identifiant lisible (PURL de préférence, puis nom).
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
  for (final r in (tree['relationships'] as List? ?? const [])) {
    if (r is! Map) continue;
    final combined = r['full_product_name'];
    final id = combined is Map ? combined['product_id'] : null;
    final ref = out['${r['product_reference']}'];
    if (id != null && ref != null) out['$id'] = ref;
  }
  return out;
}

List<VexStatement> _parseCsaf(Map<String, dynamic> json) {
  final products = _csafProducts(json['product_tree']);
  List<String> resolve(Object? ids) => [
    for (final id in (ids as List? ?? const [])) products['$id'] ?? '$id',
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
    final ids = raw['ids'] as List? ?? const [];
    final id =
        '${raw['cve'] ?? (ids.isNotEmpty && ids.first is Map ? (ids.first as Map)['text'] : '') ?? ''}';
    final status = raw['product_status'];
    if (id.isEmpty || status is! Map) continue;

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
            vexJustifications.contains(f['label']) &&
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

      out.add(
        VexStatement(
          vulnId: id,
          products: own,
          status: e.value,
          justification: justification,
          impactStatement: detail('threats', (t) => t['category'] == 'impact'),
          actionStatement: detail('remediations', (_) => true),
        ),
      );
    }
  }
  return out;
}

/// Document CSAF 2.0, profil VEX (même structure que le CLI).
Map<String, dynamic> buildCsafVex(
  List<VexStatement> statements, {
  required String author,
  required String toolVersion,
}) {
  final now = _now();
  final ids = <String, String>{};
  String productId(String ref) => ids.putIfAbsent(
    ref,
    () => 'CSAFPID-${(ids.length + 1).toString().padLeft(4, '0')}',
  );

  final byVuln = <String, List<VexStatement>>{};
  for (final s in statements) {
    (byVuln[s.vulnId] ??= []).add(s);
  }
  final vulnerabilities = <Map<String, dynamic>>[];
  for (final e in byVuln.entries) {
    final status = <String, List<String>>{};
    final flags = <Map<String, dynamic>>[];
    final threats = <Map<String, dynamic>>[];
    final remediations = <Map<String, dynamic>>[];
    for (final s in e.value) {
      final pids = [
        for (final p
            in s.products.isEmpty ? const [_csafAllProducts] : s.products)
          productId(p),
      ];
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
      if (s.impactStatement != null && s.impactStatement!.isNotEmpty) {
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
        'id': 'sbom-generator-${_uuid()}',
        'status': 'final',
        'version': '1',
        'initial_release_date': now,
        'current_release_date': now,
        'revision_history': [
          {'date': now, 'number': '1', 'summary': 'Initial version'},
        ],
        'generator': {
          'engine': {'name': 'sbom_generator_gui', 'version': toolVersion},
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
