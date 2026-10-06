import 'dart:convert';
import 'dart:math';

// Noyau VEX de la GUI : lecture et écriture OpenVEX / CycloneDX VEX. Reprend
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

/// Lit un document OpenVEX ou CycloneDX VEX ; [FormatException] sinon.
List<VexStatement> parseVex(Map<String, dynamic> json) {
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
  throw const FormatException('not an OpenVEX or CycloneDX VEX document');
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

String encodeVex(Map<String, dynamic> doc) =>
    const JsonEncoder.withIndent('  ').convert(doc);
