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

  const VexStatement({
    required this.vulnId,
    this.products = const [],
    required this.status,
    this.justification,
    this.impactStatement,
    this.actionStatement,
  });

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

/// Document VEX (OpenVEX ou CycloneDX VEX), réduit à ses déclarations.
class VexDocument {
  final List<VexStatement> statements;
  const VexDocument(this.statements);

  /// Lit un document OpenVEX (`@context` openvex.dev) ou CycloneDX (tableau
  /// `vulnerabilities`). Lève [FormatException] pour tout autre contenu.
  factory VexDocument.parse(Map<String, dynamic> json) {
    final ctx = '${json['@context'] ?? ''}';
    if (ctx.contains('openvex')) return VexDocument(_parseOpenVex(json));
    if (json['bomFormat'] == 'CycloneDX' && json['vulnerabilities'] is List) {
      return VexDocument(_parseCdx(json));
    }
    throw FormatException(tr(
        'document VEX non reconnu (attendu : OpenVEX ou CycloneDX avec "vulnerabilities")',
        'unrecognised VEX document (expected: OpenVEX or CycloneDX with "vulnerabilities")'));
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

  /// Première déclaration qui vise [vulnId] pour le paquet `name@version`.
  VexStatement? find(String vulnId, String name, String version) {
    final id = vulnId.toUpperCase();
    for (final s in statements) {
      if (s.vulnId.toUpperCase() == id && s.appliesTo(name, version)) return s;
    }
    return null;
  }
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
                  tr('Voir les correctifs de l\'éditeur.',
                      'See the vendor fixes.'),
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

String encodeVex(Map<String, dynamic> doc) =>
    const JsonEncoder.withIndent('  ').convert(doc);
