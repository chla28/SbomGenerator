import 'i18n.dart';

/// Fusionne plusieurs documents SBOM JSON (CycloneDX ou SPDX 2.x) en un seul,
/// dans le même format que le premier document fourni.
class SbomMerger {
  Map<String, dynamic> merge(
    List<Map<String, dynamic>> sboms, {
    String? documentName,
  }) {
    if (sboms.isEmpty) {
      throw ArgumentError(
          tr('Au moins un SBOM requis', 'At least one SBOM is required'));
    }
    if (sboms.length == 1) return sboms.first;

    if (sboms.first.containsKey('spdxVersion')) {
      return _mergeSpdx(sboms, documentName: documentName);
    }
    return _mergeCycloneDx(sboms, documentName: documentName);
  }

  Map<String, dynamic> _mergeCycloneDx(
    List<Map<String, dynamic>> sboms, {
    String? documentName,
  }) {
    // Prendre les métadonnées du premier SBOM comme base
    final base = sboms.first;
    final metadata = Map<String, dynamic>.from(
        (base['metadata'] as Map<String, dynamic>?) ?? {});

    // Mettre à jour le nom si fourni
    if (documentName != null) {
      final component = Map<String, dynamic>.from(
          (metadata['component'] as Map<String, dynamic>?) ?? {});
      component['name'] = documentName;
      metadata['component'] = component;
    }
    metadata['timestamp'] = DateTime.now().toUtc().toIso8601String();

    // Fusionner les composants en dédupliquant par purl puis par bomRef
    final seenPurls = <String>{};
    final seenRefs = <String>{};
    final allComponents = <Map<String, dynamic>>[];

    for (final sbom in sboms) {
      final components = (sbom['components'] as List?) ?? [];
      for (final raw in components) {
        final c = raw as Map<String, dynamic>;
        final purl = (c['purl'] as String?) ?? '';
        final ref = (c['bom-ref'] as String?) ?? '';

        final key = purl.isNotEmpty ? purl : ref;
        if (key.isEmpty || seenPurls.add(key)) {
          if (ref.isNotEmpty) seenRefs.add(ref);
          allComponents.add(c);
        }
      }
    }

    // Fusionner les dépendances
    final allDeps = <Map<String, dynamic>>[];
    final depRefs = <String>{};
    for (final sbom in sboms) {
      for (final dep in (sbom['dependencies'] as List?) ?? []) {
        final d = dep as Map<String, dynamic>;
        final ref = (d['ref'] as String?) ?? '';
        if (ref.isEmpty || depRefs.add(ref)) allDeps.add(d);
      }
    }

    // Fusionner les citations (CycloneDX 1.7, root-level)
    final allCitations = <Map<String, dynamic>>[];
    final citationRefs = <String>{};
    for (final sbom in sboms) {
      for (final citation in (sbom['citations'] as List?) ?? []) {
        final c = citation as Map<String, dynamic>;
        final ref = (c['bom-ref'] as String?) ?? '';
        if (ref.isEmpty || citationRefs.add(ref)) allCitations.add(c);
      }
    }

    // Fusionner definitions.patents (CycloneDX 1.7, root-level)
    final allPatents = <Map<String, dynamic>>[];
    final patentRefs = <String>{};
    for (final sbom in sboms) {
      final defs = sbom['definitions'] as Map<String, dynamic>?;
      for (final patent in (defs?['patents'] as List?) ?? []) {
        final p = patent as Map<String, dynamic>;
        final ref = (p['bom-ref'] as String?) ?? '';
        if (ref.isEmpty || patentRefs.add(ref)) allPatents.add(p);
      }
    }

    // Construire le document fusionné
    final result = <String, dynamic>{
      'bomFormat': 'CycloneDX',
      'specVersion': (base['specVersion'] as String?) ?? '1.6',
      'serialNumber': 'urn:uuid:${_generateUuid()}',
      'version': 1,
      'metadata': metadata,
      'components': allComponents,
    };
    if (allDeps.isNotEmpty) result['dependencies'] = allDeps;
    if (allCitations.isNotEmpty) result['citations'] = allCitations;
    if (allPatents.isNotEmpty) result['definitions'] = {'patents': allPatents};

    return result;
  }

  /// Fusionne des documents SPDX 2.x. Les paquets sont dédupliqués par purl
  /// (externalRefs de type "purl"), puis par SPDXID. Note : les SPDXID des
  /// documents source sont conservés tels quels dans les relations ; pour les
  /// SBOM générés par cet outil, ils sont déterministes (nom+version) donc
  /// stables entre documents, mais une collision reste possible si un
  /// document externe réutilise un SPDXID générique pour un autre paquet.
  Map<String, dynamic> _mergeSpdx(
    List<Map<String, dynamic>> sboms, {
    String? documentName,
  }) {
    final base = sboms.first;

    final seenKeys = <String>{};
    final allPackages = <Map<String, dynamic>>[];
    for (final sbom in sboms) {
      final packages = (sbom['packages'] as List?) ?? [];
      for (final raw in packages) {
        final p = raw as Map<String, dynamic>;
        final spdxId = (p['SPDXID'] as String?) ?? '';
        String purl = '';
        for (final ref in (p['externalRefs'] as List? ?? [])) {
          final r = ref as Map<String, dynamic>;
          if (r['referenceType'] == 'purl') {
            purl = (r['referenceLocator'] as String?) ?? '';
            break;
          }
        }
        final key = purl.isNotEmpty ? purl : spdxId;
        if (key.isEmpty || seenKeys.add(key)) {
          allPackages.add(p);
        }
      }
    }

    final seenRels = <String>{};
    final allRels = <Map<String, dynamic>>[];
    for (final sbom in sboms) {
      for (final raw in (sbom['relationships'] as List?) ?? []) {
        final r = raw as Map<String, dynamic>;
        final key =
            '${r['spdxElementId']}|${r['relationshipType']}|${r['relatedSpdxElement']}';
        if (seenRels.add(key)) allRels.add(r);
      }
    }

    final baseCreationInfo = base['creationInfo'] as Map<String, dynamic>?;

    return {
      'SPDXID': 'SPDXRef-DOCUMENT',
      'spdxVersion': (base['spdxVersion'] as String?) ?? 'SPDX-2.3',
      'creationInfo': {
        'created': DateTime.now().toUtc().toIso8601String(),
        'creators': ['Tool: sbom_generator-1.6.6'],
        'licenseListVersion': baseCreationInfo?['licenseListVersion'] ?? '3.21',
      },
      'name': documentName ?? (base['name'] as String? ?? 'Merged SBOM'),
      'dataLicense': (base['dataLicense'] as String?) ?? 'CC0-1.0',
      'documentNamespace': 'https://sbom.local/spdx/${_generateUuid()}',
      'packages': allPackages,
      'relationships': allRels,
    };
  }

  /// UUID v4 simplifié (non-cryptographique, suffisant pour les bomRef).
  String _generateUuid() {
    final now = DateTime.now().millisecondsSinceEpoch;
    final bytes = List<int>.generate(16, (i) {
      if (i == 0) return (now >> 24) & 0xFF;
      if (i == 1) return (now >> 16) & 0xFF;
      if (i == 2) return (now >> 8) & 0xFF;
      if (i == 3) return now & 0xFF;
      return (now * (i + 1)) & 0xFF;
    });
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant RFC4122

    String hex(int b) => b.toRadixString(16).padLeft(2, '0');
    return '${hex(bytes[0])}${hex(bytes[1])}${hex(bytes[2])}${hex(bytes[3])}-'
        '${hex(bytes[4])}${hex(bytes[5])}-'
        '${hex(bytes[6])}${hex(bytes[7])}-'
        '${hex(bytes[8])}${hex(bytes[9])}-'
        '${bytes.sublist(10).map(hex).join()}';
  }
}
