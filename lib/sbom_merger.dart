/// Fusionne plusieurs documents SBOM CycloneDX JSON en un seul.
class SbomMerger {
  Map<String, dynamic> merge(
    List<Map<String, dynamic>> sboms, {
    String? documentName,
  }) {
    if (sboms.isEmpty) throw ArgumentError('Au moins un SBOM requis');
    if (sboms.length == 1) return sboms.first;

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

    return result;
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
