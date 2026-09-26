import 'dart:convert';
import 'dart:io';
import 'hash_utils.dart' show spdx3Alg;
import 'image_layers.dart';
import 'license_normalizer.dart';
import 'models.dart';

/// Generates an SPDX 3.0 JSON-LD SBOM.
///
/// Specification: https://spdx.github.io/spdx-spec/v3.0/
class Spdx3Generator {
  static const _context = 'https://spdx.org/rdf/3.0.0/spdx-context.jsonld';
  static const _specVersion = '3.0.0';

  Map<String, dynamic> generate(
    List<Package> packages,
    List<PackageDependency> dependencies, {
    String? documentName,

    /// OS de base de l'image de conteneur source (voir [OsInfo]), si connu.
    /// Ajoute un élément `software:primaryPurpose: "operatingSystem"`
    /// distinct des paquets applicatifs — même justification que côté
    /// CycloneDX (voir `CycloneDxGenerator.generate`).
    OsInfo? osInfo,

    /// SDK/toolchain de build (`{'flutter': '3.47.2', 'dart': '3.9.0'}`),
    /// ajouté au graphe comme éléments `Tool` référencés par `createdBy`.
    Map<String, String> sdkTools = const {},

    /// Analyse par couche (`--per-layer`) : description en commentaire du
    /// document, couche d'origine / changement en annotation des paquets.
    LayerAnnotations? layers,
  }) {
    final now = DateTime.now().toUtc().toIso8601String();
    final base =
        'https://sbom.local/spdx3/${layers?.documentUuid ?? generateUuidV4()}';

    final docId = base;
    final ciId = '$base#creationInfo';
    final toolId = '$base#tool-sbom_generator';
    final sdkToolIds = {
      for (final name in sdkTools.keys) name: '$base#tool-sdk-${_safeId(name)}',
    };

    final pkgIds = {
      for (final pkg in packages) pkg.bomRef: '$base#${pkg.spdxId}',
    };
    final osId = osInfo != null ? '$base#os-${_safeId(osInfo.id)}' : null;

    final graph = <Map<String, dynamic>>[];

    graph.add({
      '@id': ciId,
      'type': 'CreationInfo',
      'specVersion': _specVersion,
      'created': now,
      'createdBy': [toolId, ...sdkToolIds.values],
    });

    graph.add({
      'type': 'Tool',
      'spdxId': toolId,
      'creationInfo': ciId,
      'name': 'sbom_generator',
      'toolVersion': '1.5.12',
    });

    sdkTools.forEach((name, version) {
      graph.add({
        'type': 'Tool',
        'spdxId': sdkToolIds[name],
        'creationInfo': ciId,
        'name': name,
        if (version.isNotEmpty) 'toolVersion': version,
      });
    });

    final vendorIds = _buildVendorElements(packages, base, ciId, graph);

    final rootElements = [
      if (osId != null) osId,
      ...pkgIds.values,
    ];

    graph.add({
      'type': 'SpdxDocument',
      'spdxId': docId,
      'creationInfo': ciId,
      'name': layers?.isLayerDocument == true
          ? '${documentName ?? 'Package Set SBOM'} — ${layers!.layerLabel}'
          : documentName ?? 'Package Set SBOM',
      if (layers != null) 'comment': layers.describe().join('\n'),
      'profileConformance': ['core', 'software'],
      'rootElement': rootElements,
    });

    if (osInfo != null) {
      graph.add(_osToElement(osInfo, spdxId: osId!, ciId: ciId));
    }

    for (final pkg in packages) {
      graph.add(_packageToElement(
        pkg,
        spdxId: pkgIds[pkg.bomRef]!,
        ciId: ciId,
        vendorId: vendorIds[pkg.vendor],
        layers: layers,
      ));
    }

    graph.add({
      'type': 'Relationship',
      'spdxId': '$base#rel-describes',
      'creationInfo': ciId,
      'from': docId,
      'to': rootElements,
      'relationshipType': 'describes',
    });

    int idx = 0;
    for (final dep in dependencies) {
      final fromId = pkgIds[dep.sourceRef];
      if (fromId == null || dep.dependsOn.isEmpty) continue;
      for (final target in dep.dependsOn) {
        final toId = pkgIds[target];
        if (toId == null) continue;
        idx++;
        graph.add({
          'type': 'Relationship',
          'spdxId': '$base#rel-$idx',
          'creationInfo': ciId,
          'from': fromId,
          'to': [toId],
          'relationshipType': 'dependsOn',
        });
      }
    }

    return {
      '@context': _context,
      '@graph': graph,
    };
  }

  Map<String, String> _buildVendorElements(
    List<Package> packages,
    String base,
    String ciId,
    List<Map<String, dynamic>> graph,
  ) {
    final seen = <String, String>{};
    for (final pkg in packages) {
      if (!_hasValue(pkg.vendor) || seen.containsKey(pkg.vendor)) continue;
      final id = '$base#org-${_safeId(pkg.vendor)}';
      seen[pkg.vendor] = id;
      graph.add({
        'type': 'Organization',
        'spdxId': id,
        'creationInfo': ciId,
        'name': pkg.vendor,
      });
    }
    return seen;
  }

  /// Élément `software:primaryPurpose: "operatingSystem"` — voir [OsInfo].
  Map<String, dynamic> _osToElement(
    OsInfo os, {
    required String spdxId,
    required String ciId,
  }) {
    final elem = <String, dynamic>{
      'type': 'software:Package',
      'spdxId': spdxId,
      'creationInfo': ciId,
      'name': os.id,
      'software:packageVersion': os.version,
      'software:primaryPurpose': 'operatingSystem',
      'copyrightText': 'NOASSERTION',
    };
    if (_hasValue(os.prettyName ?? '')) elem['summary'] = os.prettyName;
    if (_hasValue(os.cpe ?? '')) {
      elem['externalIdentifier'] = [
        {'externalIdentifierType': 'cpe23', 'identifier': os.cpe},
      ];
    }
    return elem;
  }

  Map<String, dynamic> _packageToElement(
    Package pkg, {
    required String spdxId,
    required String ciId,
    String? vendorId,
    LayerAnnotations? layers,
  }) {
    final elem = <String, dynamic>{
      'type': 'software:Package',
      'spdxId': spdxId,
      'creationInfo': ciId,
      'name': pkg.name,
      'software:packageVersion': pkg.fullVersion,
      'software:primaryPurpose': 'library',
      'externalIdentifier': [
        {
          'externalIdentifierType': 'purl',
          'identifier': pkg.purl,
        }
      ],
    };

    if (_hasValue(pkg.summary)) elem['summary'] = pkg.summary;
    if (_hasValue(pkg.url)) elem['software:downloadLocation'] = pkg.url;

    if (pkg.hashes.isNotEmpty) {
      elem['verifiedUsing'] = [
        for (final h in pkg.hashes)
          {
            'type': 'Hash',
            'algorithm': spdx3Alg(h.alg),
            'hashValue': h.content,
          },
      ];
    }

    elem['concludedLicense'] = _normalizeLicense(pkg.license);
    elem['declaredLicense'] = _normalizeLicense(pkg.license);
    elem['copyrightText'] = 'NOASSERTION';

    if (vendorId != null) elem['suppliedBy'] = vendorId;

    final statement = [
      _annotationStatement(pkg),
      for (final e in (layers?.componentFields(pkg) ?? const {}).entries)
        '$layerPropertyPrefix${e.key}=${e.value}',
    ].where((c) => c.isNotEmpty).join('; ');
    if (statement.isNotEmpty) {
      elem['annotation'] = [
        {
          'type': 'Annotation',
          'annotationType': 'other',
          'subject': spdxId,
          'statement': statement,
        }
      ];
    }

    return elem;
  }

  String _annotationStatement(Package pkg) {
    if (pkg is RpmPackage) {
      return [
        'rpm:arch=${pkg.arch}',
        'rpm:release=${pkg.release}',
        if (pkg.epoch != '(none)' && pkg.epoch.isNotEmpty)
          'rpm:epoch=${pkg.epoch}',
        if (_hasValue(pkg.buildTime)) 'rpm:buildTime=${pkg.buildTime}',
        if (_hasValue(pkg.headerSha256))
          'rpm:header-sha256=${pkg.headerSha256}',
      ].join('; ');
    }
    if (pkg is DebPackage) return 'deb:arch=${pkg.arch}';
    if (pkg is WheelPackage) {
      final ns = pkg.packageType == 'pypi' ? 'pypi' : 'source';
      return '$ns:platform=${pkg.arch}';
    }
    return '';
  }

  String _normalizeLicense(String raw) {
    if (!_hasValue(raw)) return 'NOASSERTION';
    final expr = LicenseNormalizer.toSpdxExpression(raw);
    return expr.isNotEmpty ? expr : 'NOASSERTION';
  }

  bool _hasValue(String s) => s.isNotEmpty && s != '(none)';

  String _safeId(String s) =>
      s.replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '-').toLowerCase();

  Future<void> writeToFile(
    List<Package> packages,
    List<PackageDependency> dependencies,
    String outputPath, {
    String? documentName,
    OsInfo? osInfo,
    Map<String, String> sdkTools = const {},
    LayerAnnotations? layers,
  }) async {
    final sbom = generate(packages, dependencies,
        documentName: documentName,
        osInfo: osInfo,
        sdkTools: sdkTools,
        layers: layers);
    await File(outputPath)
        .writeAsString(JsonEncoder.withIndent('  ').convert(sbom));
  }
}
