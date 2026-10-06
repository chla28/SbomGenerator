import 'dart:convert';
import 'dart:io';
import 'hash_utils.dart' show spdx2Alg;
import 'image_layers.dart';
import 'nested_archive.dart';
import 'license_normalizer.dart';
import 'models.dart';

/// Generates an SPDX 2.3 JSON SBOM.
///
/// Specification: https://spdx.github.io/spdx-spec/v2.3/
class SpdxGenerator {
  Map<String, dynamic> generate(
    List<Package> packages,
    List<PackageDependency> dependencies, {
    String? documentName,

    /// OS de base de l'image de conteneur source (voir [OsInfo]), si connu.
    /// Ajoute un paquet `primaryPackagePurpose: "OPERATING-SYSTEM"` distinct
    /// des paquets applicatifs — même justification que côté CycloneDX (voir
    /// `CycloneDxGenerator.generate`) : sans lui, Trivy en mode `trivy sbom`
    /// n'évalue pas les CVE des paquets système.
    OsInfo? osInfo,

    /// SDK/toolchain de build (`{'flutter': '3.47.2', 'dart': '3.9.0'}`),
    /// ajouté aux `creationInfo.creators` sous forme `Tool: <nom>-<version>`.
    Map<String, String> sdkTools = const {},

    /// Analyse par couche (`--per-layer`) : description de la couche ou des
    /// couches en commentaire du document, couche d'origine / changement en
    /// annotation de chaque paquet.
    LayerAnnotations? layers,
  }) {
    final now = _spdxTimestamp();
    final docUuid = layers?.documentUuid ?? generateUuidV4();
    final docNamespace = 'https://sbom.local/spdx/$docUuid';

    final refToSpdxId = <String, String>{
      for (final pkg in packages) pkg.bomRef: pkg.spdxId,
    };

    final relationships =
        _buildRelationships(packages, dependencies, refToSpdxId);
    if (osInfo != null) {
      relationships.insert(0, {
        'spdxElementId': 'SPDXRef-DOCUMENT',
        'relationshipType': 'DESCRIBES',
        'relatedSpdxElement': _osSpdxId(osInfo),
      });
    }

    return {
      'SPDXID': 'SPDXRef-DOCUMENT',
      'spdxVersion': 'SPDX-2.3',
      'creationInfo': {
        'created': now,
        'creators': [
          'Tool: sbom_generator-1.7.0',
          for (final e in sdkTools.entries)
            'Tool: ${e.key}${e.value.isEmpty ? '' : '-${e.value}'}',
        ],
        'licenseListVersion': '3.21',
      },
      'name': _documentTitle(documentName ?? 'Package Set SBOM', layers),
      'dataLicense': 'CC0-1.0',
      'documentNamespace': docNamespace,
      if (layers != null) 'comment': layers.describe().join('\n'),
      'packages': [
        if (osInfo != null) _osToSpdx(osInfo),
        for (final pkg in packages) _packageToSpdx(pkg, layers),
      ],
      'relationships': relationships,
    };
  }

  // ── OS de base (image de conteneur) ───────────────────────────────────────

  // Le préfixe `SPDXRef-OperatingSystem-` (plutôt que `SPDXRef-Package-`)
  // est ce que Trivy reconnaît pour associer ce paquet à la classe de
  // vulnérabilités "os-pkgs" en mode `trivy sbom` — vérifié empiriquement :
  // `primaryPackagePurpose: "OPERATING-SYSTEM"` seul, avec un SPDXID
  // `SPDXRef-Package-...`, ne suffit pas (0 CVE os-pkgs détectée) ; changer
  // uniquement le préfixe du SPDXID en `SPDXRef-OperatingSystem-` suffit.
  // Suit la convention observée dans la sortie SPDX native de trivy
  // (`SPDXRef-OperatingSystem-<hash>`).
  String _osSpdxId(OsInfo os) =>
      'SPDXRef-OperatingSystem-${_safeId(os.id).replaceAll('_', '-')}';

  /// Paquet `primaryPackagePurpose: "OPERATING-SYSTEM"` — voir [OsInfo].
  Map<String, dynamic> _osToSpdx(OsInfo os) {
    final pkg = <String, dynamic>{
      'SPDXID': _osSpdxId(os),
      'name': os.id,
      'versionInfo': os.version,
      'downloadLocation': 'NOASSERTION',
      'supplier': 'NOASSERTION',
      'filesAnalyzed': false,
      'primaryPackagePurpose': 'OPERATING-SYSTEM',
      'licenseConcluded': 'NOASSERTION',
      'licenseDeclared': 'NOASSERTION',
      'copyrightText': 'NOASSERTION',
    };
    if (_hasValue(os.prettyName ?? '')) pkg['summary'] = os.prettyName;
    if (_hasValue(os.cpe ?? '')) {
      pkg['externalRefs'] = [
        {
          'referenceCategory': 'SECURITY',
          'referenceType': 'cpe23Type',
          'referenceLocator': os.cpe,
        }
      ];
    }
    return pkg;
  }

  String _safeId(String s) => s.replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '-');

  List<Map<String, dynamic>> _buildRelationships(
    List<Package> packages,
    List<PackageDependency> dependencies,
    Map<String, String> refToSpdxId,
  ) {
    final rels = <Map<String, dynamic>>[];

    for (final pkg in packages) {
      rels.add({
        'spdxElementId': 'SPDXRef-DOCUMENT',
        'relationshipType': 'DESCRIBES',
        'relatedSpdxElement': pkg.spdxId,
      });
    }

    for (final dep in dependencies) {
      final sourceSpdxId = refToSpdxId[dep.sourceRef];
      if (sourceSpdxId == null) continue;
      for (final targetRef in dep.dependsOn) {
        final targetSpdxId = refToSpdxId[targetRef];
        if (targetSpdxId == null) continue;
        rels.add({
          'spdxElementId': sourceSpdxId,
          'relationshipType': 'DEPENDS_ON',
          'relatedSpdxElement': targetSpdxId,
        });
      }
    }

    return rels;
  }

  String _documentTitle(String name, LayerAnnotations? layers) =>
      layers?.isLayerDocument == true ? '$name — ${layers!.layerLabel}' : name;

  Map<String, dynamic> _packageToSpdx(Package pkg, LayerAnnotations? layers) {
    final spdxPkg = <String, dynamic>{
      'SPDXID': pkg.spdxId,
      'name': pkg.name,
      'versionInfo': pkg.fullVersion,
      'downloadLocation': _hasValue(pkg.url) ? pkg.url : 'NOASSERTION',
      'filesAnalyzed': false,
      'externalRefs': [
        {
          'referenceCategory': 'PACKAGE-MANAGER',
          'referenceType': 'purl',
          'referenceLocator': pkg.purl,
        }
      ],
      'licenseConcluded': _normalizeLicense(pkg.license),
      'licenseDeclared': _normalizeLicense(pkg.license),
      'copyrightText': 'NOASSERTION',
    };

    if (_hasValue(pkg.summary)) spdxPkg['summary'] = pkg.summary;

    if (pkg.hashes.isNotEmpty) {
      spdxPkg['checksums'] = [
        for (final h in pkg.hashes)
          {'algorithm': spdx2Alg(h.alg), 'checksumValue': h.content},
      ];
    }

    // SPDX 2.3 : `supplier` a une cardinalité 0..1 mais la spéc demande
    // `NOASSERTION` explicite quand le fournisseur est inconnu (plutôt que
    // d'omettre le champ) — c'est aussi ce qu'attendent NTIA / sbomqs.
    spdxPkg['supplier'] =
        _hasValue(pkg.vendor) ? 'Organization: ${pkg.vendor}' : 'NOASSERTION';

    // Package-type specific metadata as annotation comment
    final comment = [
      _annotationComment(pkg),
      for (final e in (layers?.componentFields(pkg) ?? const {}).entries)
        '$layerPropertyPrefix${e.key}=${e.value}',
      for (final e in nestedFields(pkg).entries)
        '$nestedPropertyPrefix${e.key}=${e.value}',
    ].where((c) => c.isNotEmpty).join('; ');
    if (comment.isNotEmpty) {
      spdxPkg['annotations'] = [
        {
          'annotationType': 'OTHER',
          'annotator': 'Tool: sbom_generator-1.7.0',
          'annotationDate': _spdxTimestamp(),
          'comment': comment,
        }
      ];
    }

    return spdxPkg;
  }

  String _annotationComment(Package pkg) {
    if (pkg is RpmPackage) {
      return 'arch=${pkg.arch}; epoch=${pkg.epoch}; release=${pkg.release}'
          '${_hasValue(pkg.buildTime) ? "; buildTime=${pkg.buildTime}" : ""}'
          '${_hasValue(pkg.headerSha256) ? "; rpm:header-sha256=${pkg.headerSha256}" : ""}';
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

/// Horodatage SPDX : `AAAA-MM-JJThh:mm:ssZ` (sans fraction de seconde, comme
/// l'exige le schéma SPDX).
String _spdxTimestamp() => DateTime.now()
    .toUtc()
    .toIso8601String()
    .replaceFirst(RegExp(r'\.\d+Z$'), 'Z');
