import 'dart:convert';
import 'dart:io';
import 'models.dart';

/// Generates an SPDX 2.3 JSON SBOM.
///
/// Specification: https://spdx.github.io/spdx-spec/v2.3/
class SpdxGenerator {
  Map<String, dynamic> generate(
    List<Package> packages,
    List<PackageDependency> dependencies, {
    String? documentName,
  }) {
    final now = DateTime.now().toUtc().toIso8601String();
    final docUuid = generateUuidV4();
    final docNamespace = 'https://sbom.local/spdx/$docUuid';

    final refToSpdxId = <String, String>{
      for (final pkg in packages) pkg.bomRef: pkg.spdxId,
    };

    final relationships =
        _buildRelationships(packages, dependencies, refToSpdxId);

    return {
      'SPDXID': 'SPDXRef-DOCUMENT',
      'spdxVersion': 'SPDX-2.3',
      'creationInfo': {
        'created': now,
        'creators': ['Tool: sbom_generator-1.0.0'],
        'licenseListVersion': '3.21',
      },
      'name': documentName ?? 'Package Set SBOM',
      'dataLicense': 'CC0-1.0',
      'documentNamespace': docNamespace,
      'packages': [for (final pkg in packages) _packageToSpdx(pkg)],
      'relationships': relationships,
    };
  }

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

  Map<String, dynamic> _packageToSpdx(Package pkg) {
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
      'licenseConcluded': _hasValue(pkg.license) ? pkg.license : 'NOASSERTION',
      'licenseDeclared': _hasValue(pkg.license) ? pkg.license : 'NOASSERTION',
      'copyrightText': 'NOASSERTION',
    };

    if (_hasValue(pkg.summary)) spdxPkg['summary'] = pkg.summary;

    if (_hasValue(pkg.vendor)) {
      spdxPkg['supplier'] = 'Organization: ${pkg.vendor}';
    }

    // Package-type specific metadata as annotation comment
    final comment = _annotationComment(pkg);
    if (comment.isNotEmpty) {
      spdxPkg['annotations'] = [
        {
          'annotationType': 'OTHER',
          'annotator': 'Tool: sbom_generator-1.0.0',
          'annotationDate': DateTime.now().toUtc().toIso8601String(),
          'comment': comment,
        }
      ];
    }

    return spdxPkg;
  }

  String _annotationComment(Package pkg) {
    if (pkg is RpmPackage) {
      return 'arch=${pkg.arch}; epoch=${pkg.epoch}; release=${pkg.release}'
          '${_hasValue(pkg.buildTime) ? "; buildTime=${pkg.buildTime}" : ""}';
    }
    if (pkg is WheelPackage) {
      final ns = pkg.packageType == 'pypi' ? 'pypi' : 'source';
      return '$ns:platform=${pkg.arch}';
    }
    return '';
  }

  bool _hasValue(String s) => s.isNotEmpty && s != '(none)';

  Future<void> writeToFile(
    List<Package> packages,
    List<PackageDependency> dependencies,
    String outputPath, {
    String? documentName,
  }) async {
    final sbom = generate(packages, dependencies, documentName: documentName);
    await File(outputPath)
        .writeAsString(JsonEncoder.withIndent('  ').convert(sbom));
  }
}
