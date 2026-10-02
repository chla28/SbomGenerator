import 'dart:convert';
import 'dart:io';
import 'image_layers.dart';
import 'nested_archive.dart';
import 'models.dart';

/// Generates a human-friendly, custom JSON SBOM.
class SimpleJsonGenerator {
  Map<String, dynamic> generate(
    List<Package> packages,
    List<PackageDependency> dependencies, {
    String? documentName,
    LayerAnnotations? layers,
  }) {
    final now = DateTime.now().toUtc().toIso8601String();

    final depIndex = <String, List<String>>{
      for (final d in dependencies) d.sourceRef: d.dependsOn,
    };

    final refToName = <String, String>{
      for (final pkg in packages) pkg.bomRef: pkg.name,
    };

    final pkgList = packages.map((pkg) {
      final resolvedDeps = (depIndex[pkg.bomRef] ?? [])
          .map((ref) => refToName[ref] ?? ref)
          .toList()
        ..sort();

      final base = <String, dynamic>{
        'packageType': pkg.packageType,
        'ref': pkg.bomRef,
        'purl': pkg.purl,
        'name': pkg.name,
        'version': pkg.fullVersion,
        'arch': pkg.arch,
        'summary': pkg.summary,
        'license': pkg.license,
        'vendor': pkg.vendor,
        'url': pkg.url,
        'requires': pkg.requires,
        'provides': pkg.provides,
        'resolvedDependencies': resolvedDeps,
      };

      // RPM-specific fields
      if (pkg is RpmPackage) {
        base['release'] = pkg.release;
        base['epoch'] = pkg.epoch;
        base['buildTime'] = pkg.buildTime;
      }

      final layerFields = layers?.componentFields(pkg) ?? const {};
      if (layerFields.isNotEmpty) base['layer'] = layerFields;
      final nested = nestedFields(pkg);
      if (nested.isNotEmpty) base['nested'] = nested;

      return base;
    }).toList();

    final depGraph = packages.map((pkg) {
      return {
        'package': pkg.name,
        'ref': pkg.bomRef,
        'dependsOn': (depIndex[pkg.bomRef] ?? [])
            .map((ref) => {
                  'name': refToName[ref] ?? ref,
                  'ref': ref,
                })
            .toList(),
      };
    }).toList();

    final totalRelationships =
        dependencies.fold<int>(0, (sum, d) => sum + d.dependsOn.length);

    return {
      'bomFormat': 'sbom-json',
      'formatVersion': '1.0',
      'generated': now,
      'name': documentName ?? 'Package Set',
      'statistics': {
        'packageCount': packages.length,
        'dependencyRelationships': totalRelationships,
      },
      'packages': pkgList,
      'dependencyGraph': depGraph,
      if (layers != null) ..._layersJson(layers),
    };
  }

  Map<String, dynamic> _layersJson(LayerAnnotations l) {
    final self = l.self;
    if (self == null) {
      return {
        'layers': {
          'mode': l.mode,
          'items': [for (final s in l.layers) s.toJson()],
        },
      };
    }
    return {
      'layer': {
        'mode': l.mode,
        ...self.toJson(),
        'globalFile': l.globalFileBase,
        'removed': [
          for (final p in l.removed)
            {'ref': p.bomRef, 'name': p.name, 'version': p.fullVersion},
        ],
      },
    };
  }

  Future<void> writeToFile(
    List<Package> packages,
    List<PackageDependency> dependencies,
    String outputPath, {
    String? documentName,
    LayerAnnotations? layers,
  }) async {
    final sbom = generate(packages, dependencies,
        documentName: documentName, layers: layers);
    await File(outputPath)
        .writeAsString(JsonEncoder.withIndent('  ').convert(sbom));
  }
}
