import 'dart:convert';
import 'dart:io';
import 'license_normalizer.dart';
import 'models.dart';

/// Generates a CycloneDX 1.6 JSON SBOM.
///
/// Specification: https://cyclonedx.org/specification/overview/
class CycloneDxGenerator {
  // ── Public API ─────────────────────────────────────────────────────────────

  Map<String, dynamic> generate(
    List<Package> packages,
    List<PackageDependency> dependencies, {
    String? documentName,
    String? author,
    String? organization,
  }) {
    final now = DateTime.now().toUtc().toIso8601String();
    final serialNumber = 'urn:uuid:${generateUuidV4()}';

    final depIndex = <String, List<String>>{
      for (final d in dependencies) d.sourceRef: d.dependsOn,
    };

    final rootDep = {
      'ref': 'root',
      'dependsOn': [for (final pkg in packages) pkg.bomRef],
    };

    final pkgDeps = [
      for (final pkg in packages)
        {
          'ref': pkg.bomRef,
          'dependsOn': depIndex[pkg.bomRef] ?? [],
        }
    ];

    final allBomRefs = [for (final pkg in packages) pkg.bomRef];

    return {
      'bomFormat': 'CycloneDX',
      'specVersion': '1.6',
      'serialNumber': serialNumber,
      'version': 1,
      'metadata': _buildMetadata(now, documentName, author, organization),
      'components': [for (final pkg in packages) _packageToComponent(pkg)],
      'dependencies': [rootDep, ...pkgDeps],
      'compositions': [
        {
          'bom-ref': 'composition-main',
          'aggregate': 'incomplete',
          'assemblies': ['root', ...allBomRefs],
          'dependencies': ['root', ...allBomRefs],
        },
      ],
    };
  }

  Future<void> writeToFile(
    List<Package> packages,
    List<PackageDependency> dependencies,
    String outputPath, {
    String? documentName,
    String? author,
    String? organization,
  }) async {
    final sbom = generate(packages, dependencies,
        documentName: documentName, author: author, organization: organization);
    await File(outputPath)
        .writeAsString(JsonEncoder.withIndent('  ').convert(sbom));
  }

  // ── Metadata ───────────────────────────────────────────────────────────────

  Map<String, dynamic> _buildMetadata(
    String timestamp,
    String? name,
    String? author,
    String? org,
  ) {
    final authorName = author ?? 'sbom_generator';
    final orgName = org ?? 'local';

    return {
      'timestamp': timestamp,
      'lifecycles': [
        {'phase': 'operations'}
      ],
      'tools': {
        'components': [
          {
            'type': 'application',
            'bom-ref': 'tool-sbom_generator',
            'name': 'sbom_generator',
            'version': '1.0.0',
          }
        ]
      },
      'authors': [
        {'name': authorName}
      ],
      'supplier': {'name': orgName},
      'licenses': [
        {
          'license': {'id': 'CC0-1.0'}
        }
      ],
      'component': {
        'type': 'container',
        'bom-ref': 'root',
        'name': name ?? 'Package Set',
        'version': '1.0',
      },
    };
  }

  // ── Component ──────────────────────────────────────────────────────────────

  Map<String, dynamic> _packageToComponent(Package pkg) {
    final component = <String, dynamic>{
      'type': 'library',
      'bom-ref': pkg.bomRef,
      'name': pkg.name,
      'version': pkg.fullVersion,
      'purl': pkg.purl,
    };

    if (_hasValue(pkg.summary)) {
      component['description'] = pkg.summary;
    }

    if (_hasValue(pkg.sha256Header)) {
      component['hashes'] = [
        {'alg': 'SHA-256', 'content': pkg.sha256Header},
      ];
    }

    if (_hasValue(pkg.license)) {
      component['licenses'] =
          LicenseNormalizer.toCycloneDxLicenses(pkg.license);
    }

    // CPE only makes practical sense for RPM packages (NVD uses distro CPEs)
    if (pkg is RpmPackage) {
      final cpe = _buildCpe(pkg);
      if (cpe.isNotEmpty) component['cpe'] = cpe;
    }

    if (_hasValue(pkg.vendor)) {
      component['supplier'] = {'name': pkg.vendor};
      component['publisher'] = pkg.vendor;
    }

    // ── External references ────────────────────────────────────────────────
    final externalRefs = <Map<String, dynamic>>[];

    if (_hasValue(pkg.url)) {
      externalRefs.add({'type': 'website', 'url': pkg.url});
    }

    if (pkg is RpmPackage && _hasValue(pkg.sourceRpm)) {
      final srcPkgName = _sourcePackageName(pkg.sourceRpm);
      externalRefs.add({
        'type': 'vcs',
        'url': 'https://src.fedoraproject.org/rpms/$srcPkgName',
        'comment': 'Source RPM: ${pkg.sourceRpm}',
      });
    }

    if (pkg.sourceRef.endsWith('.rpm') || pkg.sourceRef.endsWith('.whl')) {
      externalRefs.add({
        'type': 'distribution',
        'url': Uri.file(pkg.sourceRef).toString(),
      });
    }

    if (externalRefs.isNotEmpty) {
      component['externalReferences'] = externalRefs;
    }

    // ── Properties (package-type specific) ────────────────────────────────
    final properties = <Map<String, String>>[];

    if (pkg is RpmPackage) {
      properties.addAll([
        {'name': 'rpm:arch', 'value': pkg.arch},
        {'name': 'rpm:release', 'value': pkg.release},
        if (pkg.epoch != '(none)' && pkg.epoch.isNotEmpty)
          {'name': 'rpm:epoch', 'value': pkg.epoch},
        if (_hasValue(pkg.buildTime))
          {'name': 'rpm:buildTime', 'value': pkg.buildTime},
      ]);
      for (final req in pkg.requires) {
        properties.add({'name': 'rpm:requires', 'value': req});
      }
    } else if (pkg is DebPackage) {
      properties.add({'name': 'deb:arch', 'value': pkg.arch});
      for (final req in pkg.requires) {
        properties.add({'name': 'deb:depends', 'value': req});
      }
    } else if (pkg is WheelPackage) {
      final ns = pkg.packageType == 'pypi' ? 'pypi' : 'source';
      properties.add({'name': '$ns:platform', 'value': pkg.arch});
      for (final req in pkg.requires) {
        properties.add({'name': '$ns:requires', 'value': req});
      }
    }

    if (properties.isNotEmpty) {
      component['properties'] = properties;
    }

    return component;
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  String _buildCpe(RpmPackage pkg) {
    final product = _cpeToken(pkg.name);
    if (product.isEmpty) return '';
    final vendor = _hasValue(pkg.vendor) ? _vendorToCpe(pkg.vendor) : product;
    final version = _cpeToken(pkg.version);
    if (version.isEmpty) return '';
    return 'cpe:2.3:a:$vendor:$product:$version:*:*:*:*:*:*:*';
  }

  String _cpeToken(String s) => s
      .toLowerCase()
      .replaceAll(RegExp(r'[^a-z0-9._-]'), '_')
      .replaceAll(RegExp(r'_+'), '_')
      .replaceAll(RegExp(r'^_+|_+$'), '');

  String _vendorToCpe(String vendor) {
    final v = vendor.toLowerCase();
    if (v.contains('red hat')) return 'redhat';
    if (v.contains('fedora')) return 'fedoraproject';
    if (v.contains('gnu')) return 'gnu';
    if (v.contains('apache')) return 'apache';
    if (v.contains('google')) return 'google';
    if (v.contains('microsoft')) return 'microsoft';
    if (v.contains('mozilla')) return 'mozilla';
    if (v.contains('canonical')) return 'canonical';
    if (v.contains('debian')) return 'debian';
    if (v.contains('suse') || v.contains('novell')) return 'novell';
    return _cpeToken(vendor);
  }

  bool _hasValue(String s) => s.isNotEmpty && s != '(none)';

  String _sourcePackageName(String sourceRpm) {
    final stripped = sourceRpm.replaceAll(RegExp(r'\.src\.rpm$'), '');
    final parts = stripped.split('-');
    return parts.length > 2
        ? parts.sublist(0, parts.length - 2).join('-')
        : stripped;
  }
}
