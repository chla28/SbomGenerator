import 'dart:convert';
import 'dart:io';
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
      component['licenses'] = _buildLicenses(pkg.license);
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

  // ── License normalisation ──────────────────────────────────────────────────

  static const _rpmToSpdx = <String, String>{
    // GPL family
    'GPL': 'GPL-2.0-only',
    'GPL+': 'GPL-2.0-or-later',
    'GPL-2.0': 'GPL-2.0-only',
    'GPL-2.0+': 'GPL-2.0-or-later',
    'GPLv2': 'GPL-2.0-only',
    'GPLv2+': 'GPL-2.0-or-later',
    'GPL-3.0': 'GPL-3.0-only',
    'GPL-3.0+': 'GPL-3.0-or-later',
    'GPLv3': 'GPL-3.0-only',
    'GPLv3+': 'GPL-3.0-or-later',
    // LGPL family
    'LGPL': 'LGPL-2.0-only',
    'LGPLv2': 'LGPL-2.0-only',
    'LGPLv2+': 'LGPL-2.0-or-later',
    'LGPL-2.0': 'LGPL-2.0-only',
    'LGPL-2.0+': 'LGPL-2.0-or-later',
    'LGPLv2.1': 'LGPL-2.1-only',
    'LGPLv2.1+': 'LGPL-2.1-or-later',
    'LGPL-2.1': 'LGPL-2.1-only',
    'LGPL-2.1+': 'LGPL-2.1-or-later',
    'LGPLv3': 'LGPL-3.0-only',
    'LGPLv3+': 'LGPL-3.0-or-later',
    'LGPL-3.0': 'LGPL-3.0-only',
    'LGPL-3.0+': 'LGPL-3.0-or-later',
    // Apache / MIT / BSD
    'ASL 1.1': 'Apache-1.1',
    'ASL 2.0': 'Apache-2.0',
    'ASL2.0': 'Apache-2.0',
    'Apache 2.0': 'Apache-2.0',
    'Apache-2.0': 'Apache-2.0',
    'Apache Software License': 'Apache-2.0',
    'MIT': 'MIT',
    'MIT License': 'MIT',
    'MIT-0': 'MIT-0',
    'ISC': 'ISC',
    'BSD': 'BSD-2-Clause',
    'BSD License': 'BSD-2-Clause',
    'BSD 2-Clause': 'BSD-2-Clause',
    'BSD-2-Clause': 'BSD-2-Clause',
    'BSD 3-Clause': 'BSD-3-Clause',
    'BSD-3-Clause': 'BSD-3-Clause',
    'BSD 4-Clause': 'BSD-4-Clause',
    // Mozilla
    'MPLv1.1': 'MPL-1.1',
    'MPL-1.1': 'MPL-1.1',
    'MPLv2.0': 'MPL-2.0',
    'MPL-2.0': 'MPL-2.0',
    'MPL': 'MPL-2.0',
    // CDDL / CPL / EPL
    'CDDL': 'CDDL-1.0',
    'CDDLv1.0': 'CDDL-1.0',
    'CDDL-1.0': 'CDDL-1.0',
    'CPL': 'CPL-1.0',
    'CPL-1.0': 'CPL-1.0',
    'EPLv1.0': 'EPL-1.0',
    'EPL-1.0': 'EPL-1.0',
    'EPLv2.0': 'EPL-2.0',
    'EPL-2.0': 'EPL-2.0',
    // Artistic / Perl
    'Artistic': 'Artistic-1.0',
    'Artistic-1.0': 'Artistic-1.0',
    'Artistic 2.0': 'Artistic-2.0',
    'Artistic-2.0': 'Artistic-2.0',
    'Perl': 'Artistic-1.0',
    // Python / Ruby / others
    'Python': 'Python-2.0',
    'Python-2.0': 'Python-2.0',
    'Ruby': 'Ruby',
    'WTFPL': 'WTFPL',
    'Unlicense': 'Unlicense',
    'CC0': 'CC0-1.0',
    'CC0-1.0': 'CC0-1.0',
    'CC BY 4.0': 'CC-BY-4.0',
    'OFL': 'OFL-1.1',
    'OFL-1.1': 'OFL-1.1',
    'SIL OFL 1.1': 'OFL-1.1',
    'ZPLv2.0': 'ZPL-2.0',
    'ZPL-2.0': 'ZPL-2.0',
    'EUPL 1.1': 'EUPL-1.1',
    'EUPL-1.1': 'EUPL-1.1',
    'EUPL 1.2': 'EUPL-1.2',
    'EUPL-1.2': 'EUPL-1.2',
    'FTL': 'FTL',
    'FSFUL': 'LicenseRef-FSFUL',
    'FSFAP': 'FSFAP',
    'HPND': 'HPND',
    'NLPL': 'NLPL',
    'OpenLDAP': 'OLDAP-2.8',
    'Sleepycat': 'Sleepycat',
    'Boost': 'BSL-1.0',
    'zlib': 'Zlib',
    'Zlib': 'Zlib',
    'Public Domain': 'LicenseRef-PublicDomain',
    'PublicDomain': 'LicenseRef-PublicDomain',
    'public domain': 'LicenseRef-PublicDomain',
  };

  List<Map<String, dynamic>> _buildLicenses(String licenseStr) {
    final s = licenseStr.trim();
    if (s.isEmpty || s == '(none)') return [];

    final normalised = s
        .replaceAll(RegExp(r'(?<=\S)\s+and\s+(?=\S)', caseSensitive: false), ' AND ')
        .replaceAll(RegExp(r'(?<=\S)\s+or\s+(?=\S)', caseSensitive: false), ' OR ')
        .replaceAll(RegExp(r'(?<=\S)\s+with\s+(?=\S)', caseSensitive: false), ' WITH ');

    final isCompound = normalised.contains(' AND ') ||
        normalised.contains(' OR ') ||
        normalised.contains(' WITH ');

    if (isCompound) {
      return [{'expression': _normaliseExpressionTokens(normalised)}];
    }

    final mapped = _rpmToSpdx[s] ?? s;

    if (_looksLikeSpdxId(mapped)) {
      if (mapped.startsWith('LicenseRef-')) {
        return [{'license': {'name': s}}];
      }
      final fromTable = _rpmToSpdx.containsKey(s);
      final isVersioned = mapped.contains(RegExp(r'-\d'));
      if (fromTable || isVersioned) {
        return [{'license': {'id': mapped}}];
      }
    }

    return [
      {'license': {'name': s}}
    ];
  }

  String _normaliseExpressionTokens(String expr) {
    final sorted = _rpmToSpdx.entries.toList()
      ..sort((a, b) => b.key.length.compareTo(a.key.length));
    var result = expr;
    for (final e in sorted) {
      final pattern =
          RegExp('(?<![A-Za-z0-9._-])${RegExp.escape(e.key)}(?![A-Za-z0-9._-])');
      result = result.replaceAll(pattern, e.value);
    }
    return result.trim();
  }

  bool _looksLikeSpdxId(String s) =>
      s.isNotEmpty &&
      !s.contains(' ') &&
      RegExp(r'^[A-Za-z0-9][A-Za-z0-9.+\-]+$').hasMatch(s);

  // ── Helpers ────────────────────────────────────────────────────────────────

  String _buildCpe(RpmPackage pkg) {
    final product = _cpeToken(pkg.name);
    if (product.isEmpty) return '';
    final vendor = _hasValue(pkg.vendor)
        ? _vendorToCpe(pkg.vendor)
        : product;
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
    return parts.length > 2 ? parts.sublist(0, parts.length - 2).join('-') : stripped;
  }
}
