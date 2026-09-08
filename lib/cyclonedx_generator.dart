import 'dart:convert';
import 'dart:io';
import 'license_normalizer.dart';
import 'models.dart';

/// A patent assertion to attach to a matching package's component, per the
/// CycloneDX 1.7 `patentAssertions` / `definitions.patents` structures.
///
/// Only meaningful when generating with [CycloneDxGenerator.supportedSpecVersions]
/// entry `'1.7'` — CycloneDX 1.6 has no patent-related fields.
class PatentAssertion {
  /// The patent number as granted by the issuing authority (e.g. `US1234567`).
  final String patentNumber;

  /// Two-letter jurisdiction / patent office code (WIPO ST.3), e.g. `US`, `EP`.
  final String jurisdiction;

  /// Legal status per the CycloneDX `patentLegalStatus` enum
  /// (pending, granted, revoked, expired, lapsed, withdrawn, abandoned,
  /// suspended, reinstated, opposed, terminated, invalidated, in-force).
  final String legalStatus;

  /// Nature of the assertion per the CycloneDX `assertionType` enum
  /// (ownership, license, third-party-claim, standards-inclusion, prior-art,
  /// exclusive-rights, non-assertion, research-or-evaluation).
  final String assertionType;

  const PatentAssertion({
    required this.patentNumber,
    required this.jurisdiction,
    required this.legalStatus,
    required this.assertionType,
  });

  static const validLegalStatuses = [
    'pending', 'granted', 'revoked', 'expired', 'lapsed', 'withdrawn',
    'abandoned', 'suspended', 'reinstated', 'opposed', 'terminated',
    'invalidated', 'in-force',
  ];

  static const validAssertionTypes = [
    'ownership', 'license', 'third-party-claim', 'standards-inclusion',
    'prior-art', 'exclusive-rights', 'non-assertion', 'research-or-evaluation',
  ];
}

/// Generates a CycloneDX JSON SBOM.
///
/// Supports CycloneDX 1.6 (default) and 1.7. Specification:
/// https://cyclonedx.org/specification/overview/
class CycloneDxGenerator {
  /// specVersion values this generator knows how to emit.
  static const supportedSpecVersions = ['1.6', '1.7'];

  /// Traffic Light Protocol classifications accepted by `--tlp` (1.7 only).
  static const validTlpClassifications = [
    'CLEAR', 'GREEN', 'AMBER', 'AMBER_AND_STRICT', 'RED',
  ];

  // ── Public API ─────────────────────────────────────────────────────────────

  Map<String, dynamic> generate(
    List<Package> packages,
    List<PackageDependency> dependencies, {
    String? documentName,
    String? author,
    String? organization,
    String specVersion = '1.6',
    String? tlp,
    String? citationSource,
    Map<String, PatentAssertion>? patentsByPackageName,

    /// OS de base de l'image de conteneur source (voir [OsInfo]), si connu.
    /// Ajoute un composant `type: "operating-system"` distinct des paquets
    /// applicatifs — nécessaire pour que des consommateurs comme Trivy en
    /// mode `trivy sbom` évaluent aussi les CVE des paquets système
    /// (RPM/DEB/APK), et pas seulement celles des paquets applicatifs.
    OsInfo? osInfo,

    /// SDK/toolchain ayant servi à produire l'artefact (`{'flutter': '3.47.2',
    /// 'dart': '3.9.0'}`), ajouté à `metadata.tools.components`. Vient de
    /// `--sdk-version` côté CLI.
    Map<String, String> sdkTools = const {},
  }) {
    if (!supportedSpecVersions.contains(specVersion)) {
      throw ArgumentError(
          'specVersion non supporté : "$specVersion" (valides : ${supportedSpecVersions.join(', ')})');
    }
    final is17 = specVersion == '1.7';
    final patents = patentsByPackageName ?? const {};

    if (!is17 && (tlp != null || citationSource != null || patents.isNotEmpty)) {
      throw ArgumentError(
          'tlp / citationSource / patentsByPackageName nécessitent specVersion="1.7" '
          '(CycloneDX 1.6 n\'a pas ces champs : le schéma 1.6 rejette les propriétés inconnues)');
    }
    if (tlp != null && !validTlpClassifications.contains(tlp)) {
      throw ArgumentError(
          'tlp invalide : "$tlp" (valides : ${validTlpClassifications.join(', ')})');
    }
    for (final p in patents.values) {
      if (!RegExp(r'^[A-Z]{2}$').hasMatch(p.jurisdiction)) {
        throw ArgumentError(
            'jurisdiction de brevet invalide : "${p.jurisdiction}" (2 lettres majuscules attendues, ex: US)');
      }
      if (!PatentAssertion.validLegalStatuses.contains(p.legalStatus)) {
        throw ArgumentError(
            'legalStatus de brevet invalide : "${p.legalStatus}" (valides : ${PatentAssertion.validLegalStatuses.join(', ')})');
      }
      if (!PatentAssertion.validAssertionTypes.contains(p.assertionType)) {
        throw ArgumentError(
            'assertionType de brevet invalide : "${p.assertionType}" (valides : ${PatentAssertion.validAssertionTypes.join(', ')})');
      }
    }

    final now = DateTime.now().toUtc().toIso8601String();
    final serialNumber = 'urn:uuid:${generateUuidV4()}';
    final orgName = organization ?? 'local';

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

    final result = {
      'bomFormat': 'CycloneDX',
      'specVersion': specVersion,
      'serialNumber': serialNumber,
      'version': 1,
      'metadata': _buildMetadata(now, documentName, author, organization,
          tlp: tlp, extraTool: citationSource, sdkTools: sdkTools),
      'components': [
        if (osInfo != null) _buildOsComponent(osInfo),
        for (final pkg in packages)
          _packageToComponent(pkg, patents[pkg.name], orgName),
      ],
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

    if (is17) {
      final patentDefs = _buildPatentDefinitions(packages, patents);
      if (patentDefs.isNotEmpty) {
        result['definitions'] = {'patents': patentDefs};
      }
      if (citationSource != null) {
        result['citations'] = [_buildCitation(now, citationSource)];
      }
    }

    return result;
  }

  Future<void> writeToFile(
    List<Package> packages,
    List<PackageDependency> dependencies,
    String outputPath, {
    String? documentName,
    String? author,
    String? organization,
    String specVersion = '1.6',
    String? tlp,
    String? citationSource,
    Map<String, PatentAssertion>? patentsByPackageName,
    OsInfo? osInfo,
    Map<String, String> sdkTools = const {},
  }) async {
    final sbom = generate(
      packages,
      dependencies,
      documentName: documentName,
      author: author,
      organization: organization,
      specVersion: specVersion,
      tlp: tlp,
      citationSource: citationSource,
      patentsByPackageName: patentsByPackageName,
      osInfo: osInfo,
      sdkTools: sdkTools,
    );
    await File(outputPath)
        .writeAsString(JsonEncoder.withIndent('  ').convert(sbom));
  }

  // ── Metadata ───────────────────────────────────────────────────────────────

  Map<String, dynamic> _buildMetadata(
    String timestamp,
    String? name,
    String? author,
    String? org, {
    String? tlp,
    String? extraTool,
    Map<String, String> sdkTools = const {},
  }) {
    final authorName = author ?? 'sbom_generator';
    final orgName = org ?? 'local';

    final tools = <Map<String, dynamic>>[
      {
        'type': 'application',
        'bom-ref': 'tool-sbom_generator',
        'name': 'sbom_generator',
        'version': '1.5.5',
      }
    ];
    if (extraTool != null && extraTool != 'sbom_generator') {
      tools.add({
        'type': 'application',
        'bom-ref': _toolBomRef(extraTool),
        'name': extraTool,
      });
    }
    // SDK/toolchain de build (Dart, Flutter…) — `type: platform` : ni une
    // application ni une lib, c'est l'environnement qui a produit l'artefact.
    sdkTools.forEach((name, version) {
      tools.add({
        'type': 'platform',
        'bom-ref': _toolBomRef('sdk-$name'),
        'name': name,
        if (version.isNotEmpty) 'version': version,
      });
    });

    final metadata = <String, dynamic>{
      'timestamp': timestamp,
      'lifecycles': [
        {'phase': 'operations'}
      ],
      'tools': {'components': tools},
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

    // CycloneDX 1.7+ only (schema 1.6 has no `distributionConstraints`).
    if (tlp != null) {
      metadata['distributionConstraints'] = {'tlp': tlp};
    }

    return metadata;
  }

  // ── Citations & patents (CycloneDX 1.7) ────────────────────────────────────

  Map<String, dynamic> _buildCitation(String timestamp, String source) => {
        'bom-ref': 'citation-components',
        'timestamp': timestamp,
        'attributedTo': _toolBomRef(source),
        'pointers': ['/components'],
        'note': 'Données de composants collectées via $source.',
      };

  List<Map<String, dynamic>> _buildPatentDefinitions(
      List<Package> packages, Map<String, PatentAssertion> patents) {
    final seenRefs = <String>{};
    final defs = <Map<String, dynamic>>[];
    for (final pkg in packages) {
      final patent = patents[pkg.name];
      if (patent == null) continue;
      final ref = _patentBomRef(patent.patentNumber);
      if (seenRefs.add(ref)) {
        defs.add({
          'bom-ref': ref,
          'patentNumber': patent.patentNumber,
          'jurisdiction': patent.jurisdiction,
          'patentLegalStatus': patent.legalStatus,
        });
      }
    }
    return defs;
  }

  String _toolBomRef(String toolName) => 'tool-${_cpeToken(toolName)}';

  String _patentBomRef(String patentNumber) =>
      'patent-${_cpeToken(patentNumber)}';

  // ── Composant OS de base (image de conteneur) ─────────────────────────────

  /// Composant `type: "operating-system"` distinct des paquets applicatifs —
  /// voir [OsInfo] pour la justification (nécessaire à Trivy en mode
  /// `trivy sbom` pour évaluer les CVE des paquets système).
  Map<String, dynamic> _buildOsComponent(OsInfo os) {
    final component = <String, dynamic>{
      'type': 'operating-system',
      'bom-ref': 'os-${_cpeToken(os.id)}',
      'name': os.id,
      'version': os.version,
    };
    if (_hasValue(os.prettyName ?? '')) {
      component['description'] = os.prettyName;
    }
    if (_hasValue(os.cpe ?? '')) {
      component['cpe'] = os.cpe;
    }
    return component;
  }

  // ── Component ──────────────────────────────────────────────────────────────

  Map<String, dynamic> _packageToComponent(
      Package pkg, PatentAssertion? patent, String orgName) {
    // Maven coordinates are stored as "groupId:artifactId" in pkg.name.
    // CycloneDX has a dedicated `group` field for exactly this (matching
    // what tools such as syft emit) — split it out instead of leaving the
    // groupId folded into `name`.
    final nameParts =
        pkg.packageType == 'maven' ? pkg.name.split(':') : const <String>[];
    final hasGroup = nameParts.length == 2 && nameParts[0].isNotEmpty;

    final component = <String, dynamic>{
      'type': 'library',
      'bom-ref': pkg.bomRef,
      if (hasGroup) 'group': nameParts[0],
      'name': hasGroup ? nameParts[1] : pkg.name,
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
          LicenseNormalizer.toCycloneDxLicensesConcluded(pkg.license);
    }

    // CycloneDX 1.7+ only (schema 1.6 has no `patentAssertions`).
    if (patent != null) {
      component['patentAssertions'] = [
        {
          'assertionType': patent.assertionType,
          // `url` (organization-only field) disambiguates the asserter from
          // an `organizationalContact` (person) for the schema's oneOf check
          // — both share every other field, so a bare {'name': ...} is
          // ambiguous and fails strict CycloneDX 1.7 validation.
          'asserter': {'name': orgName, 'url': <String>[]},
          'patentRefs': [_patentBomRef(patent.patentNumber)],
        }
      ];
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
