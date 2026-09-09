import 'dart:convert';
import 'dart:io';
import 'hash_utils.dart'
    show hashesFromCycloneDx, packageHash;
import 'models.dart';

/// Detected format of a SBOM file.
enum SbomFormat { cyclonedx, spdx2, spdx3, unknown }

/// Reads a SBOM JSON/JSON-LD file and reconstructs [Package] objects.
///
/// Used by the `convert` sub-command to round-trip between formats.
class SbomReader {
  static SbomFormat detectFormat(Map<String, dynamic> json) {
    if (json['bomFormat'] == 'CycloneDX') return SbomFormat.cyclonedx;
    final ver = json['spdxVersion'];
    if (ver is String && ver.startsWith('SPDX-')) return SbomFormat.spdx2;
    if (json.containsKey('@context') && json.containsKey('@graph')) {
      return SbomFormat.spdx3;
    }
    return SbomFormat.unknown;
  }

  static Future<Map<String, dynamic>> loadJson(String path) async {
    final content = await File(path).readAsString();
    return jsonDecode(content) as Map<String, dynamic>;
  }

  /// Reconstructs packages from [json]. Throws if format is unknown.
  List<Package> read(Map<String, dynamic> json) => switch (detectFormat(json)) {
        SbomFormat.cyclonedx => _readCycloneDx(json),
        SbomFormat.spdx2 => _readSpdx2(json),
        SbomFormat.spdx3 => _readSpdx3(json),
        SbomFormat.unknown =>
          throw Exception('Format SBOM non reconnu dans le fichier fourni.'),
      };

  /// Extracts the document name from the SBOM metadata.
  String? documentName(Map<String, dynamic> json) {
    switch (detectFormat(json)) {
      case SbomFormat.cyclonedx:
        final meta = json['metadata'] as Map<String, dynamic>?;
        final comp = meta?['component'] as Map<String, dynamic>?;
        return comp?['name'] as String?;
      case SbomFormat.spdx2:
        return json['name'] as String?;
      case SbomFormat.spdx3:
        final graph = json['@graph'] as List?;
        if (graph == null) return null;
        for (final node in graph.whereType<Map<String, dynamic>>()) {
          if (node['type'] == 'SpdxDocument') {
            return node['name'] as String?;
          }
        }
        return null;
      case SbomFormat.unknown:
        return null;
    }
  }

  // ── CycloneDX 1.x ─────────────────────────────────────────────────────────

  List<Package> _readCycloneDx(Map<String, dynamic> json) {
    final components = (json['components'] as List?) ?? [];
    return [
      for (final c in components.whereType<Map<String, dynamic>>())
        _cdxComponent(c),
    ];
  }

  Package _cdxComponent(Map<String, dynamic> c) {
    final rawName = (c['name'] as String?) ?? '';
    final version = (c['version'] as String?) ?? '';
    final purl = (c['purl'] as String?) ?? '';
    final description = (c['description'] as String?) ?? '';
    final packageType = _purlToType(purl);

    // Maven components store groupId in the dedicated CycloneDX `group`
    // field (see cyclonedx_generator.dart) rather than folded into `name`.
    // Recombine them into the "groupId:artifactId" convention used
    // internally by WheelPackage(packageType: 'maven') so groupId isn't
    // silently dropped when re-reading a document we (or another tool)
    // generated this way.
    final group = (c['group'] as String?) ?? '';
    final name = (packageType == 'maven' && group.isNotEmpty)
        ? '$group:$rawName'
        : rawName;

    String license = '';
    final licenses = c['licenses'] as List?;
    if (licenses != null && licenses.isNotEmpty) {
      final entries = licenses.whereType<Map<String, dynamic>>().toList();
      // Prefer the entry tagged "declared" (CycloneDX 1.5+
      // `license.acknowledgement`) — LicenseNormalizer.
      // toCycloneDxLicensesConcluded always stores the complete raw
      // license string there, even when the "concluded" determination is
      // split into several entries for a compound AND license. Falls back
      // to the first entry for SBOMs without that tag (older exports, or
      // produced by another tool).
      Map<String, dynamic>? declared;
      for (final entry in entries) {
        final ack = entry['acknowledgement'] ??
            (entry['license'] as Map<String, dynamic>?)?['acknowledgement'];
        if (ack == 'declared') {
          declared = entry;
          break;
        }
      }
      final chosen = declared ?? entries.first;
      final expr = chosen['expression'] as String?;
      final licObj = chosen['license'] as Map<String, dynamic>?;
      license = expr ??
          (licObj?['id'] as String?) ??
          (licObj?['name'] as String?) ??
          '';
    }

    final supplier = c['supplier'] as Map<String, dynamic>?;
    final vendor = (supplier?['name'] as String?) ?? '';

    String url = '';
    final extRefs = c['externalReferences'] as List?;
    if (extRefs != null) {
      for (final r in extRefs.whereType<Map<String, dynamic>>()) {
        if (r['type'] == 'website') {
          url = (r['url'] as String?) ?? '';
          break;
        }
      }
    }

    return WheelPackage(
      name: name,
      version: version,
      license: license,
      url: url,
      summary: description,
      vendor: vendor,
      arch: 'any',
      sourceRef: '',
      hashes: hashesFromCycloneDx(c['hashes']),
      requires: [],
      provides: [name],
      packageType: packageType,
    );
  }

  // ── SPDX 2.3 ──────────────────────────────────────────────────────────────

  List<Package> _readSpdx2(Map<String, dynamic> json) {
    final packages = (json['packages'] as List?) ?? [];
    return [
      for (final p in packages.whereType<Map<String, dynamic>>())
        _spdx2Package(p),
    ];
  }

  Package _spdx2Package(Map<String, dynamic> p) {
    final name = (p['name'] as String?) ?? '';
    final version = (p['versionInfo'] as String?) ?? '';
    final concluded = (p['licenseConcluded'] as String?) ?? '';
    final declared = (p['licenseDeclared'] as String?) ?? '';
    final license = _spdxLicense(concluded.isNotEmpty ? concluded : declared);
    final url = (p['homepage'] as String?) ?? '';
    final summary = (p['summary'] as String?) ?? '';
    var vendor = (p['supplier'] as String?) ?? '';
    vendor = vendor.replaceAll(RegExp(r'^(Organization|Tool|Person):\s*'), '');

    final purl = _spdx2Purl(p) ?? '';

    return WheelPackage(
      name: name,
      version: version,
      license: license,
      url: url,
      summary: summary,
      vendor: vendor,
      arch: 'any',
      sourceRef: '',
      hashes: _spdxChecksums(p['checksums']),
      requires: [],
      provides: [name],
      packageType: _purlToType(purl),
    );
  }

  /// Relit un tableau SPDX `checksums` (`[{algorithm, checksumValue}]`).
  List<PackageHash> _spdxChecksums(Object? node) {
    if (node is! List) return const [];
    final out = <PackageHash>[];
    for (final c in node.whereType<Map<String, dynamic>>()) {
      final h = packageHash(
          (c['algorithm'] as String?) ?? '', (c['checksumValue'] as String?) ?? '');
      if (h != null && !out.contains(h)) out.add(h);
    }
    return out;
  }

  String? _spdx2Purl(Map<String, dynamic> p) {
    final extRefs = p['externalRefs'] as List?;
    if (extRefs == null) return null;
    for (final r in extRefs.whereType<Map<String, dynamic>>()) {
      if (r['referenceType'] == 'purl') return r['referenceLocator'] as String?;
    }
    return null;
  }

  // ── SPDX 3.0 ──────────────────────────────────────────────────────────────

  List<Package> _readSpdx3(Map<String, dynamic> json) {
    final graph = (json['@graph'] as List?) ?? [];
    return [
      for (final node in graph.whereType<Map<String, dynamic>>())
        if (_isSpdx3Package(node['type'])) _spdx3Package(node),
    ];
  }

  /// `type` d'un élément paquet SPDX 3.0. Le générateur émet `software:Package`
  /// (forme préfixée du contexte JSON-LD) ; on tolère aussi la forme aplatie
  /// `software_Package` et une valeur `type` sous forme de liste.
  bool _isSpdx3Package(Object? type) {
    bool match(Object? t) => t == 'software:Package' || t == 'software_Package';
    return type is List ? type.any(match) : match(type);
  }

  Package _spdx3Package(Map<String, dynamic> node) {
    // Le générateur émet les champs `software:` préfixés (forme du contexte
    // JSON-LD) ; on tolère aussi la forme aplatie `software_` et sans préfixe.
    String prop(String local) =>
        (node['software:$local'] ??
                node['software_$local'] ??
                node[local]) as String? ??
            '';
    final name = (node['name'] as String?) ?? '';
    final version = prop('packageVersion');
    final license = _spdxLicense((node['concludedLicense'] as String?) ??
        (node['declaredLicense'] as String?) ??
        '');
    final url = prop('downloadLocation');
    final summary = (node['summary'] as String?) ?? '';
    final purl = _spdx3Purl(node) ?? '';
    return WheelPackage(
      name: name,
      version: version,
      license: license,
      url: url,
      summary: summary,
      vendor: '',
      arch: 'any',
      sourceRef: '',
      hashes: _spdx3Hashes(node['verifiedUsing']),
      requires: [],
      provides: [name],
      packageType: _purlToType(purl),
    );
  }

  /// Relit un tableau SPDX 3.0 `verifiedUsing` (`[{type: Hash, algorithm,
  /// hashValue}]`).
  List<PackageHash> _spdx3Hashes(Object? node) {
    if (node is! List) return const [];
    final out = <PackageHash>[];
    for (final h in node.whereType<Map<String, dynamic>>()) {
      if (h['type'] != 'Hash') continue;
      final ph = packageHash(
          (h['algorithm'] as String?) ?? '', (h['hashValue'] as String?) ?? '');
      if (ph != null && !out.contains(ph)) out.add(ph);
    }
    return out;
  }

  String? _spdx3Purl(Map<String, dynamic> node) {
    final extIds = node['externalIdentifier'] as List?;
    if (extIds == null) return null;
    for (final id in extIds.whereType<Map<String, dynamic>>()) {
      if (id['externalIdentifierType'] == 'purl') {
        return id['identifier'] as String?;
      }
    }
    return null;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  String _purlToType(String purl) {
    if (purl.startsWith('pkg:rpm/')) return 'rpm';
    if (purl.startsWith('pkg:deb/')) return 'deb';
    if (purl.startsWith('pkg:pypi/')) return 'pypi';
    if (purl.startsWith('pkg:npm/')) return 'npm';
    if (purl.startsWith('pkg:pub/')) return 'pub';
    if (purl.startsWith('pkg:golang/')) return 'golang';
    if (purl.startsWith('pkg:maven/')) return 'maven';
    if (purl.startsWith('pkg:cargo/')) return 'cargo';
    if (purl.startsWith('pkg:apk/')) return 'apk';
    return 'generic';
  }

  String _spdxLicense(String expr) {
    const skip = {'NOASSERTION', 'NONE', ''};
    return skip.contains(expr) ? '' : expr;
  }
}
