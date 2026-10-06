import 'dart:convert';
import 'dart:io';
import 'i18n.dart';

/// Résultat de la comparaison entre deux SBOMs CycloneDX.
class SbomDiffResult {
  final List<SbomComponent> added;
  final List<SbomComponent> removed;
  final List<SbomComponentUpdate> updated;

  /// Composants de **même version** dont la licence, les empreintes, le
  /// fournisseur ou la couche d'origine ont changé.
  final List<SbomComponentModification> modified;

  /// Comparaison des couches d'image (deux SBOM globaux `--per-layer`), ou
  /// `null` si aucun des deux ne porte de résumé de couches.
  final SbomLayerDiff? layers;

  const SbomDiffResult({
    required this.added,
    required this.removed,
    required this.updated,
    this.modified = const [],
    this.layers,
  });

  bool get isEmpty =>
      added.isEmpty &&
      removed.isEmpty &&
      updated.isEmpty &&
      modified.isEmpty &&
      (layers == null || layers!.isEmpty);
  int get changeCount =>
      added.length + removed.length + updated.length + modified.length;
}

class SbomComponent {
  final String name;
  final String version;
  final String purl;
  final String type;

  /// Licence(s) déclarée(s)/conclue(s), triées et jointes par « , » ('' si
  /// absente ou `NOASSERTION`).
  final String license;

  /// Empreintes `algorithme:valeur`, triées.
  final List<String> hashes;
  final String supplier;

  /// Index de la couche d'origine (SBOM `--per-layer`), '' sinon.
  final String layer;

  const SbomComponent({
    required this.name,
    required this.version,
    required this.purl,
    required this.type,
    this.license = '',
    this.hashes = const [],
    this.supplier = '',
    this.layer = '',
  });
}

class SbomComponentUpdate {
  final String name;
  final String purl;
  final String type;
  final String oldVersion;
  final String newVersion;

  /// Autres changements (licence, fournisseur, couche) : champ → (avant, après).
  /// Les empreintes ne sont pas comparées : elles changent avec la version.
  final Map<String, (String, String)> changes;

  const SbomComponentUpdate({
    required this.name,
    required this.purl,
    required this.type,
    required this.oldVersion,
    required this.newVersion,
    this.changes = const {},
  });
}

/// Composant dont la version est inchangée mais dont des métadonnées ont
/// changé : champ (`license`, `hashes`, `supplier`, `layer`) → (avant, après).
class SbomComponentModification {
  final String name;
  final String version;
  final String purl;
  final Map<String, (String, String)> changes;

  const SbomComponentModification({
    required this.name,
    required this.version,
    required this.purl,
    required this.changes,
  });
}

/// Différences entre les couches de deux images (par empreinte de couche).
class SbomLayerDiff {
  final int beforeCount;
  final int afterCount;

  /// Empreintes (courtes) des couches présentes seulement avant / après.
  final List<String> removed;
  final List<String> added;

  /// Couches communes dont le nombre de composants ajoutés/modifiés/supprimés
  /// diffère : empreinte → (avant, après), sous la forme `+a ~m -r`.
  final Map<String, (String, String)> changed;

  const SbomLayerDiff({
    required this.beforeCount,
    required this.afterCount,
    required this.removed,
    required this.added,
    required this.changed,
  });

  bool get isEmpty => removed.isEmpty && added.isEmpty && changed.isEmpty;
}

/// Compare deux fichiers SBOM JSON (CycloneDX, SPDX 2.x ou SPDX 3.0 JSON-LD).
class SbomDiffer {
  SbomDiffResult diff(Map<String, dynamic> before, Map<String, dynamic> after) {
    final beforeMap = _indexComponents(before);
    final afterMap = _indexComponents(after);

    final added = <SbomComponent>[];
    final removed = <SbomComponent>[];
    final updated = <SbomComponentUpdate>[];
    final modified = <SbomComponentModification>[];

    // Parcourir les composants "après" pour trouver ajouts et mises à jour
    for (final entry in afterMap.entries) {
      final key = entry.key; // purl sans version, ou name
      final comp = entry.value;
      final prev = beforeMap[key];
      if (prev == null) {
        added.add(comp);
      } else if (prev.version != comp.version) {
        updated.add(SbomComponentUpdate(
          name: comp.name,
          purl: comp.purl,
          type: comp.type,
          oldVersion: prev.version,
          newVersion: comp.version,
          changes: _metadataChanges(prev, comp, withHashes: false),
        ));
      } else {
        final changes = _metadataChanges(prev, comp, withHashes: true);
        if (changes.isNotEmpty) {
          modified.add(SbomComponentModification(
            name: comp.name,
            version: comp.version,
            purl: comp.purl,
            changes: changes,
          ));
        }
      }
    }

    // Parcourir les composants "avant" pour trouver les suppressions
    for (final entry in beforeMap.entries) {
      if (!afterMap.containsKey(entry.key)) {
        removed.add(entry.value);
      }
    }

    // Tri alphabétique pour une sortie stable
    added.sort((a, b) => a.name.compareTo(b.name));
    removed.sort((a, b) => a.name.compareTo(b.name));
    updated.sort((a, b) => a.name.compareTo(b.name));
    modified.sort((a, b) => a.name.compareTo(b.name));

    return SbomDiffResult(
      added: added,
      removed: removed,
      updated: updated,
      modified: modified,
      layers: _diffLayers(before, after),
    );
  }

  Map<String, (String, String)> _metadataChanges(
      SbomComponent a, SbomComponent b,
      {required bool withHashes}) {
    final out = <String, (String, String)>{};
    if (a.license != b.license) out['license'] = (a.license, b.license);
    if (a.supplier != b.supplier) out['supplier'] = (a.supplier, b.supplier);
    if (a.layer != b.layer) out['layer'] = (a.layer, b.layer);
    if (withHashes && a.hashes.join(',') != b.hashes.join(',')) {
      out['hashes'] = (a.hashes.join(', '), b.hashes.join(', '));
    }
    return out;
  }

  /// Résumés de couches d'un SBOM CycloneDX global `--per-layer` (propriétés
  /// `sbom_generator:layers:NNN` du composant racine) : empreinte → `+a ~m -r`.
  Map<String, String>? _layerSummaries(Map<String, dynamic> sbom) {
    final comp = (sbom['metadata'] as Map?)?['component'];
    final props = comp is Map ? comp['properties'] as List? : null;
    if (props == null) return null;
    final out = <String, String>{};
    for (final p in props) {
      if (p is! Map) continue;
      final name = '${p['name']}';
      if (!name.startsWith('sbom_generator:layers:') ||
          name.endsWith(':mode')) {
        continue;
      }
      try {
        final j = jsonDecode('${p['value']}') as Map<String, dynamic>;
        final digest = '${j['digest'] ?? name}';
        final short = digest.length > 19 ? digest.substring(0, 19) : digest;
        out[short] = '+${j['added'] ?? 0} ~${j['modified'] ?? 0} '
            '-${j['removed'] ?? 0}';
      } catch (_) {}
    }
    return out.isEmpty ? null : out;
  }

  SbomLayerDiff? _diffLayers(
      Map<String, dynamic> before, Map<String, dynamic> after) {
    final a = _layerSummaries(before);
    final b = _layerSummaries(after);
    if (a == null && b == null) return null;
    final ma = a ?? const <String, String>{};
    final mb = b ?? const <String, String>{};
    return SbomLayerDiff(
      beforeCount: ma.length,
      afterCount: mb.length,
      removed: [
        for (final k in ma.keys)
          if (!mb.containsKey(k)) k
      ],
      added: [
        for (final k in mb.keys)
          if (!ma.containsKey(k)) k
      ],
      changed: {
        for (final k in ma.keys)
          if (mb.containsKey(k) && ma[k] != mb[k]) k: (ma[k]!, mb[k]!),
      },
    );
  }

  /// Clé d'identité = purl sans la version (pkg:type/name sans @version),
  /// ou "name:type" si pas de purl.
  String _componentKey(SbomComponent c) {
    if (c.purl.isNotEmpty) {
      final atIdx = c.purl.lastIndexOf('@');
      return atIdx > 0 ? c.purl.substring(0, atIdx) : c.purl;
    }
    return '${c.name}:${c.type}';
  }

  Map<String, SbomComponent> _indexComponents(Map<String, dynamic> sbom) {
    if (sbom.containsKey('spdxVersion')) return _indexSpdxComponents(sbom);
    if (sbom.containsKey('@graph')) return _indexSpdx3Components(sbom);
    return _indexCycloneDxComponents(sbom);
  }

  Map<String, SbomComponent> _indexCycloneDxComponents(
      Map<String, dynamic> sbom) {
    final result = <String, SbomComponent>{};
    final components = (sbom['components'] as List?) ?? [];
    for (final raw in components) {
      final c = raw as Map<String, dynamic>;
      final comp = SbomComponent(
        name: (c['name'] as String?) ?? '',
        version: (c['version'] as String?) ?? '',
        purl: (c['purl'] as String?) ?? '',
        type: (c['type'] as String?) ?? 'library',
        license: _cdxLicense(c['licenses']),
        hashes: _sorted([
          for (final h in (c['hashes'] as List? ?? const []))
            if (h is Map) '${h['alg']}:${h['content']}',
        ]),
        supplier: _cdxSupplier(c),
        layer: _cdxLayer(c['properties']),
      );
      if (comp.name.isEmpty) continue;
      result[_componentKey(comp)] = comp;
    }
    return result;
  }

  Map<String, SbomComponent> _indexSpdxComponents(Map<String, dynamic> sbom) {
    final result = <String, SbomComponent>{};
    final packages = (sbom['packages'] as List?) ?? [];
    for (final raw in packages) {
      final p = raw as Map<String, dynamic>;
      String purl = '';
      for (final ref in (p['externalRefs'] as List? ?? [])) {
        final r = ref as Map<String, dynamic>;
        if (r['referenceType'] == 'purl') {
          purl = (r['referenceLocator'] as String?) ?? '';
          break;
        }
      }
      final comp = SbomComponent(
        name: (p['name'] as String?) ?? '',
        version: (p['versionInfo'] as String?) ?? '',
        purl: purl,
        type: 'package',
        license: _spdxLicense(p['licenseConcluded'], p['licenseDeclared']),
        hashes: _sorted([
          for (final h in (p['checksums'] as List? ?? const []))
            if (h is Map) '${h['algorithm']}:${h['checksumValue']}',
        ]),
        supplier: '${p['supplier'] ?? ''}'
            .replaceFirst(RegExp(r'^(Organization|Person): '), '')
            .replaceAll(RegExp(r'^NOASSERTION$'), ''),
        layer: _annotationLayer(p['annotations']),
      );
      if (comp.name.isEmpty) continue;
      result[_componentKey(comp)] = comp;
    }
    return result;
  }

  Map<String, SbomComponent> _indexSpdx3Components(Map<String, dynamic> sbom) {
    final result = <String, SbomComponent>{};
    final graph = (sbom['@graph'] as List?) ?? [];
    for (final raw in graph) {
      final e = raw as Map<String, dynamic>;
      if (e['type'] != 'software:Package') continue;
      String purl = '';
      for (final ref in (e['externalIdentifier'] as List? ?? [])) {
        final r = ref as Map<String, dynamic>;
        if (r['externalIdentifierType'] == 'purl') {
          purl = (r['identifier'] as String?) ?? '';
          break;
        }
      }
      final comp = SbomComponent(
        name: (e['name'] as String?) ?? '',
        version: (e['software:packageVersion'] as String?) ?? '',
        purl: purl,
        type: 'package',
        license: _spdxLicense(e['concludedLicense'], e['declaredLicense']),
        hashes: _sorted([
          for (final h in (e['verifiedUsing'] as List? ?? const []))
            if (h is Map) '${h['algorithm']}:${h['hashValue']}',
        ]),
        layer: _annotationLayer(e['annotation']),
      );
      if (comp.name.isEmpty) continue;
      result[_componentKey(comp)] = comp;
    }
    return result;
  }

  static List<String> _sorted(List<String> l) => l..sort();

  static String _cdxLicense(Object? licenses) {
    final out = <String>{};
    for (final l in (licenses as List? ?? const [])) {
      if (l is! Map) continue;
      final lic = l['license'];
      final v = lic is Map
          ? '${lic['id'] ?? lic['name'] ?? ''}'
          : '${l['expression'] ?? ''}';
      if (v.isNotEmpty && v != 'NOASSERTION') out.add(v);
    }
    return (out.toList()..sort()).join(', ');
  }

  static String _cdxSupplier(Map<String, dynamic> c) {
    final sup = c['supplier'];
    if (sup is Map && '${sup['name'] ?? ''}'.isNotEmpty)
      return '${sup['name']}';
    return '${c['publisher'] ?? c['author'] ?? ''}';
  }

  static String _cdxLayer(Object? props) {
    for (final p in (props as List? ?? const [])) {
      if (p is Map && p['name'] == 'sbom_generator:layer:index') {
        return '${p['value']}';
      }
    }
    return '';
  }

  static String _spdxLicense(Object? concluded, Object? declared) {
    for (final v in [concluded, declared]) {
      final s = v is String ? v : '';
      if (s.isNotEmpty && s != 'NOASSERTION' && s != 'NONE') return s;
    }
    return '';
  }

  /// Couche d'origine portée par les annotations SPDX
  /// (`sbom_generator:layer:index=N` dans le commentaire / l'énoncé).
  static String _annotationLayer(Object? annotations) {
    final re = RegExp(r'sbom_generator:layer:index=(\d+)');
    for (final a in (annotations as List? ?? const [])) {
      if (a is! Map) continue;
      final m = re.firstMatch('${a['comment'] ?? a['statement'] ?? ''}');
      if (m != null) return m.group(1)!;
    }
    return '';
  }

  /// Charge un SBOM depuis un fichier JSON (CycloneDX ou SPDX JSON).
  static Future<Map<String, dynamic>> loadFile(String path) async {
    final file = File(path);
    if (!await file.exists()) {
      throw Exception(
          tr('Fichier introuvable : $path', 'File not found: $path'));
    }
    try {
      return jsonDecode(await file.readAsString()) as Map<String, dynamic>;
    } catch (e) {
      throw Exception(tr(
          'Impossible de parser "$path" : $e', 'Unable to parse "$path": $e'));
    }
  }

  /// Imprime le diff dans stdout avec couleurs ANSI.
  void printDiff(SbomDiffResult result, {bool color = true}) {
    final green = color ? '\x1B[32m' : '';
    final red = color ? '\x1B[31m' : '';
    final yellow = color ? '\x1B[33m' : '';
    final reset = color ? '\x1B[0m' : '';
    final bold = color ? '\x1B[1m' : '';

    if (result.isEmpty) {
      print(
          '$bold${tr('Aucun changement détecté.', 'No change detected.')}$reset');
      return;
    }

    print('$bold${tr('Résumé', 'Summary')}: '
        '$green+${result.added.length} ${tr('ajouté(s)', 'added')}$reset  '
        '$red-${result.removed.length} ${tr('supprimé(s)', 'removed')}$reset  '
        '$yellow~${result.updated.length} ${tr('mis à jour', 'updated')}$reset');
    stdout.writeln();

    if (result.added.isNotEmpty) {
      print(
          '$bold$green── ${tr('Ajoutés', 'Added')} (${result.added.length}) ──$reset');
      for (final c in result.added) {
        final purl = c.purl.isNotEmpty ? '  ${c.purl}' : '';
        print('${green}  + ${c.name} ${c.version}$reset$purl');
      }
      stdout.writeln();
    }

    if (result.removed.isNotEmpty) {
      print(
          '$bold$red── ${tr('Supprimés', 'Removed')} (${result.removed.length}) ──$reset');
      for (final c in result.removed) {
        final purl = c.purl.isNotEmpty ? '  ${c.purl}' : '';
        print('${red}  - ${c.name} ${c.version}$reset$purl');
      }
      stdout.writeln();
    }

    if (result.updated.isNotEmpty) {
      print(
          '$bold$yellow── ${tr('Mis à jour', 'Updated')} (${result.updated.length}) ──$reset');
      for (final c in result.updated) {
        print('${yellow}  ~ ${c.name}  '
            '${c.oldVersion} → ${c.newVersion}$reset');
        for (final e in c.changes.entries) {
          print('      ${_fieldLabel(e.key)} : '
              '${_shown(e.value.$1)} → ${_shown(e.value.$2)}');
        }
      }
      stdout.writeln();
    }

    if (result.modified.isNotEmpty) {
      print(
          '$bold$yellow── ${tr('Modifiés (même version)', 'Modified (same version)')} (${result.modified.length}) ──$reset');
      for (final c in result.modified) {
        print('${yellow}  ~ ${c.name} ${c.version}$reset');
        for (final e in c.changes.entries) {
          print('      ${_fieldLabel(e.key)} : '
              '${_shown(e.value.$1)} → ${_shown(e.value.$2)}');
        }
      }
      stdout.writeln();
    }

    final layers = result.layers;
    if (layers != null && !layers.isEmpty) {
      print(
          '$bold── ${tr('Couches', 'Layers')} (${layers.beforeCount} → ${layers.afterCount}) ──$reset');
      for (final d in layers.removed) {
        print('$red  - ${tr('couche supprimée', 'layer removed')} $d$reset');
      }
      for (final d in layers.added) {
        print('$green  + ${tr('couche ajoutée', 'layer added')} $d$reset');
      }
      for (final e in layers.changed.entries) {
        print('$yellow  ~ ${e.key}  ${e.value.$1} → ${e.value.$2}$reset');
      }
      stdout.writeln();
    }
  }

  static String _fieldLabel(String field) => switch (field) {
        'license' => tr('licence', 'license'),
        'hashes' => tr('empreintes', 'hashes'),
        'supplier' => tr('fournisseur', 'supplier'),
        'layer' => tr('couche', 'layer'),
        _ => field,
      };

  static String _shown(String v) => v.isEmpty ? '—' : v;

  /// Génère un diff au format JSON structuré.
  Map<String, dynamic> toJson(SbomDiffResult result) {
    Map<String, dynamic> changes(Map<String, (String, String)> m) => {
          for (final e in m.entries)
            e.key: {'before': e.value.$1, 'after': e.value.$2},
        };
    Map<String, dynamic> comp(SbomComponent c) => {
          'name': c.name,
          'version': c.version,
          'purl': c.purl,
          if (c.license.isNotEmpty) 'license': c.license,
          if (c.supplier.isNotEmpty) 'supplier': c.supplier,
          if (c.layer.isNotEmpty) 'layer': c.layer,
        };
    final layers = result.layers;
    return {
      'summary': {
        'added': result.added.length,
        'removed': result.removed.length,
        'updated': result.updated.length,
        'modified': result.modified.length,
        'total_changes': result.changeCount,
      },
      'added': result.added.map(comp).toList(),
      'removed': result.removed.map(comp).toList(),
      'updated': result.updated
          .map((c) => {
                'name': c.name,
                'purl': c.purl,
                'old_version': c.oldVersion,
                'new_version': c.newVersion,
                if (c.changes.isNotEmpty) 'changes': changes(c.changes),
              })
          .toList(),
      'modified': result.modified
          .map((c) => {
                'name': c.name,
                'version': c.version,
                'purl': c.purl,
                'changes': changes(c.changes),
              })
          .toList(),
      if (layers != null)
        'layers': {
          'before': layers.beforeCount,
          'after': layers.afterCount,
          'added': layers.added,
          'removed': layers.removed,
          'changed': changes(layers.changed),
        },
    };
  }
}
