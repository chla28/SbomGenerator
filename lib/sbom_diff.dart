import 'dart:convert';
import 'dart:io';

/// Résultat de la comparaison entre deux SBOMs CycloneDX.
class SbomDiffResult {
  final List<SbomComponent> added;
  final List<SbomComponent> removed;
  final List<SbomComponentUpdate> updated;

  const SbomDiffResult({
    required this.added,
    required this.removed,
    required this.updated,
  });

  bool get isEmpty => added.isEmpty && removed.isEmpty && updated.isEmpty;
  int get changeCount => added.length + removed.length + updated.length;
}

class SbomComponent {
  final String name;
  final String version;
  final String purl;
  final String type;

  const SbomComponent({
    required this.name,
    required this.version,
    required this.purl,
    required this.type,
  });
}

class SbomComponentUpdate {
  final String name;
  final String purl;
  final String type;
  final String oldVersion;
  final String newVersion;

  const SbomComponentUpdate({
    required this.name,
    required this.purl,
    required this.type,
    required this.oldVersion,
    required this.newVersion,
  });
}

/// Compare deux fichiers SBOM JSON (CycloneDX, SPDX 2.x ou SPDX 3.0 JSON-LD).
class SbomDiffer {
  SbomDiffResult diff(Map<String, dynamic> before, Map<String, dynamic> after) {
    final beforeMap = _indexComponents(before);
    final afterMap = _indexComponents(after);

    final added = <SbomComponent>[];
    final removed = <SbomComponent>[];
    final updated = <SbomComponentUpdate>[];

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
        ));
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

    return SbomDiffResult(added: added, removed: removed, updated: updated);
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

  Map<String, SbomComponent> _indexCycloneDxComponents(Map<String, dynamic> sbom) {
    final result = <String, SbomComponent>{};
    final components = (sbom['components'] as List?) ?? [];
    for (final raw in components) {
      final c = raw as Map<String, dynamic>;
      final comp = SbomComponent(
        name: (c['name'] as String?) ?? '',
        version: (c['version'] as String?) ?? '',
        purl: (c['purl'] as String?) ?? '',
        type: (c['type'] as String?) ?? 'library',
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
      );
      if (comp.name.isEmpty) continue;
      result[_componentKey(comp)] = comp;
    }
    return result;
  }

  /// Charge un SBOM depuis un fichier JSON (CycloneDX ou SPDX JSON).
  static Future<Map<String, dynamic>> loadFile(String path) async {
    final file = File(path);
    if (!await file.exists()) throw Exception('Fichier introuvable : $path');
    try {
      return jsonDecode(await file.readAsString()) as Map<String, dynamic>;
    } catch (e) {
      throw Exception('Impossible de parser "$path" : $e');
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
      print('${bold}Aucun changement détecté.$reset');
      return;
    }

    print('${bold}Résumé : '
        '${green}+${result.added.length} ajouté(s)$reset  '
        '${red}-${result.removed.length} supprimé(s)$reset  '
        '${yellow}~${result.updated.length} mis à jour$reset');
    stdout.writeln();

    if (result.added.isNotEmpty) {
      print('${bold}${green}── Ajoutés (${result.added.length}) ──$reset');
      for (final c in result.added) {
        final purl = c.purl.isNotEmpty ? '  ${c.purl}' : '';
        print('${green}  + ${c.name} ${c.version}$reset$purl');
      }
      stdout.writeln();
    }

    if (result.removed.isNotEmpty) {
      print('${bold}${red}── Supprimés (${result.removed.length}) ──$reset');
      for (final c in result.removed) {
        final purl = c.purl.isNotEmpty ? '  ${c.purl}' : '';
        print('${red}  - ${c.name} ${c.version}$reset$purl');
      }
      stdout.writeln();
    }

    if (result.updated.isNotEmpty) {
      print('${bold}${yellow}── Mis à jour (${result.updated.length}) ──$reset');
      for (final c in result.updated) {
        print('${yellow}  ~ ${c.name}  '
            '${c.oldVersion} → ${c.newVersion}$reset');
      }
      stdout.writeln();
    }
  }

  /// Génère un diff au format JSON structuré.
  Map<String, dynamic> toJson(SbomDiffResult result) => {
        'summary': {
          'added': result.added.length,
          'removed': result.removed.length,
          'updated': result.updated.length,
          'total_changes': result.changeCount,
        },
        'added': result.added
            .map((c) => {'name': c.name, 'version': c.version, 'purl': c.purl})
            .toList(),
        'removed': result.removed
            .map((c) => {'name': c.name, 'version': c.version, 'purl': c.purl})
            .toList(),
        'updated': result.updated
            .map((c) => {
                  'name': c.name,
                  'purl': c.purl,
                  'old_version': c.oldVersion,
                  'new_version': c.newVersion,
                })
            .toList(),
      };
}
