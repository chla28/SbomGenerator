import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/layer_nav.dart';
import '../models/sbom_result.dart';
import 'help_icon.dart';
import 'layer_selector.dart';

// ─── Modèles ─────────────────────────────────────────────────────────────────

class _SbomComponent {
  final String name;
  final String version;
  final String type;
  final String license;
  final String purl;

  /// Champs `sbom_generator:layer:*` (voir [layerFieldsOf]).
  final Map<String, String> layerFields;

  const _SbomComponent({
    required this.name,
    required this.version,
    required this.type,
    required this.license,
    required this.purl,
    this.layerFields = const {},
  });

  String get key => '$name@$version';
  String get layer => layerColumnLabel(layerFields);
}

class _SbomInfo {
  final String format;
  final String specVersion;
  final String rootName;
  final String rootVersion;
  final List<_SbomComponent> components;

  const _SbomInfo({
    required this.format,
    required this.specVersion,
    required this.rootName,
    required this.rootVersion,
    required this.components,
  });

  bool get hasLayers => components.any((c) => c.layerFields.isNotEmpty);

  int get uniqueLicenseCount =>
      components.map((c) => c.license).where((l) => l.isNotEmpty).toSet().length;

  static _SbomInfo? parse(String raw) {
    try {
      final data = jsonDecode(raw) as Map<String, dynamic>;
      if (data['bomFormat'] == 'CycloneDX') return _parseCycloneDX(data);
      if (data.containsKey('spdxVersion')) return _parseSpdx(data);
      if (data.containsKey('@graph')) return _parseSpdx3(data);
    } catch (_) {}
    return null;
  }

  static _SbomInfo _parseCycloneDX(Map<String, dynamic> data) {
    final meta = (data['metadata'] as Map<String, dynamic>?) ?? {};
    final root = (meta['component'] as Map<String, dynamic>?) ?? {};
    final comps = (data['components'] as List? ?? []).map((e) {
      final c = e as Map<String, dynamic>;
      return _SbomComponent(
        name: c['name'] as String? ?? '',
        version: c['version'] as String? ?? '',
        type: c['type'] as String? ?? 'unknown',
        license: _cdxLicense(c['licenses']),
        purl: c['purl'] as String? ?? '',
        layerFields: layerFieldsOf(c),
      );
    }).toList()
      ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    return _SbomInfo(
      format: 'CycloneDX',
      specVersion: data['specVersion'] as String? ?? '',
      rootName: root['name'] as String? ?? '',
      rootVersion: root['version'] as String? ?? '',
      components: comps,
    );
  }

  static String _cdxLicense(dynamic lics) {
    if (lics == null) return '';
    final list = lics as List;
    if (list.isEmpty) return '';
    final first = list.first as Map<String, dynamic>;
    return first['expression'] as String? ??
        (first['license'] as Map<String, dynamic>?)?['id'] as String? ??
        '';
  }

  static _SbomInfo _parseSpdx(Map<String, dynamic> data) {
    final pkgs = (data['packages'] as List? ?? []).map((e) {
      final p = e as Map<String, dynamic>;
      String purl = '';
      for (final ref in (p['externalRefs'] as List? ?? [])) {
        final r = ref as Map<String, dynamic>;
        if (r['referenceType'] == 'purl') {
          purl = r['referenceLocator'] as String? ?? '';
          break;
        }
      }
      return _SbomComponent(
        name: p['name'] as String? ?? '',
        version: p['versionInfo'] as String? ?? '',
        type: 'package',
        license: p['licenseConcluded'] as String? ?? '',
        purl: purl,
        layerFields: layerFieldsOf(p),
      );
    }).toList()
      ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    return _SbomInfo(
      format: 'SPDX',
      specVersion: data['spdxVersion'] as String? ?? '',
      rootName: data['name'] as String? ?? '',
      rootVersion: '',
      components: pkgs,
    );
  }

  static _SbomInfo _parseSpdx3(Map<String, dynamic> data) {
    final graph = (data['@graph'] as List? ?? []).cast<Map<String, dynamic>>();
    final doc = graph.firstWhere(
      (e) => e['type'] == 'SpdxDocument',
      orElse: () => const {},
    );
    final comps = graph.where((e) => e['type'] == 'software:Package').map((p) {
      String purl = '';
      for (final ref in (p['externalIdentifier'] as List? ?? [])) {
        final r = ref as Map<String, dynamic>;
        if (r['externalIdentifierType'] == 'purl') {
          purl = r['identifier'] as String? ?? '';
          break;
        }
      }
      final license = p['concludedLicense'] as String? ??
          p['declaredLicense'] as String? ??
          '';
      return _SbomComponent(
        name: p['name'] as String? ?? '',
        version: p['software:packageVersion'] as String? ?? '',
        type: 'package',
        license: license == 'NOASSERTION' ? '' : license,
        purl: purl,
        layerFields: layerFieldsOf(p),
      );
    }).toList()
      ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    return _SbomInfo(
      format: 'SPDX 3.0 JSON-LD',
      specVersion: '3.0.0',
      rootName: doc['name'] as String? ?? '',
      rootVersion: '',
      components: comps,
    );
  }
}

// ─── Items du ListView plat ───────────────────────────────────────────────────

sealed class _ListItem {}

class _GroupHeader extends _ListItem {
  final String key;
  final int count;
  _GroupHeader(this.key, this.count);
}

class _CompItem extends _ListItem {
  final _SbomComponent comp;
  _CompItem(this.comp);
}

// ─── Groupement ───────────────────────────────────────────────────────────────

enum _GroupBy { none, type, license, layer }

// ─── Panel principal ──────────────────────────────────────────────────────────

class SbomTreePanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  const SbomTreePanel({super.key, required this.outputFiles});

  @override
  State<SbomTreePanel> createState() => _SbomTreePanelState();
}

class _SbomTreePanelState extends State<SbomTreePanel>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;

  _SbomInfo? _info;
  String? _selectedPath;
  String? _error;
  bool _loading = false;

  // Jeu de SBOM par couche (--per-layer) auquel appartient le fichier ouvert.
  LayerNav? _nav;
  LayerDocInfo _layerInfo = LayerDocInfo.empty;
  Map<int, String> _layerLabels = const {};

  final _searchCtrl = TextEditingController();
  String _searchTerm = '';
  _GroupBy _groupBy = _GroupBy.type;
  final Set<String> _expandedGroups = {};
  final Set<String> _expandedComps = {};

  @override
  void initState() {
    super.initState();
    // Différé après le premier frame : _autoLoad → _loadFile appelle
    // setState() avant tout "await", donc de façon synchrone si invoqué
    // directement depuis initState (avant que le widget ait fini de monter).
    WidgetsBinding.instance
        .addPostFrameCallback((_) => _autoLoad(widget.outputFiles));
  }

  @override
  void didUpdateWidget(SbomTreePanel old) {
    super.didUpdateWidget(old);
    if (widget.outputFiles != old.outputFiles && _info == null) {
      _autoLoad(widget.outputFiles);
    }
  }

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  void _autoLoad(List<OutputFile> files) {
    // Le SBOM global plutôt qu'un SBOM de couche (--per-layer) : les couches
    // restent accessibles depuis le sélecteur de couche.
    final f = files
        .where((f) =>
            (f.path.endsWith('.cdx.json') ||
                f.path.endsWith('.spdx.json') ||
                f.path.endsWith('.spdx3.jsonld')) &&
            !isLayerSbomFile(f.path))
        .firstOrNull;
    if (f != null) _loadFile(f.path);
  }

  Future<void> _loadFile(String path) async {
    setState(() {
      _loading = true;
      _error = null;
      _expandedGroups.clear();
      _expandedComps.clear();
    });
    try {
      final raw = await File(path).readAsString();
      final info = _SbomInfo.parse(raw);
      final nav = info == null ? null : LayerNav.discover(path);
      var layerInfo = LayerDocInfo.empty;
      if (info != null) {
        try {
          layerInfo = LayerDocInfo.fromSbom(
              jsonDecode(raw) as Map<String, dynamic>);
        } catch (_) {}
      }
      final labels = nav == null
          ? const <int, String>{}
          : layerInfo.layerLabels.isNotEmpty
              ? layerInfo.layerLabels
              : nav.globalPath == _nav?.globalPath && _layerLabels.isNotEmpty
                  ? _layerLabels
                  : await readLayerLabels(nav.globalPath);
      setState(() {
        _loading = false;
        _selectedPath = path;
        _info = info;
        _nav = nav;
        _layerInfo = layerInfo;
        _layerLabels = labels;
        if (_groupBy == _GroupBy.layer && info?.hasLayers != true) {
          _groupBy = _GroupBy.type;
        }
        _error = info == null ? 'Format non reconnu (ni CycloneDX ni SPDX).' : null;
        if (info != null) {
          // Déplier tous les groupes si peu nombreux
          final types = info.components.map((c) => c.type).toSet();
          if (types.length <= 6) _expandedGroups.addAll(types);
        }
      });
    } catch (e) {
      setState(() {
        _loading = false;
        _error = 'Erreur de lecture : $e';
      });
    }
  }

  Future<void> _pickFile() async {
    final r = await FilePicker.pickFiles(
      dialogTitle: 'Sélectionner un fichier SBOM (JSON)',
      type: FileType.custom,
      allowedExtensions: ['json', 'jsonld'],
    );
    if (r?.files.single.path != null) _loadFile(r!.files.single.path!);
  }

  List<_ListItem> _buildItems() {
    final info = _info;
    if (info == null) return [];

    var comps = info.components;
    if (_searchTerm.isNotEmpty) {
      final q = _searchTerm.toLowerCase();
      comps = comps
          .where((c) =>
              c.name.toLowerCase().contains(q) ||
              c.purl.toLowerCase().contains(q) ||
              c.license.toLowerCase().contains(q))
          .toList();
    }

    if (_groupBy == _GroupBy.none) {
      return comps.map(_CompItem.new).toList();
    }

    final groups = <String, List<_SbomComponent>>{};
    for (final c in comps) {
      final k = switch (_groupBy) {
        _GroupBy.type => c.type,
        _GroupBy.layer => layerGroupKey(c.layerFields),
        _ => c.license.isEmpty ? '(non spécifié)' : c.license,
      };
      (groups[k] ??= []).add(c);
    }

    final sortedKeys = groups.keys.toList()..sort();
    final items = <_ListItem>[];
    for (final k in sortedKeys) {
      items.add(_GroupHeader(k, groups[k]!.length));
      if (_expandedGroups.contains(k)) {
        items.addAll(groups[k]!.map(_CompItem.new));
      }
    }
    return items;
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final info = _info;
    final items = _buildItems();

    return Column(
      children: [
        // ── Barre de sélection de fichier ──
        _FileBar(
          selectedPath: _selectedPath,
          outputFiles: widget.outputFiles,
          onPickFile: _pickFile,
          onSelectFile: _loadFile,
        ),

        // ── Navigation par couche (--per-layer) ──
        if (info != null && _nav != null)
          LayerSelector(
            nav: _nav!,
            currentPath: _selectedPath!,
            info: _layerInfo,
            layerLabels: _layerLabels,
            onOpen: _loadFile,
          ),

        // ── Infos SBOM ──
        if (info != null)
          _InfoBar(info: info, selectedPath: _selectedPath!),

        // ── Barre outils : recherche + groupement ──
        if (info != null)
          Container(
            color: Theme.of(context).colorScheme.surfaceContainerLow,
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            child: Row(
              children: [
                // Grouper par
                _GroupBySelector(
                  value: _groupBy,
                  showLayer: info.hasLayers,
                  onChanged: (v) {
                    setState(() {
                      _groupBy = v;
                      _expandedGroups.clear();
                      if (v == _GroupBy.type) {
                        final types =
                            info.components.map((c) => c.type).toSet();
                        if (types.length <= 6) _expandedGroups.addAll(types);
                      } else if (v == _GroupBy.layer) {
                        final keys = info.components
                            .map((c) => layerGroupKey(c.layerFields))
                            .toSet();
                        if (keys.length <= 6) _expandedGroups.addAll(keys);
                      }
                    });
                  },
                ),
                const SizedBox(width: 8),
                // Tout déplier / replier
                if (_groupBy != _GroupBy.none) ...[
                  IconButton(
                    icon: const Icon(Icons.unfold_more, size: 16),
                    tooltip: 'Tout déplier',
                    visualDensity: VisualDensity.compact,
                    onPressed: () => setState(() {
                      final keys = items
                          .whereType<_GroupHeader>()
                          .map((h) => h.key)
                          .toSet();
                      _expandedGroups.addAll(keys);
                    }),
                  ),
                  IconButton(
                    icon: const Icon(Icons.unfold_less, size: 16),
                    tooltip: 'Tout replier',
                    visualDensity: VisualDensity.compact,
                    onPressed: () => setState(() => _expandedGroups.clear()),
                  ),
                  const SizedBox(width: 4),
                ],
                // Recherche
                Expanded(
                  child: TextField(
                    controller: _searchCtrl,
                    onChanged: (v) => setState(() => _searchTerm = v),
                    decoration: InputDecoration(
                      hintText: 'Filtrer par nom, purl, licence…',
                      isDense: true,
                      prefixIcon: const Icon(Icons.search, size: 16),
                      suffixIcon: _searchTerm.isNotEmpty
                          ? IconButton(
                              icon: const Icon(Icons.clear, size: 14),
                              onPressed: () {
                                _searchCtrl.clear();
                                setState(() => _searchTerm = '');
                              },
                              padding: EdgeInsets.zero,
                            )
                          : null,
                      contentPadding: const EdgeInsets.symmetric(
                          horizontal: 8, vertical: 6),
                      border: const OutlineInputBorder(),
                    ),
                    style: const TextStyle(fontSize: 12),
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  '${items.whereType<_CompItem>().length} / ${info.components.length}',
                  style: const TextStyle(fontSize: 11, color: Colors.grey),
                ),
              ],
            ),
          ),

        // ── Corps ──
        Expanded(
          child: _loading
              ? const Center(child: CircularProgressIndicator())
              : _error != null
                  ? _ErrorView(message: _error!)
                  : info == null
                      ? _EmptyView(
                          hasOutputFiles: widget.outputFiles.isNotEmpty,
                          onPick: _pickFile,
                        )
                      : items.isEmpty
                          ? Center(
                              child: Column(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  const Icon(Icons.search_off,
                                      size: 40, color: Colors.grey),
                                  const SizedBox(height: 8),
                                  Text(
                                    'Aucun composant pour "$_searchTerm"',
                                    style: const TextStyle(color: Colors.grey),
                                  ),
                                ],
                              ),
                            )
                          : ListView.builder(
                              itemCount: items.length,
                              itemBuilder: (_, i) {
                                final item = items[i];
                                return switch (item) {
                                  _GroupHeader h => _GroupHeaderTile(
                                      header: h,
                                      expanded:
                                          _expandedGroups.contains(h.key),
                                      onTap: () => setState(() {
                                        if (_expandedGroups.contains(h.key)) {
                                          _expandedGroups.remove(h.key);
                                        } else {
                                          _expandedGroups.add(h.key);
                                        }
                                      }),
                                    ),
                                  _CompItem c => _ComponentTile(
                                      comp: c.comp,
                                      expanded:
                                          _expandedComps.contains(c.comp.key),
                                      onTap: () => setState(() {
                                        if (_expandedComps
                                            .contains(c.comp.key)) {
                                          _expandedComps.remove(c.comp.key);
                                        } else {
                                          _expandedComps.add(c.comp.key);
                                        }
                                      }),
                                    ),
                                };
                              },
                            ),
        ),
      ],
    );
  }
}

// ─── Barre de sélection fichier ───────────────────────────────────────────────

class _FileBar extends StatelessWidget {
  final String? selectedPath;
  final List<OutputFile> outputFiles;
  final VoidCallback onPickFile;
  final ValueChanged<String> onSelectFile;

  const _FileBar({
    required this.selectedPath,
    required this.outputFiles,
    required this.onPickFile,
    required this.onSelectFile,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    // Les SBOM de couche (--per-layer) passent par le sélecteur de couche.
    final sbomFiles = outputFiles
        .where((f) =>
            (f.path.endsWith('.cdx.json') ||
                f.path.endsWith('.spdx.json') ||
                f.path.endsWith('.spdx3.jsonld')) &&
            !isLayerSbomFile(f.path))
        .toList();

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      color: theme.colorScheme.surfaceContainerHigh,
      child: Row(
        children: [
          const Icon(Icons.account_tree_outlined, size: 16),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              selectedPath != null
                  ? selectedPath!.split('/').last
                  : 'Aucun fichier SBOM sélectionné',
              style: TextStyle(
                  fontSize: 12,
                  color: selectedPath != null
                      ? theme.colorScheme.onSurface
                      : Colors.grey),
              overflow: TextOverflow.ellipsis,
            ),
          ),
          // Fichiers générés
          if (sbomFiles.isNotEmpty)
            MenuAnchor(
              builder: (ctx, ctrl, child) => TextButton.icon(
                icon: const Icon(Icons.folder_outlined, size: 14),
                label: Text('Générés (${sbomFiles.length})',
                    style: const TextStyle(fontSize: 12)),
                onPressed: () =>
                    ctrl.isOpen ? ctrl.close() : ctrl.open(),
                style: TextButton.styleFrom(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 8, vertical: 4)),
              ),
              menuChildren: [
                for (final f in sbomFiles)
                  MenuItemButton(
                    onPressed: () => onSelectFile(f.path),
                    child: Text(
                      f.path.split('/').last,
                      style: const TextStyle(fontSize: 12),
                    ),
                  ),
              ],
            ),
          const SizedBox(width: 4),
          TextButton.icon(
            icon: const Icon(Icons.file_open_outlined, size: 14),
            label: const Text('Ouvrir…', style: TextStyle(fontSize: 12)),
            onPressed: onPickFile,
            style: TextButton.styleFrom(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 4)),
          ),
        ],
      ),
    );
  }
}

// ─── Barre d'infos SBOM ───────────────────────────────────────────────────────

class _InfoBar extends StatelessWidget {
  final _SbomInfo info;
  final String selectedPath;

  const _InfoBar({required this.info, required this.selectedPath});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      color: theme.colorScheme.primaryContainer.withValues(alpha: 0.3),
      child: Row(
        children: [
          _Chip(Icons.inventory_2_outlined, info.rootName.isEmpty ? selectedPath.split('/').last : info.rootName),
          if (info.rootVersion.isNotEmpty) ...[
            const SizedBox(width: 6),
            _Chip(Icons.tag, info.rootVersion),
          ],
          const SizedBox(width: 6),
          _Chip(Icons.description_outlined, '${info.format} ${info.specVersion}'),
          const SizedBox(width: 6),
          _Chip(Icons.inventory_outlined, '${info.components.length} composants'),
          const SizedBox(width: 6),
          _Chip(Icons.gavel_outlined, '${info.uniqueLicenseCount} licences'),
        ],
      ),
    );
  }
}

class _Chip extends StatelessWidget {
  final IconData icon;
  final String label;
  const _Chip(this.icon, this.label);

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 12, color: Colors.grey[600]),
        const SizedBox(width: 3),
        Text(label,
            style: TextStyle(fontSize: 11, color: Colors.grey[700])),
      ],
    );
  }
}

// ─── Sélecteur de groupement ──────────────────────────────────────────────────

class _GroupBySelector extends StatelessWidget {
  final _GroupBy value;
  final ValueChanged<_GroupBy> onChanged;

  /// Propose le regroupement par couche (SBOM produit avec --per-layer).
  final bool showLayer;

  const _GroupBySelector({
    required this.value,
    required this.onChanged,
    this.showLayer = false,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Text('Grouper :', style: TextStyle(fontSize: 11)),
        const SizedBox(width: 2),
        const HelpIcon(
          'Mode de regroupement des composants.\n'
          '• Aucun : liste à plat alphabétique\n'
          '• Type : groupé par écosystème (rpm, pypi…)\n'
          '• Licence : groupé par expression SPDX\n'
          '• Couche : groupé par couche d\'origine (SBOM global) ou par '
          'changement (SBOM de couche) — SBOM produits avec --per-layer',
        ),
        const SizedBox(width: 4),
        SegmentedButton<_GroupBy>(
          segments: [
            const ButtonSegment(value: _GroupBy.none, label: Text('Aucun')),
            const ButtonSegment(value: _GroupBy.type, label: Text('Type')),
            const ButtonSegment(
                value: _GroupBy.license, label: Text('Licence')),
            if (showLayer)
              const ButtonSegment(
                  value: _GroupBy.layer, label: Text('Couche')),
          ],
          selected: {value},
          onSelectionChanged: (s) => onChanged(s.first),
          style: ButtonStyle(
            tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            visualDensity: VisualDensity.compact,
            textStyle: WidgetStateProperty.all(
                const TextStyle(fontSize: 11)),
          ),
        ),
      ],
    );
  }
}

// ─── Tuile groupe ─────────────────────────────────────────────────────────────

class _GroupHeaderTile extends StatelessWidget {
  final _GroupHeader header;
  final bool expanded;
  final VoidCallback onTap;

  const _GroupHeaderTile({
    required this.header,
    required this.expanded,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return InkWell(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
        color: theme.colorScheme.surfaceContainerLow,
        child: Row(
          children: [
            Icon(
              expanded ? Icons.expand_more : Icons.chevron_right,
              size: 18,
              color: theme.colorScheme.primary,
            ),
            const SizedBox(width: 6),
            Icon(Icons.folder_outlined, size: 15,
                color: theme.colorScheme.primary),
            const SizedBox(width: 6),
            Expanded(
              child: Text(
                header.key,
                style: TextStyle(
                    fontWeight: FontWeight.w600,
                    fontSize: 13,
                    color: theme.colorScheme.primary),
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 1),
              decoration: BoxDecoration(
                color: theme.colorScheme.primaryContainer,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text(
                '${header.count}',
                style: TextStyle(
                    fontSize: 11,
                    color: theme.colorScheme.onPrimaryContainer),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ─── Tuile composant ─────────────────────────────────────────────────────────

class _ComponentTile extends StatelessWidget {
  final _SbomComponent comp;
  final bool expanded;
  final VoidCallback onTap;

  const _ComponentTile({
    required this.comp,
    required this.expanded,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      children: [
        InkWell(
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.only(left: 36, right: 12, top: 5, bottom: 5),
            child: Row(
              children: [
                Icon(
                  expanded ? Icons.expand_more : Icons.chevron_right,
                  size: 14,
                  color: Colors.grey[400],
                ),
                const SizedBox(width: 4),
                const Icon(Icons.inventory_2_outlined, size: 14,
                    color: Colors.grey),
                const SizedBox(width: 8),
                Expanded(
                  flex: 3,
                  child: Text(
                    comp.name,
                    style: const TextStyle(
                        fontSize: 13, fontWeight: FontWeight.w500),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  flex: 2,
                  child: Text(
                    comp.version,
                    style: const TextStyle(
                        fontSize: 11,
                        fontFamily: 'monospace',
                        color: Colors.grey),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  flex: 3,
                  child: Text(
                    comp.license,
                    style: TextStyle(
                        fontSize: 10, color: Colors.blue[700]),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ),
        ),
        if (expanded)
          Container(
            margin: const EdgeInsets.only(left: 62, right: 12, bottom: 6),
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: theme.colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(6),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (comp.purl.isNotEmpty)
                  _DetailRow('PURL', comp.purl, copyable: true),
                _DetailRow('Version', comp.version),
                if (comp.type != 'package')
                  _DetailRow('Type', comp.type),
                if (comp.license.isNotEmpty)
                  _DetailRow('Licence', comp.license),
                if (comp.layer.isNotEmpty) _DetailRow('Couche', comp.layer),
              ],
            ),
          ),
        Divider(height: 1, color: Colors.grey[200]),
      ],
    );
  }
}

class _DetailRow extends StatelessWidget {
  final String label;
  final String value;
  final bool copyable;

  const _DetailRow(this.label, this.value, {this.copyable = false});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 3),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 58,
            child: Text(label,
                style: const TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: Colors.grey)),
          ),
          Expanded(
            child: SelectableText(
              value,
              style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
            ),
          ),
          if (copyable)
            IconButton(
              icon: const Icon(Icons.copy, size: 12),
              tooltip: 'Copier',
              onPressed: () =>
                  Clipboard.setData(ClipboardData(text: value)),
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(),
            ),
        ],
      ),
    );
  }
}

// ─── États vides / erreur ─────────────────────────────────────────────────────

class _EmptyView extends StatelessWidget {
  final bool hasOutputFiles;
  final VoidCallback onPick;

  const _EmptyView({required this.hasOutputFiles, required this.onPick});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.account_tree_outlined, size: 56, color: Colors.grey[300]),
          const SizedBox(height: 16),
          Text(
            hasOutputFiles
                ? 'Aucun fichier SBOM (JSON/JSON-LD) dans les sorties.'
                : 'Générez un SBOM ou ouvrez un fichier existant.',
            style: const TextStyle(color: Colors.grey, fontSize: 14),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            icon: const Icon(Icons.file_open_outlined, size: 16),
            label: const Text('Ouvrir un fichier SBOM'),
            onPressed: onPick,
          ),
        ],
      ),
    );
  }
}

class _ErrorView extends StatelessWidget {
  final String message;
  const _ErrorView({required this.message});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline, size: 40, color: Colors.red),
            const SizedBox(height: 12),
            Text(message,
                style: const TextStyle(color: Colors.red),
                textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }
}
