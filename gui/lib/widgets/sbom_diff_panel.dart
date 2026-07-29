import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../models/sbom_result.dart';

// ─── Modèles ─────────────────────────────────────────────────────────────────

class _Comp {
  final String name;
  final String version;
  final String type;
  final String license;
  final String purl;

  const _Comp({
    required this.name,
    required this.version,
    required this.type,
    required this.license,
    required this.purl,
  });
}

class _SbomInfo {
  final String label; // nom du document / composant racine
  final String format;
  final List<_Comp> components;

  const _SbomInfo(
      {required this.label, required this.format, required this.components});

  static _SbomInfo? parse(String raw) {
    try {
      final d = jsonDecode(raw) as Map<String, dynamic>;
      if (d['bomFormat'] == 'CycloneDX') return _cdx(d);
      if (d.containsKey('spdxVersion')) return _spdx(d);
    } catch (_) {}
    return null;
  }

  static _SbomInfo _cdx(Map<String, dynamic> d) {
    final meta = (d['metadata'] as Map<String, dynamic>?) ?? {};
    final root = (meta['component'] as Map<String, dynamic>?) ?? {};
    final comps = (d['components'] as List? ?? []).map((e) {
      final c = e as Map<String, dynamic>;
      return _Comp(
        name: c['name'] as String? ?? '',
        version: c['version'] as String? ?? '',
        type: c['type'] as String? ?? 'unknown',
        license: _cdxLic(c['licenses']),
        purl: c['purl'] as String? ?? '',
      );
    }).toList();
    return _SbomInfo(
      label: (root['name'] as String? ?? '').isEmpty
          ? 'CycloneDX ${d['specVersion'] ?? ''}'
          : root['name'] as String,
      format: 'CycloneDX ${d['specVersion'] ?? ''}',
      components: comps,
    );
  }

  static String _cdxLic(dynamic lics) {
    if (lics == null) return '';
    final list = lics as List;
    if (list.isEmpty) return '';
    final first = list.first as Map<String, dynamic>;
    return first['expression'] as String? ??
        (first['license'] as Map<String, dynamic>?)?['id'] as String? ??
        '';
  }

  static _SbomInfo _spdx(Map<String, dynamic> d) {
    final pkgs = (d['packages'] as List? ?? []).map((e) {
      final p = e as Map<String, dynamic>;
      String purl = '';
      for (final ref in (p['externalRefs'] as List? ?? [])) {
        final r = ref as Map<String, dynamic>;
        if (r['referenceType'] == 'purl') {
          purl = r['referenceLocator'] as String? ?? '';
          break;
        }
      }
      return _Comp(
        name: p['name'] as String? ?? '',
        version: p['versionInfo'] as String? ?? '',
        type: 'package',
        license: p['licenseConcluded'] as String? ?? '',
        purl: purl,
      );
    }).toList();
    return _SbomInfo(
      label: d['name'] as String? ?? 'SPDX',
      format: d['spdxVersion'] as String? ?? 'SPDX',
      components: pkgs,
    );
  }
}

// ─── Résultat de comparaison ──────────────────────────────────────────────────

enum _Status { added, removed, changed, unchanged }

class _DiffEntry {
  final _Status status;
  final _Comp? compA;
  final _Comp? compB;

  const _DiffEntry({required this.status, this.compA, this.compB});

  String get name => (compB ?? compA)!.name;

  // true si la version a changé
  bool get versionChanged =>
      compA != null && compB != null && compA!.version != compB!.version;

  // true si la licence a changé
  bool get licenseChanged =>
      compA != null && compB != null && compA!.license != compB!.license;
}

List<_DiffEntry> _computeDiff(_SbomInfo a, _SbomInfo b) {
  final mapA = <String, _Comp>{};
  for (final c in a.components) {
    mapA[c.name.toLowerCase()] = c;
  }
  final mapB = <String, _Comp>{};
  for (final c in b.components) {
    mapB[c.name.toLowerCase()] = c;
  }

  final allKeys = {...mapA.keys, ...mapB.keys}.toList()..sort();

  return [
    for (final k in allKeys)
      if (!mapA.containsKey(k))
        _DiffEntry(status: _Status.added, compB: mapB[k])
      else if (!mapB.containsKey(k))
        _DiffEntry(status: _Status.removed, compA: mapA[k])
      else if (mapA[k]!.version != mapB[k]!.version ||
          mapA[k]!.license != mapB[k]!.license)
        _DiffEntry(status: _Status.changed, compA: mapA[k], compB: mapB[k])
      else
        _DiffEntry(status: _Status.unchanged, compA: mapA[k], compB: mapB[k]),
  ];
}

// ─── Panel ────────────────────────────────────────────────────────────────────

class SbomDiffPanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  const SbomDiffPanel({super.key, required this.outputFiles});

  @override
  State<SbomDiffPanel> createState() => _SbomDiffPanelState();
}

class _SbomDiffPanelState extends State<SbomDiffPanel>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;

  String? _pathA;
  String? _pathB;
  _SbomInfo? _infoA;
  _SbomInfo? _infoB;
  bool _loadingA = false;
  bool _loadingB = false;
  String? _errorA;
  String? _errorB;

  List<_DiffEntry>? _diff;

  // Filtres
  final Set<_Status> _shownStatuses = {
    _Status.added,
    _Status.removed,
    _Status.changed,
  };
  String _searchTerm = '';
  final _searchCtrl = TextEditingController();

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  List<OutputFile> get _sbomFiles => widget.outputFiles
      .where((f) =>
          f.path.endsWith('.cdx.json') ||
          f.path.endsWith('.spdx.json') ||
          f.path.endsWith('.spdx3.jsonld'))
      .toList();

  Future<void> _loadA(String path) async {
    setState(() {
      _loadingA = true;
      _errorA = null;
      _diff = null;
    });
    try {
      final raw = await File(path).readAsString();
      final info = _SbomInfo.parse(raw);
      setState(() {
        _loadingA = false;
        _pathA = path;
        _infoA = info;
        _errorA = info == null ? 'Format non reconnu.' : null;
      });
    } catch (e) {
      setState(() {
        _loadingA = false;
        _errorA = e.toString();
      });
    }
  }

  Future<void> _loadB(String path) async {
    setState(() {
      _loadingB = true;
      _errorB = null;
      _diff = null;
    });
    try {
      final raw = await File(path).readAsString();
      final info = _SbomInfo.parse(raw);
      setState(() {
        _loadingB = false;
        _pathB = path;
        _infoB = info;
        _errorB = info == null ? 'Format non reconnu.' : null;
      });
    } catch (e) {
      setState(() {
        _loadingB = false;
        _errorB = e.toString();
      });
    }
  }

  Future<void> _pickFile(bool isA, {bool filtered = true}) async {
    final r = await FilePicker.pickFiles(
      dialogTitle:
          'Sélectionner SBOM ${isA ? "A (référence)" : "B (comparé)"}',
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? ['json', 'jsonld'] : null,
    );
    if (r?.files.single.path != null) {
      if (isA) {
        _loadA(r!.files.single.path!);
      } else {
        _loadB(r!.files.single.path!);
      }
    }
  }

  void _compare() {
    final a = _infoA;
    final b = _infoB;
    if (a == null || b == null) return;
    setState(() {
      _diff = _computeDiff(a, b);
    });
  }

  List<_DiffEntry> get _filtered {
    final diff = _diff ?? [];
    var list = diff.where((e) => _shownStatuses.contains(e.status)).toList();
    if (_searchTerm.isNotEmpty) {
      final q = _searchTerm.toLowerCase();
      list = list.where((e) => e.name.toLowerCase().contains(q)).toList();
    }
    return list;
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final diff = _diff;
    final filtered = _filtered;

    final counts = diff == null
        ? null
        : {
            _Status.added: diff.where((e) => e.status == _Status.added).length,
            _Status.removed:
                diff.where((e) => e.status == _Status.removed).length,
            _Status.changed:
                diff.where((e) => e.status == _Status.changed).length,
            _Status.unchanged:
                diff.where((e) => e.status == _Status.unchanged).length,
          };

    return Column(
      children: [
        // ── Sélection des deux fichiers ──
        _FileSelectorBar(
          pathA: _pathA,
          pathB: _pathB,
          infoA: _infoA,
          infoB: _infoB,
          loadingA: _loadingA,
          loadingB: _loadingB,
          errorA: _errorA,
          errorB: _errorB,
          sbomFiles: _sbomFiles,
          canCompare: _infoA != null && _infoB != null,
          onPickA: ({bool filtered = true}) => _pickFile(true, filtered: filtered),
          onPickB: ({bool filtered = true}) => _pickFile(false, filtered: filtered),
          onSelectA: _loadA,
          onSelectB: _loadB,
          onCompare: _compare,
        ),

        // ── Résumé ──
        if (counts != null) _SummaryBar(counts: counts),

        // ── Filtres + recherche ──
        if (diff != null)
          _FilterBar(
            counts: counts!,
            shownStatuses: _shownStatuses,
            searchCtrl: _searchCtrl,
            searchTerm: _searchTerm,
            onStatusToggle: (s) => setState(() {
              if (_shownStatuses.contains(s)) {
                _shownStatuses.remove(s);
              } else {
                _shownStatuses.add(s);
              }
            }),
            onSearchChanged: (v) => setState(() => _searchTerm = v),
            onSearchClear: () {
              _searchCtrl.clear();
              setState(() => _searchTerm = '');
            },
            totalShown: filtered.length,
            totalAll: diff.length,
          ),

        // ── Tableau de comparaison ──
        if (diff != null)
          _DiffHeader(showUnchanged: _shownStatuses.contains(_Status.unchanged)),

        Expanded(
          child: diff == null
              ? _DiffEmpty(
                  infoA: _infoA,
                  infoB: _infoB,
                  onCompare: _compare,
                )
              : filtered.isEmpty
                  ? Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(Icons.search_off,
                              size: 40, color: Colors.grey),
                          const SizedBox(height: 8),
                          Text(
                            _searchTerm.isNotEmpty
                                ? 'Aucun résultat pour "$_searchTerm"'
                                : 'Aucun élément pour les filtres sélectionnés.',
                            style: const TextStyle(color: Colors.grey),
                          ),
                        ],
                      ),
                    )
                  : ListView.builder(
                      itemCount: filtered.length,
                      itemBuilder: (_, i) => _DiffRow(
                        entry: filtered[i],
                        showUnchanged:
                            _shownStatuses.contains(_Status.unchanged),
                      ),
                    ),
        ),
      ],
    );
  }
}

// ─── Barre de sélection des deux fichiers ─────────────────────────────────────

class _FileSelectorBar extends StatelessWidget {
  final String? pathA;
  final String? pathB;
  final _SbomInfo? infoA;
  final _SbomInfo? infoB;
  final bool loadingA;
  final bool loadingB;
  final String? errorA;
  final String? errorB;
  final List<OutputFile> sbomFiles;
  final bool canCompare;
  final void Function({bool filtered}) onPickA;
  final void Function({bool filtered}) onPickB;
  final ValueChanged<String> onSelectA;
  final ValueChanged<String> onSelectB;
  final VoidCallback onCompare;

  const _FileSelectorBar({
    required this.pathA,
    required this.pathB,
    required this.infoA,
    required this.infoB,
    required this.loadingA,
    required this.loadingB,
    required this.errorA,
    required this.errorB,
    required this.sbomFiles,
    required this.canCompare,
    required this.onPickA,
    required this.onPickB,
    required this.onSelectA,
    required this.onSelectB,
    required this.onCompare,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      color: theme.colorScheme.surfaceContainerHigh,
      child: Row(
        children: [
          // ── SBOM A ──
          Expanded(
            child: _FileSlot(
              label: 'A – Référence',
              path: pathA,
              info: infoA,
              loading: loadingA,
              error: errorA,
              sbomFiles: sbomFiles,
              color: const Color(0xFF1565C0),
              onPick: onPickA,
              onSelect: onSelectA,
            ),
          ),

          // ── Bouton Comparer ──
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.compare_arrows, size: 22, color: Colors.grey),
                const SizedBox(height: 4),
                FilledButton(
                  onPressed: canCompare ? onCompare : null,
                  style: FilledButton.styleFrom(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 8),
                    minimumSize: Size.zero,
                  ),
                  child: const Text('Comparer',
                      style: TextStyle(fontSize: 12)),
                ),
              ],
            ),
          ),

          // ── SBOM B ──
          Expanded(
            child: _FileSlot(
              label: 'B – Comparé',
              path: pathB,
              info: infoB,
              loading: loadingB,
              error: errorB,
              sbomFiles: sbomFiles,
              color: const Color(0xFF6A1B9A),
              onPick: onPickB,
              onSelect: onSelectB,
            ),
          ),
        ],
      ),
    );
  }
}

class _FileSlot extends StatelessWidget {
  final String label;
  final String? path;
  final _SbomInfo? info;
  final bool loading;
  final String? error;
  final List<OutputFile> sbomFiles;
  final Color color;
  final void Function({bool filtered}) onPick;
  final ValueChanged<String> onSelect;

  const _FileSlot({
    required this.label,
    required this.path,
    required this.info,
    required this.loading,
    required this.error,
    required this.sbomFiles,
    required this.color,
    required this.onPick,
    required this.onSelect,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        border: Border.all(
            color: error != null
                ? Colors.red[300]!
                : info != null
                    ? color.withValues(alpha: 0.5)
                    : Colors.grey[300]!),
        borderRadius: BorderRadius.circular(6),
        color: info != null
            ? color.withValues(alpha: 0.05)
            : null,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label,
              style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.bold,
                  color: color)),
          const SizedBox(height: 4),
          Row(
            children: [
              Expanded(
                child: loading
                    ? const SizedBox(
                        height: 14,
                        width: 14,
                        child: CircularProgressIndicator(strokeWidth: 2))
                    : Text(
                        error != null
                            ? '⚠ $error'
                            : path != null
                                ? (info?.label ?? path!.split('/').last)
                                : 'Aucun fichier sélectionné',
                        style: TextStyle(
                            fontSize: 12,
                            color: error != null
                                ? Colors.red
                                : path != null
                                    ? null
                                    : Colors.grey),
                        overflow: TextOverflow.ellipsis,
                      ),
              ),
              const SizedBox(width: 4),
              if (sbomFiles.isNotEmpty)
                MenuAnchor(
                  builder: (ctx, ctrl, child) => IconButton(
                    icon: const Icon(Icons.folder_outlined, size: 16),
                    tooltip: 'Fichiers générés',
                    onPressed: () =>
                        ctrl.isOpen ? ctrl.close() : ctrl.open(),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                  menuChildren: [
                    for (final f in sbomFiles)
                      MenuItemButton(
                        onPressed: () => onSelect(f.path),
                        child: Text(f.path.split('/').last,
                            style: const TextStyle(fontSize: 12)),
                      ),
                  ],
                ),
              _FilePickButton(onPick: onPick),
            ],
          ),
          if (info != null)
            Text(
              '${info!.format} · ${info!.components.length} composants',
              style: TextStyle(fontSize: 10, color: color.withValues(alpha: 0.8)),
            ),
        ],
      ),
    );
  }
}

// ─── Bouton sélection fichier (filtré / tous) ─────────────────────────────────

class _FilePickButton extends StatefulWidget {
  final void Function({bool filtered}) onPick;
  const _FilePickButton({required this.onPick});

  @override
  State<_FilePickButton> createState() => _FilePickButtonState();
}

class _FilePickButtonState extends State<_FilePickButton> {
  final _menu = MenuController();

  @override
  Widget build(BuildContext context) {
    return MenuAnchor(
      controller: _menu,
      menuChildren: [
        MenuItemButton(
          leadingIcon: const Icon(Icons.filter_alt_outlined, size: 16),
          onPressed: () {
            _menu.close();
            widget.onPick(filtered: true);
          },
          child: const Text('.json / .jsonld'),
        ),
        MenuItemButton(
          leadingIcon: const Icon(Icons.folder_open, size: 16),
          onPressed: () {
            _menu.close();
            widget.onPick(filtered: false);
          },
          child: const Text('Tous les fichiers'),
        ),
      ],
      builder: (context, ctrl, _) => IconButton(
        icon: const Icon(Icons.file_open_outlined, size: 16),
        tooltip: 'Ouvrir un fichier…',
        onPressed: () => ctrl.isOpen ? ctrl.close() : ctrl.open(),
        padding: EdgeInsets.zero,
        constraints: const BoxConstraints(),
      ),
    );
  }
}

// ─── Barre de résumé ──────────────────────────────────────────────────────────

class _SummaryBar extends StatelessWidget {
  final Map<_Status, int> counts;
  const _SummaryBar({required this.counts});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      color: Theme.of(context).colorScheme.surfaceContainerLow,
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          _SummaryChip(
              icon: Icons.add_circle_outline,
              label: 'Ajoutés',
              value: counts[_Status.added] ?? 0,
              color: Colors.green[700]!),
          const SizedBox(width: 16),
          _SummaryChip(
              icon: Icons.remove_circle_outline,
              label: 'Supprimés',
              value: counts[_Status.removed] ?? 0,
              color: Colors.red[700]!),
          const SizedBox(width: 16),
          _SummaryChip(
              icon: Icons.change_circle_outlined,
              label: 'Modifiés',
              value: counts[_Status.changed] ?? 0,
              color: Colors.orange[700]!),
          const SizedBox(width: 16),
          _SummaryChip(
              icon: Icons.check_circle_outline,
              label: 'Inchangés',
              value: counts[_Status.unchanged] ?? 0,
              color: Colors.grey[600]!),
        ],
      ),
    );
  }
}

class _SummaryChip extends StatelessWidget {
  final IconData icon;
  final String label;
  final int value;
  final Color color;
  const _SummaryChip(
      {required this.icon,
      required this.label,
      required this.value,
      required this.color});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 16, color: color),
        const SizedBox(width: 4),
        Text('$value',
            style: TextStyle(
                fontWeight: FontWeight.bold, fontSize: 14, color: color)),
        const SizedBox(width: 3),
        Text(label, style: TextStyle(fontSize: 11, color: color)),
      ],
    );
  }
}

// ─── Barre de filtres ─────────────────────────────────────────────────────────

class _FilterBar extends StatelessWidget {
  final Map<_Status, int> counts;
  final Set<_Status> shownStatuses;
  final TextEditingController searchCtrl;
  final String searchTerm;
  final ValueChanged<_Status> onStatusToggle;
  final ValueChanged<String> onSearchChanged;
  final VoidCallback onSearchClear;
  final int totalShown;
  final int totalAll;

  const _FilterBar({
    required this.counts,
    required this.shownStatuses,
    required this.searchCtrl,
    required this.searchTerm,
    required this.onStatusToggle,
    required this.onSearchChanged,
    required this.onSearchClear,
    required this.totalShown,
    required this.totalAll,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      color: Theme.of(context).colorScheme.surfaceContainerLow,
      child: Row(
        children: [
          _FilterChip2(
            label: '➕ Ajoutés (${counts[_Status.added]})',
            selected: shownStatuses.contains(_Status.added),
            selectedColor: Colors.green[700]!,
            onTap: () => onStatusToggle(_Status.added),
          ),
          const SizedBox(width: 6),
          _FilterChip2(
            label: '➖ Supprimés (${counts[_Status.removed]})',
            selected: shownStatuses.contains(_Status.removed),
            selectedColor: Colors.red[700]!,
            onTap: () => onStatusToggle(_Status.removed),
          ),
          const SizedBox(width: 6),
          _FilterChip2(
            label: '🔄 Modifiés (${counts[_Status.changed]})',
            selected: shownStatuses.contains(_Status.changed),
            selectedColor: Colors.orange[700]!,
            onTap: () => onStatusToggle(_Status.changed),
          ),
          const SizedBox(width: 6),
          _FilterChip2(
            label: '✓ Inchangés (${counts[_Status.unchanged]})',
            selected: shownStatuses.contains(_Status.unchanged),
            selectedColor: Colors.grey[600]!,
            onTap: () => onStatusToggle(_Status.unchanged),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: TextField(
              controller: searchCtrl,
              onChanged: onSearchChanged,
              decoration: InputDecoration(
                hintText: 'Filtrer par nom…',
                isDense: true,
                prefixIcon: const Icon(Icons.search, size: 16),
                suffixIcon: searchTerm.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear, size: 14),
                        onPressed: onSearchClear,
                        padding: EdgeInsets.zero,
                      )
                    : null,
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
                border: const OutlineInputBorder(),
              ),
              style: const TextStyle(fontSize: 12),
            ),
          ),
          const SizedBox(width: 8),
          Text(
            '$totalShown / $totalAll',
            style: const TextStyle(fontSize: 11, color: Colors.grey),
          ),
        ],
      ),
    );
  }
}

class _FilterChip2 extends StatelessWidget {
  final String label;
  final bool selected;
  final Color selectedColor;
  final VoidCallback onTap;

  const _FilterChip2({
    required this.label,
    required this.selected,
    required this.selectedColor,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: selected
              ? selectedColor.withValues(alpha: 0.12)
              : Colors.grey[100],
          border: Border.all(
            color: selected ? selectedColor : Colors.grey[300]!,
            width: selected ? 1.2 : 0.8,
          ),
          borderRadius: BorderRadius.circular(16),
        ),
        child: Text(
          label,
          style: TextStyle(
              fontSize: 11,
              color: selected ? selectedColor : Colors.grey[600]),
        ),
      ),
    );
  }
}

// ─── En-tête du tableau diff ──────────────────────────────────────────────────

class _DiffHeader extends StatelessWidget {
  final bool showUnchanged;
  const _DiffHeader({required this.showUnchanged});

  @override
  Widget build(BuildContext context) {
    return Container(
      color: Theme.of(context).colorScheme.surfaceContainerHigh,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: Row(
        children: [
          const SizedBox(width: 24),
          const SizedBox(
            width: 72,
            child: Text('STATUT',
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: Colors.grey)),
          ),
          const Expanded(
            flex: 3,
            child: Text('NOM',
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: Colors.grey)),
          ),
          const Expanded(
            flex: 2,
            child: Text('VERSION A',
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: Colors.grey)),
          ),
          const Expanded(
            flex: 2,
            child: Text('VERSION B',
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: Colors.grey)),
          ),
          const Expanded(
            flex: 2,
            child: Text('LICENCE',
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: Colors.grey)),
          ),
        ],
      ),
    );
  }
}

// ─── Ligne de diff ────────────────────────────────────────────────────────────

class _DiffRow extends StatelessWidget {
  final _DiffEntry entry;
  final bool showUnchanged;

  const _DiffRow({required this.entry, required this.showUnchanged});

  static const _colors = {
    _Status.added: Color(0xFFE8F5E9),
    _Status.removed: Color(0xFFFFEBEE),
    _Status.changed: Color(0xFFFFF8E1),
    _Status.unchanged: null,
  };

  static const _borderColors = {
    _Status.added: Color(0xFF81C784),
    _Status.removed: Color(0xFFE57373),
    _Status.changed: Color(0xFFFFB74D),
    _Status.unchanged: null,
  };

  @override
  Widget build(BuildContext context) {
    final s = entry.status;
    final bg = _colors[s];
    final border = _borderColors[s];
    final compA = entry.compA;
    final compB = entry.compB;

    final (icon, iconColor, statusLabel) = switch (s) {
      _Status.added => (Icons.add_circle, Colors.green[700]!, 'Ajouté'),
      _Status.removed => (Icons.remove_circle, Colors.red[700]!, 'Supprimé'),
      _Status.changed => (Icons.change_circle, Colors.orange[700]!, 'Modifié'),
      _Status.unchanged => (
          Icons.check_circle,
          Colors.grey[400]!,
          'Inchangé'
        ),
    };

    final versionA = compA?.version ?? '';
    final versionB = compB?.version ?? '';
    final licA = compA?.license ?? '';
    final licB = compB?.license ?? '';

    return Container(
      decoration: BoxDecoration(
        color: bg,
        border: border != null
            ? Border(left: BorderSide(color: border, width: 3))
            : null,
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
        child: Row(
          children: [
            Icon(icon, size: 14, color: iconColor),
            const SizedBox(width: 10),
            SizedBox(
              width: 72,
              child: Text(
                statusLabel,
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: iconColor),
              ),
            ),
            Expanded(
              flex: 3,
              child: Text(
                entry.name,
                style: const TextStyle(
                    fontSize: 12, fontWeight: FontWeight.w500),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            // Version A
            Expanded(
              flex: 2,
              child: Text(
                versionA,
                style: TextStyle(
                    fontSize: 11,
                    fontFamily: 'monospace',
                    color: entry.versionChanged ? Colors.red[700] : Colors.grey[600]),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            // Version B
            Expanded(
              flex: 2,
              child: Text(
                versionB,
                style: TextStyle(
                    fontSize: 11,
                    fontFamily: 'monospace',
                    color: entry.versionChanged
                        ? Colors.green[700]
                        : Colors.grey[600]),
                overflow: TextOverflow.ellipsis,
              ),
            ),
            // Licence (affiche A→B si différente)
            Expanded(
              flex: 2,
              child: entry.licenseChanged
                  ? Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(licA,
                            style: TextStyle(
                                fontSize: 10,
                                decoration: TextDecoration.lineThrough,
                                color: Colors.red[700]),
                            overflow: TextOverflow.ellipsis),
                        Text(licB,
                            style: TextStyle(
                                fontSize: 10, color: Colors.green[700]),
                            overflow: TextOverflow.ellipsis),
                      ],
                    )
                  : Text(
                      licB.isNotEmpty ? licB : licA,
                      style: const TextStyle(
                          fontSize: 10, color: Colors.grey),
                      overflow: TextOverflow.ellipsis,
                    ),
            ),
          ],
        ),
      ),
    );
  }
}

// ─── État initial ─────────────────────────────────────────────────────────────

class _DiffEmpty extends StatelessWidget {
  final _SbomInfo? infoA;
  final _SbomInfo? infoB;
  final VoidCallback onCompare;

  const _DiffEmpty(
      {required this.infoA, required this.infoB, required this.onCompare});

  @override
  Widget build(BuildContext context) {
    final bothReady = infoA != null && infoB != null;
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.compare_arrows,
              size: 56, color: Colors.grey[300]),
          const SizedBox(height: 16),
          Text(
            bothReady
                ? 'Cliquez sur "Comparer" pour lancer l\'analyse.'
                : 'Sélectionnez deux fichiers SBOM (A et B) pour les comparer.',
            style: const TextStyle(color: Colors.grey, fontSize: 14),
            textAlign: TextAlign.center,
          ),
          if (bothReady) ...[
            const SizedBox(height: 16),
            FilledButton.icon(
              icon: const Icon(Icons.compare_arrows, size: 16),
              label: const Text('Comparer'),
              onPressed: onCompare,
            ),
          ],
        ],
      ),
    );
  }
}
