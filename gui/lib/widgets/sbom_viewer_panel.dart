import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

// ─── Modèles ──────────────────────────────────────────────────────────────────

class _Component {
  final String name;
  final String version;
  final String type;
  final String license;
  final String purl;
  final String description;
  final String url;

  const _Component({
    required this.name,
    required this.version,
    required this.type,
    required this.license,
    required this.purl,
    required this.description,
    required this.url,
  });

  static List<_Component> fromSbom(Map<String, dynamic> raw) {
    if (raw['bomFormat'] == 'CycloneDX') return _fromCdx(raw);
    if (raw.containsKey('spdxVersion')) return _fromSpdx(raw);
    return [];
  }

  static List<_Component> _fromCdx(Map<String, dynamic> d) {
    return ((d['components'] as List?) ?? []).map((e) {
      final c = e as Map<String, dynamic>;
      final lics = c['licenses'] as List? ?? [];
      String lic = '';
      if (lics.isNotEmpty) {
        final first = lics.first as Map<String, dynamic>;
        lic = first['expression'] as String? ??
            (first['license'] as Map<String, dynamic>?)?['id'] as String? ??
            (first['license'] as Map<String, dynamic>?)?['name'] as String? ??
            '';
      }
      final meta = (c['externalReferences'] as List? ?? []);
      String homepage = '';
      for (final ref in meta) {
        final r = ref as Map<String, dynamic>;
        if (r['type'] == 'website') {
          homepage = r['url'] as String? ?? '';
          break;
        }
      }
      return _Component(
        name: c['name'] as String? ?? '',
        version: c['version'] as String? ?? '',
        type: c['type'] as String? ?? 'library',
        license: lic,
        purl: c['purl'] as String? ?? '',
        description: c['description'] as String? ?? '',
        url: homepage,
      );
    }).where((c) => c.name.isNotEmpty).toList();
  }

  static List<_Component> _fromSpdx(Map<String, dynamic> d) {
    return ((d['packages'] as List?) ?? []).map((e) {
      final p = e as Map<String, dynamic>;
      String purl = '';
      for (final ref in (p['externalRefs'] as List? ?? [])) {
        final r = ref as Map<String, dynamic>;
        if (r['referenceType'] == 'purl') {
          purl = r['referenceLocator'] as String? ?? '';
          break;
        }
      }
      return _Component(
        name: p['name'] as String? ?? '',
        version: p['versionInfo'] as String? ?? '',
        type: 'package',
        license: p['licenseConcluded'] as String? ?? '',
        purl: purl,
        description: p['comment'] as String? ?? '',
        url: p['downloadLocation'] as String? ?? '',
      );
    }).where((c) => c.name.isNotEmpty).toList();
  }
}

// ─── Panel principal ───────────────────────────────────────────────────────────

class SbomViewerPanel extends StatefulWidget {
  const SbomViewerPanel({super.key});

  @override
  State<SbomViewerPanel> createState() => _SbomViewerPanelState();
}

class _SbomViewerPanelState extends State<SbomViewerPanel> {
  List<_Component> _all = [];
  List<_Component> _filtered = [];
  _Component? _selected;
  String? _docName;
  String? _format;
  String? _error;
  bool _loading = false;

  String _search = '';
  String _typeFilter = '';
  int _sortCol = 0;
  bool _sortAsc = true;

  final _searchCtrl = TextEditingController();

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  Future<void> _loadFile() async {
    final result = await FilePicker.pickFiles(
      dialogTitle: 'Ouvrir un fichier SBOM',
      type: FileType.custom,
      allowedExtensions: ['json', 'jsonld'],
    );
    if (result == null || result.files.single.path == null) return;

    setState(() {
      _loading = true;
      _error = null;
      _all = [];
      _filtered = [];
      _selected = null;
      _docName = null;
      _format = null;
      _search = '';
      _typeFilter = '';
      _searchCtrl.clear();
    });

    try {
      final raw = await File(result.files.single.path!).readAsString();
      final json = jsonDecode(raw) as Map<String, dynamic>;
      final components = _Component.fromSbom(json);

      String? docName;
      String? fmt;
      if (json['bomFormat'] == 'CycloneDX') {
        fmt = 'CycloneDX ${json['specVersion'] ?? ''}';
        final meta = json['metadata'] as Map<String, dynamic>?;
        final comp = meta?['component'] as Map<String, dynamic>?;
        docName = comp?['name'] as String?;
      } else if (json.containsKey('spdxVersion')) {
        fmt = json['spdxVersion'] as String;
        docName = json['name'] as String?;
      }

      setState(() {
        _all = components;
        _filtered = List.from(components);
        _docName = docName ?? result.files.single.name;
        _format = fmt;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = 'Impossible de parser le fichier : $e';
        _loading = false;
      });
    }
  }

  void _applyFilter() {
    final q = _search.toLowerCase();
    final t = _typeFilter.toLowerCase();
    var list = _all.where((c) {
      if (q.isNotEmpty &&
          !c.name.toLowerCase().contains(q) &&
          !c.version.toLowerCase().contains(q) &&
          !c.license.toLowerCase().contains(q) &&
          !c.purl.toLowerCase().contains(q)) {
        return false;
      }
      if (t.isNotEmpty && c.type.toLowerCase() != t) { return false; }
      return true;
    }).toList();

    list.sort((a, b) {
      final av = _sortField(a);
      final bv = _sortField(b);
      final cmp = av.compareTo(bv);
      return _sortAsc ? cmp : -cmp;
    });

    setState(() => _filtered = list);
  }

  String _sortField(_Component c) => switch (_sortCol) {
        0 => c.name,
        1 => c.version,
        2 => c.type,
        3 => c.license,
        _ => c.name,
      };

  void _sort(int col) {
    setState(() {
      if (_sortCol == col) {
        _sortAsc = !_sortAsc;
      } else {
        _sortCol = col;
        _sortAsc = true;
      }
    });
    _applyFilter();
  }

  Set<String> get _types => _all.map((c) => c.type).toSet();

  Map<String, int> get _ecosystems {
    final m = <String, int>{};
    for (final c in _all) { m[c.type] = (m[c.type] ?? 0) + 1; }
    return m;
  }

  Map<String, int> get _licenses {
    final m = <String, int>{};
    for (final c in _all) {
      final l = c.license.isEmpty ? 'Non spécifiée' : c.license;
      m[l] = (m[l] ?? 0) + 1;
    }
    return m;
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_all.isEmpty) {
      return _buildEmpty(context);
    }

    return Row(
      children: [
        Expanded(flex: 3, child: _buildTable(context)),
        if (_selected != null) ...[
          const VerticalDivider(width: 1),
          SizedBox(width: 280, child: _buildDetail(context, _selected!)),
        ],
      ],
    );
  }

  Widget _buildEmpty(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.manage_search_outlined,
              size: 56,
              color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.3)),
          const SizedBox(height: 16),
          Text(
            _error ?? 'Aucun fichier SBOM chargé',
            style: TextStyle(
              color: _error != null
                  ? Theme.of(context).colorScheme.error
                  : Theme.of(context)
                      .colorScheme
                      .onSurface
                      .withValues(alpha: 0.5),
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 20),
          FilledButton.icon(
            icon: const Icon(Icons.folder_open_outlined),
            label: const Text('Ouvrir un fichier SBOM…'),
            onPressed: _loadFile,
          ),
        ],
      ),
    );
  }

  Widget _buildTable(BuildContext context) {
    final theme = Theme.of(context);
    final eco = _ecosystems;
    final lic = _licenses;

    return Column(
      children: [
        // ── En-tête ──────────────────────────────────────────────────────────
        Container(
          color: theme.colorScheme.surfaceContainerLow,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      _docName ?? 'SBOM',
                      style: theme.textTheme.titleSmall
                          ?.copyWith(fontWeight: FontWeight.bold),
                      overflow: TextOverflow.ellipsis,
                    ),
                    if (_format != null)
                      Text(_format!,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurface.withValues(alpha: 0.6),
                          )),
                  ],
                ),
              ),
              // Badges statistiques
              _StatBadge('${_all.length}', 'composants'),
              const SizedBox(width: 8),
              _StatBadge('${eco.length}', 'types'),
              const SizedBox(width: 8),
              _StatBadge('${lic.length}', 'licences'),
              const SizedBox(width: 12),
              OutlinedButton.icon(
                icon: const Icon(Icons.folder_open_outlined, size: 16),
                label: const Text('Ouvrir…'),
                onPressed: _loadFile,
                style: OutlinedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap),
              ),
            ],
          ),
        ),

        // ── Barre filtre ─────────────────────────────────────────────────────
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _searchCtrl,
                  decoration: const InputDecoration(
                    hintText: 'Filtrer…',
                    prefixIcon: Icon(Icons.search, size: 18),
                    isDense: true,
                    border: OutlineInputBorder(),
                    contentPadding:
                        EdgeInsets.symmetric(vertical: 8, horizontal: 10),
                  ),
                  onChanged: (v) {
                    _search = v;
                    _applyFilter();
                  },
                ),
              ),
              const SizedBox(width: 8),
              DropdownButton<String>(
                value: _typeFilter.isEmpty ? null : _typeFilter,
                hint: const Text('Type'),
                isDense: true,
                items: [
                  const DropdownMenuItem(value: '', child: Text('Tous')),
                  ..._types.map((t) => DropdownMenuItem(
                        value: t,
                        child: Text(t),
                      )),
                ],
                onChanged: (v) {
                  _typeFilter = v ?? '';
                  _applyFilter();
                },
              ),
              const SizedBox(width: 8),
              Text(
                '${_filtered.length} / ${_all.length}',
                style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurface.withValues(alpha: 0.6)),
              ),
            ],
          ),
        ),

        // ── Tableau ───────────────────────────────────────────────────────────
        Expanded(
          child: _filtered.isEmpty
              ? Center(
                  child: Text('Aucun résultat',
                      style: TextStyle(
                          color: theme.colorScheme.onSurface.withValues(alpha: 0.5))),
                )
              : Column(
                  children: [
                    // En-tête tableau
                    Container(
                      color: theme.colorScheme.surfaceContainerLow,
                      child: Row(
                        children: [
                          _Header('Nom', 0, _sortCol, _sortAsc, _sort,
                              flex: 3),
                          _Header('Version', 1, _sortCol, _sortAsc, _sort,
                              flex: 2),
                          _Header('Type', 2, _sortCol, _sortAsc, _sort,
                              flex: 2),
                          _Header('Licence', 3, _sortCol, _sortAsc, _sort,
                              flex: 3),
                        ],
                      ),
                    ),
                    const Divider(height: 1),
                    // Lignes
                    Expanded(
                      child: ListView.separated(
                        itemCount: _filtered.length,
                        separatorBuilder: (ctx, idx) =>
                            const Divider(height: 1),
                        itemBuilder: (context, i) {
                          final c = _filtered[i];
                          final isSelected = _selected == c;
                          return InkWell(
                            onTap: () => setState(() =>
                                _selected = isSelected ? null : c),
                            child: Container(
                              color: isSelected
                                  ? theme.colorScheme.primaryContainer
                                      .withValues(alpha: 0.3)
                                  : null,
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 12, vertical: 7),
                              child: Row(
                                children: [
                                  Expanded(
                                    flex: 3,
                                    child: Text(c.name,
                                        style: const TextStyle(
                                            fontWeight: FontWeight.w500,
                                            fontSize: 13),
                                        overflow: TextOverflow.ellipsis),
                                  ),
                                  Expanded(
                                    flex: 2,
                                    child: Text(c.version,
                                        style: const TextStyle(
                                            fontFamily: 'monospace',
                                            fontSize: 12),
                                        overflow: TextOverflow.ellipsis),
                                  ),
                                  Expanded(
                                    flex: 2,
                                    child: _TypeBadge(c.type),
                                  ),
                                  Expanded(
                                    flex: 3,
                                    child: Text(
                                      c.license.isEmpty
                                          ? '—'
                                          : c.license,
                                      style: TextStyle(
                                          fontSize: 12,
                                          color: c.license.isEmpty
                                              ? theme.colorScheme.onSurface
                                                  .withValues(alpha: 0.4)
                                              : null),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          );
                        },
                      ),
                    ),
                  ],
                ),
        ),
      ],
    );
  }

  Widget _buildDetail(BuildContext context, _Component c) {
    final theme = Theme.of(context);
    return Container(
      color: theme.colorScheme.surfaceContainerLow,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Titre
          Container(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    c.name,
                    style: theme.textTheme.titleSmall
                        ?.copyWith(fontWeight: FontWeight.bold),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.close, size: 18),
                  onPressed: () => setState(() => _selected = null),
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _DetailRow('Version', c.version),
                  _DetailRow('Type', c.type),
                  if (c.license.isNotEmpty) _DetailRow('Licence', c.license),
                  if (c.description.isNotEmpty)
                    _DetailRow('Description', c.description),
                  if (c.url.isNotEmpty) _DetailRow('URL', c.url),
                  if (c.purl.isNotEmpty) ...[
                    const SizedBox(height: 12),
                    Text('PURL',
                        style: theme.textTheme.labelSmall?.copyWith(
                            color: theme.colorScheme.onSurface.withValues(alpha: 0.5),
                            letterSpacing: .5)),
                    const SizedBox(height: 4),
                    Row(
                      children: [
                        Expanded(
                          child: SelectableText(
                            c.purl,
                            style: const TextStyle(
                                fontFamily: 'monospace', fontSize: 11),
                          ),
                        ),
                        IconButton(
                          icon: const Icon(Icons.copy_outlined, size: 15),
                          tooltip: 'Copier le PURL',
                          onPressed: () {
                            Clipboard.setData(ClipboardData(text: c.purl));
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text('PURL copié'),
                                duration: Duration(seconds: 2),
                              ),
                            );
                          },
                          padding: EdgeInsets.zero,
                          constraints: const BoxConstraints(),
                        ),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Widgets utilitaires ──────────────────────────────────────────────────────

class _StatBadge extends StatelessWidget {
  final String value;
  final String label;
  const _StatBadge(this.value, this.label);

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(value,
            style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 16,
                color: Theme.of(context).colorScheme.primary)),
        Text(label,
            style: TextStyle(
                fontSize: 10,
                color: Theme.of(context)
                    .colorScheme
                    .onSurface
                    .withValues(alpha: 0.6))),
      ],
    );
  }
}

class _TypeBadge extends StatelessWidget {
  final String type;
  const _TypeBadge(this.type);

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        type,
        style: TextStyle(
          fontSize: 11,
          fontWeight: FontWeight.w600,
          color: Theme.of(context).colorScheme.onPrimaryContainer,
        ),
        overflow: TextOverflow.ellipsis,
      ),
    );
  }
}

class _Header extends StatelessWidget {
  final String label;
  final int col;
  final int sortCol;
  final bool sortAsc;
  final void Function(int) onSort;
  final int flex;

  const _Header(
    this.label,
    this.col,
    this.sortCol,
    this.sortAsc,
    this.onSort, {
    this.flex = 1,
  });

  @override
  Widget build(BuildContext context) {
    final active = sortCol == col;
    return Expanded(
      flex: flex,
      child: InkWell(
        onTap: () => onSort(col),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(label,
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                    color: Theme.of(context)
                        .colorScheme
                        .onSurface
                        .withValues(alpha: active ? 1.0 : 0.6),
                    letterSpacing: .4,
                  )),
              const SizedBox(width: 4),
              Icon(
                active
                    ? (sortAsc
                        ? Icons.arrow_upward
                        : Icons.arrow_downward)
                    : Icons.unfold_more,
                size: 13,
                color: Theme.of(context)
                    .colorScheme
                    .onSurface
                    .withValues(alpha: active ? 0.8 : 0.35),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _DetailRow extends StatelessWidget {
  final String label;
  final String value;
  const _DetailRow(this.label, this.value);

  @override
  Widget build(BuildContext context) {
    if (value.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label,
              style: Theme.of(context).textTheme.labelSmall?.copyWith(
                  color: Theme.of(context)
                      .colorScheme
                      .onSurface
                      .withValues(alpha: 0.5),
                  letterSpacing: .5)),
          const SizedBox(height: 2),
          SelectableText(value, style: const TextStyle(fontSize: 13)),
        ],
      ),
    );
  }
}
