import 'dart:async';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../models/license_report.dart';
import '../models/sbom_result.dart';
import '../services/sbom_runner.dart';

/// Formats du rapport (valeurs de `sbom_generator licenses --format`).
enum _ReportFormat {
  asciidoc('asciidoc', 'adoc', 'AsciiDoc'),
  markdown('markdown', 'md', 'Markdown'),
  html('html', 'html', 'HTML'),
  csv('csv', 'csv', 'CSV'),
  json('json', 'json', 'JSON');

  final String cli;
  final String ext;
  final String label;
  const _ReportFormat(this.cli, this.ext, this.label);
}

enum _View { grouped, table }

enum _Sort { license, name, version }

/// Lit les licences d'un SBOM. Remplaçable dans les tests.
typedef LicenseLoader = Future<LicenseReportData> Function(String sbomPath);

/// Implémentation par défaut : `sbom-generator licenses -f json` dans un
/// fichier temporaire (la sortie standard mêle progression et journal).
Future<LicenseReportData> loadLicensesViaCli(String sbomPath) async {
  final dir = await Directory.systemTemp.createTemp('sbom_licenses_');
  final out = '${dir.path}/licences.json';
  final errors = <String>[];
  int? code;
  try {
    await for (final e in SbomRunner().run(
      args: ['licenses', '-i', sbomPath, '-f', 'json', '-o', out],
    )) {
      if (e is SbomLogEvent && e.isError) errors.add(e.line);
      if (e is SbomDoneEvent) code = e.exitCode;
    }
    if (code != 0) {
      throw Exception(
        errors.isEmpty ? 'code de sortie $code' : errors.join('\n'),
      );
    }
    return LicenseReportData.parse(await File(out).readAsString());
  } finally {
    unawaited(dir.delete(recursive: true).then((_) {}, onError: (_) {}));
  }
}

class SbomLicensesPanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  final LicenseLoader? loader;
  const SbomLicensesPanel({super.key, required this.outputFiles, this.loader});

  @override
  State<SbomLicensesPanel> createState() => _SbomLicensesPanelState();
}

class _SbomLicensesPanelState extends State<SbomLicensesPanel>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;

  String? _inputFile;
  final _outputCtrl = TextEditingController(text: 'licences.adoc');
  final _nameCtrl = TextEditingController();
  final _searchCtrl = TextEditingController();
  _ReportFormat _format = _ReportFormat.asciidoc;

  // Lecture des licences du SBOM sélectionné.
  bool _loading = false;
  String? _loadError;
  LicenseReportData? _data;
  _View _view = _View.grouped;
  _Sort _sort = _Sort.license;
  bool _sortAsc = true;

  // Génération du rapport.
  final SbomRunner _runner = SbomRunner();
  final List<String> _logLines = [];
  bool _running = false;
  int? _exitCode;
  String? _resultPath;

  List<OutputFile> get _sbomFiles => widget.outputFiles
      .where(
        (f) =>
            f.path.endsWith('.cdx.json') ||
            f.path.endsWith('.spdx.json') ||
            f.path.endsWith('.spdx3.jsonld'),
      )
      .toList();

  @override
  void dispose() {
    _outputCtrl.dispose();
    _nameCtrl.dispose();
    _searchCtrl.dispose();
    _runner.kill();
    super.dispose();
  }

  Future<void> _pickFile() async {
    final r = await FilePicker.pickFiles(
      dialogTitle: 'Sélectionner un fichier SBOM',
      type: FileType.custom,
      allowedExtensions: const ['json', 'jsonld'],
    );
    if (r == null || r.files.isEmpty || r.files.first.path == null) return;
    _selectFile(r.files.first.path!);
  }

  Future<void> _selectFile(String path) async {
    setState(() {
      _inputFile = path;
      _loading = true;
      _loadError = null;
      _data = null;
    });
    try {
      final data = await (widget.loader ?? loadLicensesViaCli)(path);
      if (!mounted || _inputFile != path) return;
      setState(() {
        _data = data;
        _loading = false;
      });
    } catch (e) {
      if (!mounted || _inputFile != path) return;
      setState(() {
        _loadError = '$e';
        _loading = false;
      });
    }
  }

  void _setFormat(_ReportFormat f) {
    // Adapte l'extension du fichier de sortie tant qu'il porte celle du
    // format précédent (ne touche pas à un nom saisi à la main).
    final cur = _outputCtrl.text.trim();
    final oldExt = '.${_format.ext}';
    setState(() {
      if (cur.endsWith(oldExt)) {
        _outputCtrl.text =
            '${cur.substring(0, cur.length - oldExt.length)}.${f.ext}';
      }
      _format = f;
    });
  }

  Future<void> _runLicenses() async {
    if (_inputFile == null || _outputCtrl.text.trim().isEmpty) return;
    final outputPath = _outputCtrl.text.trim();
    setState(() {
      _running = true;
      _exitCode = null;
      _resultPath = null;
      _logLines.clear();
    });

    final args = [
      'licenses',
      '-i',
      _inputFile!,
      '-f',
      _format.cli,
      '-o',
      outputPath,
    ];
    if (_nameCtrl.text.trim().isNotEmpty) {
      args.addAll(['-n', _nameCtrl.text.trim()]);
    }

    await for (final event in _runner.run(args: args)) {
      if (!mounted) return;
      if (event is SbomLogEvent) {
        setState(() => _logLines.add(event.line));
      } else if (event is SbomDoneEvent) {
        setState(() {
          _running = false;
          _exitCode = event.exitCode;
          _resultPath = event.exitCode == 0 ? outputPath : null;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final theme = Theme.of(context);
    final canRun =
        !_running && _inputFile != null && _outputCtrl.text.trim().isNotEmpty;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              OutlinedButton.icon(
                icon: const Icon(Icons.description_outlined, size: 16),
                label: const Text('Choisir un fichier…'),
                onPressed: _pickFile,
              ),
              const SizedBox(width: 8),
              if (_sbomFiles.isNotEmpty)
                MenuAnchor(
                  builder: (ctx, ctrl, child) => OutlinedButton.icon(
                    icon: const Icon(Icons.folder_outlined, size: 16),
                    label: const Text('Fichiers générés'),
                    onPressed: () => ctrl.isOpen ? ctrl.close() : ctrl.open(),
                  ),
                  menuChildren: [
                    for (final f in _sbomFiles)
                      MenuItemButton(
                        onPressed: () => _selectFile(f.path),
                        child: Text(f.path.split('/').last),
                      ),
                  ],
                ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  _inputFile == null
                      ? 'Aucun fichier sélectionné'
                      : _inputFile!,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurface.withValues(alpha: 0.6),
                  ),
                ),
              ),
            ],
          ),
        ),

        Expanded(child: _buildContent(theme)),

        const Divider(height: 1),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: Row(
            children: [
              SizedBox(
                width: 160,
                child: DropdownButtonFormField<_ReportFormat>(
                  key: const Key('licenses-format'),
                  initialValue: _format,
                  isExpanded: true,
                  isDense: true,
                  decoration: const InputDecoration(
                    labelText: 'Format',
                    isDense: true,
                    border: OutlineInputBorder(),
                  ),
                  items: [
                    for (final f in _ReportFormat.values)
                      DropdownMenuItem(value: f, child: Text(f.label)),
                  ],
                  onChanged: (f) {
                    if (f != null) _setFormat(f);
                  },
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _outputCtrl,
                  onChanged: (_) => setState(() {}),
                  decoration: const InputDecoration(
                    labelText: 'Fichier de sortie',
                    isDense: true,
                    border: OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _nameCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Nom du document (optionnel)',
                    isDense: true,
                    border: OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                icon: _running
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.gavel_outlined, size: 16),
                label: const Text('Générer'),
                onPressed: canRun ? _runLicenses : null,
              ),
            ],
          ),
        ),

        if (_exitCode != null)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            child: Row(
              children: [
                Icon(
                  _exitCode == 0 ? Icons.check_circle : Icons.error,
                  size: 16,
                  color: _exitCode == 0 ? Colors.green[700] : Colors.red[700],
                ),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    _exitCode == 0
                        ? 'Rapport généré → $_resultPath'
                        : 'Échec de la génération (code $_exitCode) — voir le journal ci-dessous.',
                  ),
                ),
              ],
            ),
          ),

        if (_logLines.isNotEmpty)
          SizedBox(
            height: 100,
            child: Container(
              width: double.infinity,
              color: theme.colorScheme.surfaceContainerLow,
              padding: const EdgeInsets.all(8),
              child: SingleChildScrollView(
                child: SelectableText(
                  _logLines.join('\n'),
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
              ),
            ),
          ),
      ],
    );
  }

  // ── Contenu : licences du SBOM ────────────────────────────────────────────

  Widget _buildContent(ThemeData theme) {
    final muted = TextStyle(
      color: theme.colorScheme.onSurface.withValues(alpha: 0.5),
    );
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_loadError != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: SelectableText(
            'Impossible de lire les licences : $_loadError',
            style: TextStyle(color: theme.colorScheme.error),
          ),
        ),
      );
    }
    final data = _data;
    if (data == null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(
            'Sélectionnez un fichier CycloneDX ou SPDX pour visualiser ses '
            'licences (regroupées par licence, avec signalement des licences '
            'copyleft et des paquets sans licence détectée), puis générer un '
            'rapport ci-dessous.',
            textAlign: TextAlign.center,
            style: muted,
          ),
        ),
      );
    }

    final groups = data.filter(_searchCtrl.text);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _summary(data, theme),
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 4, 12, 8),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  key: const Key('licenses-search'),
                  controller: _searchCtrl,
                  onChanged: (_) => setState(() {}),
                  decoration: InputDecoration(
                    hintText: 'Filtrer par licence ou par paquet…',
                    prefixIcon: const Icon(Icons.search, size: 18),
                    suffixIcon: _searchCtrl.text.isEmpty
                        ? null
                        : IconButton(
                            icon: const Icon(Icons.clear, size: 16),
                            onPressed: () =>
                                setState(() => _searchCtrl.clear()),
                          ),
                    isDense: true,
                    border: const OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              SegmentedButton<_View>(
                showSelectedIcon: false,
                segments: const [
                  ButtonSegment(
                    value: _View.grouped,
                    icon: Icon(Icons.account_tree_outlined, size: 16),
                    label: Text('Par licence'),
                  ),
                  ButtonSegment(
                    value: _View.table,
                    icon: Icon(Icons.table_rows_outlined, size: 16),
                    label: Text('Tableau'),
                  ),
                ],
                selected: {_view},
                onSelectionChanged: (s) => setState(() => _view = s.first),
              ),
            ],
          ),
        ),
        Expanded(
          child: groups.isEmpty
              ? Center(child: Text('Aucun résultat.', style: muted))
              : _view == _View.grouped
              ? _groupedView(groups)
              : _tableView(groups, theme),
        ),
      ],
    );
  }

  Widget _summary(LicenseReportData d, ThemeData theme) {
    Widget chip(String text, {Color? color}) => Chip(
      label: Text(text, style: const TextStyle(fontSize: 12)),
      visualDensity: VisualDensity.compact,
      side: color == null ? null : BorderSide(color: color),
      labelStyle: color == null ? null : TextStyle(color: color),
    );
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12),
      child: Wrap(
        spacing: 8,
        runSpacing: 0,
        children: [
          chip('${d.totalPackages} paquet(s)'),
          chip('${d.distinctLicenses} licence(s)'),
          if (d.strongCopyleftPackages > 0)
            chip(
              '${d.strongCopyleftPackages} copyleft fort',
              color: _categoryColor(LicenseCategory.strongCopyleft),
            ),
          if (d.weakCopyleftPackages > 0)
            chip(
              '${d.weakCopyleftPackages} copyleft faible',
              color: _categoryColor(LicenseCategory.weakCopyleft),
            ),
          if (d.unknownPackages > 0)
            chip(
              '${d.unknownPackages} sans licence',
              color: _categoryColor(LicenseCategory.unknown),
            ),
        ],
      ),
    );
  }

  static Color _categoryColor(LicenseCategory c) => switch (c) {
    LicenseCategory.strongCopyleft => Colors.red.shade700,
    LicenseCategory.weakCopyleft => Colors.orange.shade800,
    LicenseCategory.unknown => Colors.amber.shade800,
    LicenseCategory.permissive => Colors.green.shade700,
  };

  static String _categoryLabel(LicenseCategory c) => switch (c) {
    LicenseCategory.strongCopyleft => 'copyleft fort',
    LicenseCategory.weakCopyleft => 'copyleft faible',
    LicenseCategory.unknown => 'sans licence',
    LicenseCategory.permissive => '',
  };

  static String _licenseTitle(LicenseGroup g) =>
      g.license.isEmpty ? 'Sans licence détectée' : g.license;

  Widget _badge(LicenseCategory c) {
    final text = _categoryLabel(c);
    if (text.isEmpty) return const SizedBox.shrink();
    final color = _categoryColor(c);
    return Container(
      margin: const EdgeInsets.only(left: 8),
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        border: Border.all(color: color),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(text, style: TextStyle(fontSize: 11, color: color)),
    );
  }

  Widget _groupedView(List<LicenseGroup> groups) {
    final searching = _searchCtrl.text.trim().isNotEmpty;
    return ListView.builder(
      itemCount: groups.length,
      itemBuilder: (_, i) {
        final g = groups[i];
        return ExpansionTile(
          // La clé force la reconstruction (et donc le dépliage) quand le
          // filtre change.
          key: PageStorageKey('${g.license}|$searching'),
          initiallyExpanded: searching,
          dense: true,
          title: Row(
            children: [
              Flexible(
                child: Text(_licenseTitle(g), overflow: TextOverflow.ellipsis),
              ),
              _badge(g.category),
            ],
          ),
          trailing: Text('${g.packages.length}'),
          children: [
            for (final p in g.packages)
              ListTile(
                dense: true,
                visualDensity: VisualDensity.compact,
                contentPadding: const EdgeInsets.only(left: 32, right: 16),
                title: Text(p.label),
              ),
          ],
        );
      },
    );
  }

  Widget _tableView(List<LicenseGroup> groups, ThemeData theme) {
    final rows = <(String, LicenseCategory, LicensePackage)>[
      for (final g in groups)
        for (final p in g.packages) (g.license, g.category, p),
    ];
    int cmp(
      (String, LicenseCategory, LicensePackage) a,
      (String, LicenseCategory, LicensePackage) b,
    ) {
      final r = switch (_sort) {
        _Sort.license => a.$1.toLowerCase().compareTo(b.$1.toLowerCase()),
        _Sort.name => a.$3.name.toLowerCase().compareTo(
          b.$3.name.toLowerCase(),
        ),
        _Sort.version => a.$3.version.compareTo(b.$3.version),
      };
      return _sortAsc ? r : -r;
    }

    rows.sort(cmp);

    Widget header(String label, _Sort s, {int flex = 1}) => Expanded(
      flex: flex,
      child: InkWell(
        onTap: () => setState(() {
          if (_sort == s) {
            _sortAsc = !_sortAsc;
          } else {
            _sort = s;
            _sortAsc = true;
          }
        }),
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(
            children: [
              Text(label, style: const TextStyle(fontWeight: FontWeight.bold)),
              if (_sort == s)
                Icon(
                  _sortAsc ? Icons.arrow_upward : Icons.arrow_downward,
                  size: 14,
                ),
            ],
          ),
        ),
      ),
    );

    return Column(
      children: [
        Container(
          color: theme.colorScheme.surfaceContainerLow,
          padding: const EdgeInsets.symmetric(horizontal: 12),
          child: Row(
            children: [
              header('Paquet', _Sort.name, flex: 3),
              header('Version', _Sort.version, flex: 2),
              header('Licence', _Sort.license, flex: 4),
            ],
          ),
        ),
        Expanded(
          child: ListView.builder(
            itemCount: rows.length,
            itemExtent: 30,
            itemBuilder: (_, i) {
              final (license, cat, p) = rows[i];
              return Padding(
                padding: const EdgeInsets.symmetric(horizontal: 12),
                child: Row(
                  children: [
                    Expanded(
                      flex: 3,
                      child: Text(p.name, overflow: TextOverflow.ellipsis),
                    ),
                    Expanded(
                      flex: 2,
                      child: Text(p.version, overflow: TextOverflow.ellipsis),
                    ),
                    Expanded(
                      flex: 4,
                      child: Row(
                        children: [
                          Flexible(
                            child: Text(
                              license.isEmpty ? '—' : license,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          _badge(cat),
                        ],
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ),
      ],
    );
  }
}
