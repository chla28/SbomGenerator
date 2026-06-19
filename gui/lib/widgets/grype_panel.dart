import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/sbom_result.dart';
import '../services/grype_runner.dart';

// ─── Modèle de vulnérabilité ──────────────────────────────────────────────────

class GrypeVuln {
  final String id;
  final String severity;
  final String packageName;
  final String installedVersion;
  final String fixedVersion;
  final String packageType;

  const GrypeVuln({
    required this.id,
    required this.severity,
    required this.packageName,
    required this.installedVersion,
    required this.fixedVersion,
    required this.packageType,
  });

  static int _order(String s) => switch (s.toLowerCase()) {
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        'low' => 3,
        'negligible' => 4,
        _ => 5,
      };

  static List<GrypeVuln> fromJson(String raw) {
    try {
      final data = jsonDecode(raw) as Map<String, dynamic>;
      final matches = data['matches'] as List? ?? [];
      final vulns = matches.map((m) {
        final vuln = m['vulnerability'] as Map<String, dynamic>? ?? {};
        final artifact = m['artifact'] as Map<String, dynamic>? ?? {};
        final fix = vuln['fix'] as Map<String, dynamic>? ?? {};
        final fixVersions =
            (fix['versions'] as List?)?.cast<String>() ?? [];
        final fixState = fix['state'] as String? ?? '';
        return GrypeVuln(
          id: vuln['id'] as String? ?? '',
          severity: vuln['severity'] as String? ?? 'Unknown',
          packageName: artifact['name'] as String? ?? '',
          installedVersion: artifact['version'] as String? ?? '',
          fixedVersion:
              fixVersions.isNotEmpty ? fixVersions.first : fixState,
          packageType: artifact['type'] as String? ?? '',
        );
      }).toList();
      vulns.sort((a, b) => _order(a.severity).compareTo(_order(b.severity)));
      return vulns;
    } catch (_) {
      return [];
    }
  }
}

// ─── Widget principal ─────────────────────────────────────────────────────────

class GrypePanel extends StatefulWidget {
  final List<OutputFile> outputFiles;

  const GrypePanel({super.key, required this.outputFiles});

  @override
  State<GrypePanel> createState() => _GrypePanelState();
}

class _GrypePanelState extends State<GrypePanel>
    with SingleTickerProviderStateMixin {
  final _runner = GrypeRunner();
  final _fileCtrl = TextEditingController();
  final _configCtrl = TextEditingController();
  final _templateCtrl =
      TextEditingController(text: './grype_csv.tmpl');
  late final TabController _resultTabs;

  // Options scan
  bool _platformLinux = true;
  bool _addCpesIfNone = true;
  bool _byCve = true;
  String _distroVersion = '9';

  // Options filtrage
  String _failOn = '';
  bool _onlyFixed = false;

  // État exécution
  bool _isRunning = false;
  List<GrypeVuln> _vulns = [];
  String _jsonOutput = '';
  String _templateOutput = '';
  String? _error;
  int? _exitCode;

  static const _severities = [
    '',
    'negligible',
    'low',
    'medium',
    'high',
    'critical',
  ];

  static const _distroVersions = ['', '7', '8', '9', '10'];

  @override
  void initState() {
    super.initState();
    _resultTabs = TabController(length: 3, vsync: this);
    _updateAutoFile();
  }

  @override
  void didUpdateWidget(GrypePanel old) {
    super.didUpdateWidget(old);
    if (widget.outputFiles != old.outputFiles) _updateAutoFile();
  }

  @override
  void dispose() {
    _runner.kill();
    _fileCtrl.dispose();
    _configCtrl.dispose();
    _templateCtrl.dispose();
    _resultTabs.dispose();
    super.dispose();
  }

  void _updateAutoFile() {
    if (widget.outputFiles.isEmpty || _fileCtrl.text.isNotEmpty) return;
    final preferred = widget.outputFiles
        .where((f) =>
            f.path.endsWith('.cdx.json') ||
            f.path.endsWith('.spdx.json'))
        .firstOrNull;
    final fallback = widget.outputFiles
        .where(
            (f) => f.path.endsWith('.json') || f.path.endsWith('.jsonld'))
        .firstOrNull;
    final file = preferred ?? fallback;
    if (file != null) setState(() => _fileCtrl.text = file.path);
  }

  Future<void> _pickSbomFile() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['json', 'jsonld'],
      dialogTitle: 'Choisir un fichier SBOM',
    );
    if (result?.files.single.path != null) {
      setState(() => _fileCtrl.text = result!.files.single.path!);
    }
  }

  Future<void> _pickConfigFile() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['yaml', 'yml'],
      dialogTitle: 'Choisir grype.yaml',
    );
    if (result?.files.single.path != null) {
      setState(() => _configCtrl.text = result!.files.single.path!);
    }
  }

  Future<void> _pickTemplateFile() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['tmpl', 'tpl', 'txt'],
      dialogTitle: 'Choisir un fichier template Grype',
    );
    if (result?.files.single.path != null) {
      setState(() => _templateCtrl.text = result!.files.single.path!);
    }
  }

  void _analyze() {
    final sbomFile = _fileCtrl.text.trim();
    if (sbomFile.isEmpty) {
      setState(() => _error = 'Veuillez sélectionner un fichier SBOM.');
      return;
    }
    if (!File(sbomFile).existsSync()) {
      setState(() => _error = 'Fichier introuvable : $sbomFile');
      return;
    }

    setState(() {
      _isRunning = true;
      _vulns = [];
      _jsonOutput = '';
      _templateOutput = '';
      _error = null;
      _exitCode = null;
    });

    final tmpl = _templateCtrl.text.trim();

    _runner
        .run(
          sbomFile: sbomFile,
          failOn: _failOn.isEmpty ? null : _failOn,
          onlyFixed: _onlyFixed,
          configFile:
              _configCtrl.text.trim().isEmpty ? null : _configCtrl.text.trim(),
          platformLinux: _platformLinux,
          addCpesIfNone: _addCpesIfNone,
          byCve: _byCve,
          distroVersion:
              _distroVersion.isEmpty ? null : _distroVersion,
          templateFile: tmpl.isEmpty ? null : tmpl,
        )
        .listen(
      (event) {
        if (!mounted) return;
        switch (event) {
          case GrypeOutputEvent(:final jsonOutput):
            setState(() {
              _jsonOutput = jsonOutput;
              _vulns = GrypeVuln.fromJson(jsonOutput);
            });
          case GrypeTemplateEvent(:final content):
            setState(() {
              _templateOutput = content;
              // Basculer vers l'onglet Template
              _resultTabs.animateTo(2);
            });
          case GrypeDoneEvent(:final exitCode, :final stderr):
            setState(() {
              _isRunning = false;
              _exitCode = exitCode;
              if (stderr != null && _vulns.isEmpty) _error = stderr;
            });
        }
      },
      onError: (Object e) {
        if (mounted) {
          setState(() {
            _isRunning = false;
            _error = e.toString();
            _exitCode = 1;
          });
        }
      },
    );
  }

  void _stop() {
    _runner.kill();
    setState(() => _isRunning = false);
  }

  @override
  Widget build(BuildContext context) {
    final showResults =
        _vulns.isNotEmpty || _jsonOutput.isNotEmpty || _templateOutput.isNotEmpty;

    return Column(
      children: [
        _ConfigSection(
          fileCtrl: _fileCtrl,
          configCtrl: _configCtrl,
          templateCtrl: _templateCtrl,
          platformLinux: _platformLinux,
          addCpesIfNone: _addCpesIfNone,
          byCve: _byCve,
          distroVersion: _distroVersion,
          distroVersions: _distroVersions,
          failOn: _failOn,
          onlyFixed: _onlyFixed,
          severities: _severities,
          isRunning: _isRunning,
          onPickSbom: _pickSbomFile,
          onPickConfig: _pickConfigFile,
          onPickTemplate: _pickTemplateFile,
          onPlatformLinuxChanged: (v) =>
              setState(() => _platformLinux = v ?? true),
          onAddCpesIfNoneChanged: (v) =>
              setState(() => _addCpesIfNone = v ?? true),
          onByCveChanged: (v) => setState(() => _byCve = v ?? true),
          onDistroVersionChanged: (v) =>
              setState(() => _distroVersion = v),
          onFailOnChanged: (v) => setState(() => _failOn = v),
          onOnlyFixedChanged: (v) =>
              setState(() => _onlyFixed = v ?? false),
          onRun: _analyze,
          onStop: _stop,
        ),
        const Divider(height: 1),
        if (_isRunning) const LinearProgressIndicator(minHeight: 3),
        if (!_isRunning && _exitCode != null)
          _GrypeBanner(
              exitCode: _exitCode!, vulns: _vulns, error: _error),
        if (!_isRunning && _error != null && _vulns.isEmpty)
          _ErrorBanner(error: _error!),
        if (showResults) ...[
          ColoredBox(
            color:
                Theme.of(context).colorScheme.surfaceContainerLow,
            child: TabBar(
              controller: _resultTabs,
              tabs: [
                Tab(
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.table_rows_outlined, size: 16),
                      const SizedBox(width: 6),
                      Text('Table (${_vulns.length})'),
                    ],
                  ),
                ),
                const Tab(
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.data_object, size: 16),
                      SizedBox(width: 6),
                      Text('JSON'),
                    ],
                  ),
                ),
                const Tab(
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.article_outlined, size: 16),
                      SizedBox(width: 6),
                      Text('Template'),
                    ],
                  ),
                ),
              ],
            ),
          ),
          Expanded(
            child: TabBarView(
              controller: _resultTabs,
              children: [
                _VulnTableView(vulns: _vulns),
                _JsonView(json: _jsonOutput),
                _TemplateView(
                  content: _templateOutput,
                  hasTemplate: _templateCtrl.text.trim().isNotEmpty,
                ),
              ],
            ),
          ),
        ] else if (_isRunning)
          const Expanded(child: _GrypeRunningHint())
        else
          const Expanded(child: _GrypeEmptyHint()),
      ],
    );
  }
}

// ─── Section configuration ────────────────────────────────────────────────────

class _ConfigSection extends StatelessWidget {
  final TextEditingController fileCtrl;
  final TextEditingController configCtrl;
  final TextEditingController templateCtrl;
  final bool platformLinux;
  final bool addCpesIfNone;
  final bool byCve;
  final String distroVersion;
  final List<String> distroVersions;
  final String failOn;
  final bool onlyFixed;
  final List<String> severities;
  final bool isRunning;
  final VoidCallback onPickSbom;
  final VoidCallback onPickConfig;
  final VoidCallback onPickTemplate;
  final ValueChanged<bool?> onPlatformLinuxChanged;
  final ValueChanged<bool?> onAddCpesIfNoneChanged;
  final ValueChanged<bool?> onByCveChanged;
  final ValueChanged<String> onDistroVersionChanged;
  final ValueChanged<String> onFailOnChanged;
  final ValueChanged<bool?> onOnlyFixedChanged;
  final VoidCallback onRun;
  final VoidCallback onStop;

  const _ConfigSection({
    required this.fileCtrl,
    required this.configCtrl,
    required this.templateCtrl,
    required this.platformLinux,
    required this.addCpesIfNone,
    required this.byCve,
    required this.distroVersion,
    required this.distroVersions,
    required this.failOn,
    required this.onlyFixed,
    required this.severities,
    required this.isRunning,
    required this.onPickSbom,
    required this.onPickConfig,
    required this.onPickTemplate,
    required this.onPlatformLinuxChanged,
    required this.onAddCpesIfNoneChanged,
    required this.onByCveChanged,
    required this.onDistroVersionChanged,
    required this.onFailOnChanged,
    required this.onOnlyFixedChanged,
    required this.onRun,
    required this.onStop,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Fichier SBOM ──
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: fileCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Fichier SBOM',
                    hintText: 'chemin/vers/sbom.cdx.json',
                    border: OutlineInputBorder(),
                    isDense: true,
                  ),
                  style: const TextStyle(
                      fontFamily: 'monospace', fontSize: 13),
                ),
              ),
              const SizedBox(width: 8),
              OutlinedButton.icon(
                onPressed: onPickSbom,
                icon: const Icon(Icons.folder_open, size: 18),
                label: const Text('Choisir'),
              ),
            ],
          ),
          const SizedBox(height: 10),

          // ── Options de scan (3 checkboxes) ──
          Wrap(
            spacing: 4,
            runSpacing: 0,
            children: [
              _CheckOption(
                label: '--platform linux',
                value: platformLinux,
                enabled: !isRunning,
                onChanged: onPlatformLinuxChanged,
              ),
              _CheckOption(
                label: '--add-cpes-if-none',
                value: addCpesIfNone,
                enabled: !isRunning,
                onChanged: onAddCpesIfNoneChanged,
              ),
              _CheckOption(
                label: '--by-cve',
                value: byCve,
                enabled: !isRunning,
                onChanged: onByCveChanged,
              ),
            ],
          ),
          const SizedBox(height: 8),

          // ── Distro / Seuil / Only-fixed / Bouton ──
          Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              // Distro
              _LabeledDropdown<String>(
                label: 'Distro',
                value: distroVersion,
                items: distroVersions
                    .map((v) => DropdownMenuItem(
                          value: v,
                          child: Text(
                            v.isEmpty ? '(aucune)' : 'rhel:$v',
                            style: const TextStyle(fontSize: 13),
                          ),
                        ))
                    .toList(),
                enabled: !isRunning,
                onChanged: (v) => onDistroVersionChanged(v ?? ''),
              ),
              const SizedBox(width: 16),

              // Seuil --fail-on
              _LabeledDropdown<String>(
                label: '--fail-on',
                value: failOn,
                items: severities
                    .map((s) => DropdownMenuItem(
                          value: s,
                          child: Text(
                            s.isEmpty ? '(aucun)' : s,
                            style: const TextStyle(fontSize: 13),
                          ),
                        ))
                    .toList(),
                enabled: !isRunning,
                onChanged: (v) => onFailOnChanged(v ?? ''),
              ),
              const SizedBox(width: 8),

              // Only-fixed
              _CheckOption(
                label: '--only-fixed',
                value: onlyFixed,
                enabled: !isRunning,
                onChanged: onOnlyFixedChanged,
              ),

              const Spacer(),

              // Bouton Analyser / Stop
              isRunning
                  ? OutlinedButton.icon(
                      onPressed: onStop,
                      icon: const Icon(Icons.stop, size: 18),
                      label: const Text('Stop'),
                      style: OutlinedButton.styleFrom(
                          foregroundColor: Colors.red),
                    )
                  : FilledButton.icon(
                      onPressed: onRun,
                      icon: const Icon(Icons.security, size: 18),
                      label: const Text('Analyser'),
                    ),
            ],
          ),
          const SizedBox(height: 10),

          // ── Template (-t) ──
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: templateCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Template (-t)',
                    hintText: './grype_csv.tmpl',
                    border: OutlineInputBorder(),
                    isDense: true,
                  ),
                  style: const TextStyle(
                      fontFamily: 'monospace', fontSize: 12),
                ),
              ),
              const SizedBox(width: 8),
              OutlinedButton.icon(
                onPressed: onPickTemplate,
                icon: const Icon(Icons.folder_open, size: 18),
                label: const Text('Choisir'),
              ),
            ],
          ),
          const SizedBox(height: 8),

          // ── grype.yaml optionnel ──
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: configCtrl,
                  decoration: const InputDecoration(
                    labelText: 'grype.yaml (optionnel)',
                    hintText: '/chemin/vers/grype.yaml',
                    border: OutlineInputBorder(),
                    isDense: true,
                  ),
                  style: const TextStyle(
                      fontFamily: 'monospace', fontSize: 12),
                ),
              ),
              const SizedBox(width: 8),
              OutlinedButton.icon(
                onPressed: onPickConfig,
                icon: const Icon(Icons.folder_open, size: 18),
                label: const Text('Choisir'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

// ─── Helpers UI ───────────────────────────────────────────────────────────────

class _CheckOption extends StatelessWidget {
  final String label;
  final bool value;
  final bool enabled;
  final ValueChanged<bool?> onChanged;

  const _CheckOption({
    required this.label,
    required this.value,
    required this.enabled,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Checkbox(
          value: value,
          onChanged: enabled ? onChanged : null,
          materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
          visualDensity: VisualDensity.compact,
        ),
        Text(label,
            style: TextStyle(
                fontSize: 12,
                fontFamily: 'monospace',
                color: enabled ? null : Colors.grey)),
      ],
    );
  }
}

class _LabeledDropdown<T> extends StatelessWidget {
  final String label;
  final T value;
  final List<DropdownMenuItem<T>> items;
  final bool enabled;
  final ValueChanged<T?> onChanged;

  const _LabeledDropdown({
    required this.label,
    required this.value,
    required this.items,
    required this.enabled,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(label,
            style: const TextStyle(
                fontSize: 11, fontWeight: FontWeight.w500)),
        const SizedBox(height: 2),
        DropdownButton<T>(
          value: value,
          isDense: true,
          items: items,
          onChanged: enabled ? onChanged : null,
        ),
      ],
    );
  }
}

// ─── Bannière résumé ──────────────────────────────────────────────────────────

class _GrypeBanner extends StatelessWidget {
  final int exitCode;
  final List<GrypeVuln> vulns;
  final String? error;

  const _GrypeBanner(
      {required this.exitCode, required this.vulns, this.error});

  @override
  Widget build(BuildContext context) {
    if (vulns.isEmpty && error != null) return const SizedBox.shrink();

    final counts = <String, int>{};
    for (final v in vulns) {
      counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    }

    final hasCritical = (counts['Critical'] ?? 0) > 0;
    final hasHigh = (counts['High'] ?? 0) > 0;
    final bgColor = hasCritical
        ? Colors.red[50]
        : hasHigh
            ? Colors.orange[50]
            : vulns.isEmpty
                ? Colors.green[50]
                : Colors.yellow[50];
    final fgColor = hasCritical
        ? Colors.red[800]
        : hasHigh
            ? Colors.orange[800]
            : vulns.isEmpty
                ? Colors.green[800]
                : Colors.yellow[900];
    final icon = hasCritical || hasHigh
        ? Icons.warning_amber_rounded
        : vulns.isEmpty
            ? Icons.verified_user_outlined
            : Icons.security_outlined;

    final parts = <String>[];
    for (final s in ['Critical', 'High', 'Medium', 'Low', 'Negligible']) {
      if ((counts[s] ?? 0) > 0) parts.add('${counts[s]} $s');
    }
    final summary = vulns.isEmpty
        ? 'Aucune vulnérabilité détectée'
        : '${vulns.length} vulnérabilité(s) : ${parts.join(', ')}';

    return Container(
      color: bgColor,
      padding:
          const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Row(
        children: [
          Icon(icon, color: fgColor, size: 20),
          const SizedBox(width: 10),
          Expanded(
            child: Text(summary,
                style: TextStyle(
                    fontWeight: FontWeight.bold, color: fgColor)),
          ),
        ],
      ),
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  final String error;
  const _ErrorBanner({required this.error});

  @override
  Widget build(BuildContext context) {
    return Container(
      color: Colors.red[50],
      padding:
          const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.error_outline, color: Colors.red[700], size: 20),
          const SizedBox(width: 10),
          Expanded(
            child: SelectableText(
              error,
              style: TextStyle(
                  color: Colors.red[800],
                  fontFamily: 'monospace',
                  fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Vue table des vulnérabilités ─────────────────────────────────────────────

class _VulnTableView extends StatefulWidget {
  final List<GrypeVuln> vulns;
  const _VulnTableView({required this.vulns});

  @override
  State<_VulnTableView> createState() => _VulnTableViewState();
}

class _VulnTableViewState extends State<_VulnTableView> {
  static const _severityOrder = [
    'Critical', 'High', 'Medium', 'Low', 'Negligible'
  ];

  Set<String> _activeFilters = {};

  List<GrypeVuln> get _filtered => _activeFilters.isEmpty
      ? widget.vulns
      : widget.vulns
          .where((v) => _activeFilters.contains(v.severity))
          .toList();

  static Color _fg(String s) => switch (s.toLowerCase()) {
        'critical' => const Color(0xFFB71C1C),
        'high' => const Color(0xFFBF360C),
        'medium' => const Color(0xFFE65100),
        'low' => const Color(0xFF2E7D32),
        'negligible' => Colors.grey,
        _ => Colors.grey,
      };

  static Color _bg(String s) => switch (s.toLowerCase()) {
        'critical' => const Color(0xFFFFEBEE),
        'high' => const Color(0xFFFBE9E7),
        'medium' => const Color(0xFFFFF3E0),
        'low' => const Color(0xFFF1F8E9),
        'negligible' => const Color(0xFFF5F5F5),
        _ => const Color(0xFFF5F5F5),
      };

  @override
  Widget build(BuildContext context) {
    if (widget.vulns.isEmpty) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.verified_user_outlined,
                size: 56, color: Colors.green),
            SizedBox(height: 12),
            Text('Aucune vulnérabilité détectée',
                style: TextStyle(color: Colors.green, fontSize: 15)),
          ],
        ),
      );
    }

    // Compter par sévérité
    final counts = <String, int>{};
    for (final v in widget.vulns) {
      counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    }

    final filtered = _filtered;

    return Column(
      children: [
        // Barre de filtres
        Container(
          color: Theme.of(context).colorScheme.surfaceContainerLow,
          padding:
              const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          child: Row(
            children: [
              const Text('Filtre :',
                  style: TextStyle(fontSize: 11)),
              const SizedBox(width: 8),
              Expanded(
                child: Wrap(
                  spacing: 6,
                  runSpacing: 2,
                  children: [
                    for (final s in _severityOrder)
                      if ((counts[s] ?? 0) > 0)
                        FilterChip(
                          label: Text(
                            '$s (${counts[s]})',
                            style: const TextStyle(fontSize: 11),
                          ),
                          selected: _activeFilters.contains(s),
                          selectedColor:
                              _fg(s).withValues(alpha: 0.2),
                          checkmarkColor: _fg(s),
                          onSelected: (v) => setState(() {
                            if (v) {
                              _activeFilters.add(s);
                            } else {
                              _activeFilters.remove(s);
                            }
                          }),
                          visualDensity: VisualDensity.compact,
                          padding: const EdgeInsets.symmetric(
                              horizontal: 4),
                        ),
                    if (_activeFilters.isNotEmpty)
                      ActionChip(
                        label: const Text('Tout voir',
                            style: TextStyle(fontSize: 11)),
                        onPressed: () =>
                            setState(() => _activeFilters = {}),
                        visualDensity: VisualDensity.compact,
                        padding: const EdgeInsets.symmetric(
                            horizontal: 4),
                      ),
                  ],
                ),
              ),
            ],
          ),
        ),

        // Liste filtrée
        Expanded(
          child: filtered.isEmpty
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.filter_alt_off_outlined,
                          size: 40, color: Colors.grey),
                      const SizedBox(height: 8),
                      Text(
                        'Aucun résultat pour ${_activeFilters.join(', ')}',
                        style: const TextStyle(
                            color: Colors.grey, fontSize: 13),
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 12, vertical: 8),
                  itemCount: filtered.length,
                  itemBuilder: (_, i) {
                    final v = filtered[i];
                    final fg = _fg(v.severity);
                    final bg = _bg(v.severity);
                    return Card(
                      margin: const EdgeInsets.only(bottom: 6),
                      color: bg,
                      elevation: 0,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(6),
                        side: BorderSide(
                            color: fg.withValues(alpha: 0.3)),
                      ),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 12, vertical: 8),
                        child: Row(
                          children: [
                            Container(
                              width: 72,
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 6, vertical: 3),
                              decoration: BoxDecoration(
                                color: fg,
                                borderRadius:
                                    BorderRadius.circular(4),
                              ),
                              child: Text(
                                v.severity.toUpperCase(),
                                textAlign: TextAlign.center,
                                style: const TextStyle(
                                    color: Colors.white,
                                    fontSize: 10,
                                    fontWeight: FontWeight.bold),
                              ),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              flex: 3,
                              child: Column(
                                crossAxisAlignment:
                                    CrossAxisAlignment.start,
                                children: [
                                  Text(v.packageName,
                                      style: const TextStyle(
                                          fontFamily: 'monospace',
                                          fontWeight:
                                              FontWeight.bold,
                                          fontSize: 13)),
                                  Text(
                                    v.fixedVersion.isNotEmpty
                                        ? '${v.installedVersion} → ${v.fixedVersion}'
                                        : v.installedVersion,
                                    style: TextStyle(
                                        fontFamily: 'monospace',
                                        fontSize: 11,
                                        color: Colors.grey[700]),
                                  ),
                                ],
                              ),
                            ),
                            Expanded(
                              flex: 2,
                              child: Tooltip(
                                message: 'Copier l\'identifiant',
                                child: InkWell(
                                  onTap: () {
                                    Clipboard.setData(
                                        ClipboardData(text: v.id));
                                    ScaffoldMessenger.of(context)
                                        .showSnackBar(
                                      const SnackBar(
                                        content: Text('CVE copié'),
                                        duration:
                                            Duration(seconds: 2),
                                      ),
                                    );
                                  },
                                  child: Text(
                                    v.id,
                                    style: TextStyle(
                                        fontFamily: 'monospace',
                                        fontSize: 12,
                                        color: fg,
                                        fontWeight:
                                            FontWeight.w600),
                                  ),
                                ),
                              ),
                            ),
                            Text(
                              v.packageType,
                              style: const TextStyle(
                                  fontFamily: 'monospace',
                                  fontSize: 11,
                                  color: Colors.grey),
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
        ),
      ],
    );
  }
}

// ─── Vue JSON brut ────────────────────────────────────────────────────────────

class _JsonView extends StatelessWidget {
  final String json;
  const _JsonView({required this.json});

  String _pretty() {
    try {
      return const JsonEncoder.withIndent('  ')
          .convert(jsonDecode(json));
    } catch (_) {
      return json;
    }
  }

  @override
  Widget build(BuildContext context) {
    final pretty = _pretty();
    return Stack(
      children: [
        Container(
          color: const Color(0xFF1E1E1E),
          padding: const EdgeInsets.all(12),
          child: SelectionArea(
            child: SingleChildScrollView(
              child: Text(
                pretty,
                style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: Color(0xFFD4D4D4),
                    height: 1.5),
              ),
            ),
          ),
        ),
        Positioned(
          top: 8,
          right: 8,
          child: Tooltip(
            message: 'Copier le JSON',
            child: IconButton(
              icon: const Icon(Icons.copy_outlined,
                  size: 18, color: Colors.white70),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: json));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('JSON copié'),
                    duration: Duration(seconds: 2),
                  ),
                );
              },
            ),
          ),
        ),
      ],
    );
  }
}

// ─── Vue sortie template ──────────────────────────────────────────────────────

class _TemplateView extends StatelessWidget {
  final String content;
  final bool hasTemplate;

  const _TemplateView({required this.content, required this.hasTemplate});

  @override
  Widget build(BuildContext context) {
    if (content.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.article_outlined, size: 56, color: Colors.grey[400]),
            const SizedBox(height: 12),
            Text(
              hasTemplate
                  ? 'Lancez l\'analyse pour afficher la sortie template'
                  : 'Configurez un fichier template (-t) pour activer cette vue',
              style: const TextStyle(color: Colors.grey, fontSize: 14),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }

    return Stack(
      children: [
        Container(
          color: const Color(0xFF1E1E1E),
          padding: const EdgeInsets.all(12),
          child: SelectionArea(
            child: SingleChildScrollView(
              child: Text(
                content,
                style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: Color(0xFFD4D4D4),
                    height: 1.5),
              ),
            ),
          ),
        ),
        Positioned(
          top: 8,
          right: 8,
          child: Tooltip(
            message: 'Copier la sortie',
            child: IconButton(
              icon: const Icon(Icons.copy_outlined,
                  size: 18, color: Colors.white70),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: content));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Sortie template copiée'),
                    duration: Duration(seconds: 2),
                  ),
                );
              },
            ),
          ),
        ),
      ],
    );
  }
}

// ─── Hints ────────────────────────────────────────────────────────────────────

class _GrypeEmptyHint extends StatelessWidget {
  const _GrypeEmptyHint();

  @override
  Widget build(BuildContext context) => const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.security_outlined, size: 56, color: Colors.grey),
            SizedBox(height: 12),
            Text(
              'Choisissez un fichier SBOM et lancez l\'analyse Grype',
              style: TextStyle(color: Colors.grey, fontSize: 15),
            ),
          ],
        ),
      );
}

class _GrypeRunningHint extends StatelessWidget {
  const _GrypeRunningHint();

  @override
  Widget build(BuildContext context) => const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 16),
            Text(
              'Analyse Grype en cours…',
              style: TextStyle(color: Colors.grey, fontSize: 15),
            ),
          ],
        ),
      );
}
