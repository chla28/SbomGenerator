import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../models/cve_date_filter.dart';
import '../models/sbom_result.dart';
import '../services/trivy_runner.dart';
import 'help_icon.dart';
import '../services/version_service.dart';
import 'vuln_shared.dart';

// ─── Modèle ───────────────────────────────────────────────────────────────────

class TrivyVuln implements VulnRow {
  @override
  final String id;
  @override
  final String severity;
  @override
  final String packageName;
  @override
  final String installedVersion;
  @override
  final String fixedVersion;
  final String title;
  @override
  final DateTime? publishedDate;
  @override
  final DateTime? modifiedDate;

  const TrivyVuln({
    required this.id,
    required this.severity,
    required this.packageName,
    required this.installedVersion,
    required this.fixedVersion,
    required this.title,
    this.publishedDate,
    this.modifiedDate,
  });

  static int _order(String s) => switch (s.toLowerCase()) {
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        'low' => 3,
        'unknown' => 4,
        _ => 5,
      };

  static DateTime? _parseDate(String? s) {
    if (s == null || s.isEmpty) return null;
    try {
      return DateTime.parse(s).toUtc();
    } catch (_) {
      return null;
    }
  }

  /// Lève une [FormatException] si `raw` n'est pas un JSON trivy valide,
  /// plutôt que de retourner silencieusement une liste vide : un JSON
  /// tronqué/corrompu ne doit pas être confondu avec "aucune vulnérabilité".
  static List<TrivyVuln> fromJson(String raw) {
    final vulns = <TrivyVuln>[];
    final data = jsonDecode(raw) as Map<String, dynamic>;
    for (final result in (data['Results'] as List? ?? [])) {
      for (final v in ((result['Vulnerabilities'] as List?) ?? [])) {
        vulns.add(TrivyVuln(
          id: v['VulnerabilityID'] as String? ?? '',
          severity: v['Severity'] as String? ?? 'Unknown',
          packageName: v['PkgName'] as String? ?? '',
          installedVersion: v['InstalledVersion'] as String? ?? '',
          fixedVersion: v['FixedVersion'] as String? ?? '',
          title: v['Title'] as String? ?? '',
          publishedDate: _parseDate(v['PublishedDate'] as String?),
          modifiedDate: _parseDate(v['LastModifiedDate'] as String?),
        ));
      }
    }
    vulns.sort((a, b) => _order(a.severity).compareTo(_order(b.severity)));
    return vulns;
  }
}

// ─── Widget principal ─────────────────────────────────────────────────────────

class TrivyPanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  final void Function(List<TrivyVuln>)? onVulnsChanged;
  final CveDateFilter dateFilter;
  final void Function(CveDateFilter)? onDateFilterChanged;
  final void Function(CveDateFilter)? onPropagate;

  const TrivyPanel({
    super.key,
    required this.outputFiles,
    this.onVulnsChanged,
    this.dateFilter = CveDateFilter.empty,
    this.onDateFilterChanged,
    this.onPropagate,
  });

  @override
  State<TrivyPanel> createState() => _TrivyPanelState();
}

class _TrivyPanelState extends State<TrivyPanel>
    with SingleTickerProviderStateMixin, AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;
  final _runner = TrivyRunner();
  final _fileCtrl = TextEditingController();
  final _configCtrl = TextEditingController();
  late final TabController _resultTabs;

  // Options Trivy
  final Set<String> _selectedSeverities = {};
  bool _ignoreUnfixed = false;
  bool _skipDbUpdate = false;

  bool _isRunning = false;
  List<TrivyVuln> _vulns = [];
  String _jsonOutput = '';
  String? _error;
  bool _parseFailed = false;
  int? _exitCode;

  ToolVersionInfo? _versionInfo;

  @override
  void initState() {
    super.initState();
    _resultTabs = TabController(length: 2, vsync: this);
    _updateAutoFile();
    VersionService.checkTrivy()
        .then((info) { if (mounted) setState(() => _versionInfo = info); });
  }

  @override
  void didUpdateWidget(TrivyPanel old) {
    super.didUpdateWidget(old);
    if (widget.outputFiles != old.outputFiles) _updateAutoFile();
  }

  @override
  void dispose() {
    _runner.kill();
    _fileCtrl.dispose();
    _configCtrl.dispose();
    _resultTabs.dispose();
    super.dispose();
  }

  void _updateAutoFile() {
    if (widget.outputFiles.isEmpty || _fileCtrl.text.isNotEmpty) return;
    final preferred = widget.outputFiles
        .where((f) =>
            f.path.endsWith('.cdx.json') || f.path.endsWith('.spdx.json'))
        .firstOrNull;
    final fallback = widget.outputFiles
        .where((f) => f.path.endsWith('.json') || f.path.endsWith('.jsonld'))
        .firstOrNull;
    final file = preferred ?? fallback;
    if (file != null) setState(() => _fileCtrl.text = file.path);
  }

  Future<void> _pickSbomFile({bool filtered = true}) async {
    final r = await FilePicker.pickFiles(
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? ['json', 'jsonld'] : null,
      dialogTitle: 'Choisir un fichier SBOM',
    );
    if (r?.files.single.path != null) {
      setState(() => _fileCtrl.text = r!.files.single.path!);
    }
  }

  Future<void> _pickConfigFile({bool filtered = true}) async {
    final r = await FilePicker.pickFiles(
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? ['yaml', 'yml'] : null,
      dialogTitle: 'Choisir trivy.yaml',
    );
    if (r?.files.single.path != null) {
      setState(() => _configCtrl.text = r!.files.single.path!);
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
      _error = null;
      _parseFailed = false;
      _exitCode = null;
    });

    _runner
        .run(
          sbomFile: sbomFile,
          severities: _selectedSeverities.toList(),
          ignoreUnfixed: _ignoreUnfixed,
          skipDbUpdate: _skipDbUpdate,
          configFile:
              _configCtrl.text.trim().isEmpty ? null : _configCtrl.text.trim(),
        )
        .listen(
      (event) {
        if (!mounted) return;
        switch (event) {
          case TrivyOutputEvent(:final jsonOutput):
            try {
              final vulns = TrivyVuln.fromJson(jsonOutput);
              setState(() {
                _jsonOutput = jsonOutput;
                _vulns = vulns;
              });
              widget.onVulnsChanged?.call(_vulns);
            } catch (e) {
              setState(() {
                _jsonOutput = jsonOutput;
                _vulns = [];
                _parseFailed = true;
                _error = 'Sortie trivy illisible (JSON invalide) : $e';
              });
            }
          case TrivyDoneEvent(:final exitCode, :final stderr):
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
    super.build(context);
    final hasDone = _exitCode != null;

    return Column(
      children: [
        _ConfigSection(
          fileCtrl: _fileCtrl,
          configCtrl: _configCtrl,
          selectedSeverities: _selectedSeverities,
          ignoreUnfixed: _ignoreUnfixed,
          skipDbUpdate: _skipDbUpdate,
          isRunning: _isRunning,
          onPickSbom: _pickSbomFile,
          onPickSbomAll: () => _pickSbomFile(filtered: false),
          onPickConfig: _pickConfigFile,
          onPickConfigAll: () => _pickConfigFile(filtered: false),
          onSeverityChanged: (s, v) => setState(() {
            if (v) {
              _selectedSeverities.add(s);
            } else {
              _selectedSeverities.remove(s);
            }
          }),
          onIgnoreUnfixedChanged: (v) =>
              setState(() => _ignoreUnfixed = v ?? false),
          onSkipDbUpdateChanged: (v) =>
              setState(() => _skipDbUpdate = v ?? false),
          onRun: _analyze,
          onStop: _stop,
          versionInfo: _versionInfo,
        ),
        if (hasDone && _error != null)
          ErrorBanner(message: _error!),
        if (hasDone && _error == null)
          _TrivyBanner(vulns: _vulns, exitCode: _exitCode!),
        if (hasDone)
          ColoredBox(
            color: Theme.of(context).colorScheme.surfaceContainerLow,
            child: TabBar(
              controller: _resultTabs,
              tabs: const [
                Tab(
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.security_outlined, size: 16),
                      SizedBox(width: 6),
                      Text('Vulnérabilités'),
                    ],
                  ),
                ),
                Tab(
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.data_object, size: 16),
                      SizedBox(width: 6),
                      Text('JSON brut'),
                    ],
                  ),
                ),
              ],
            ),
          ),
        if (hasDone)
          Expanded(
            child: TabBarView(
              controller: _resultTabs,
              children: [
                VulnTableView<TrivyVuln>(
                  vulns: _vulns,
                  parseFailed: _parseFailed,
                  parseFailedMessage:
                      'Sortie trivy illisible : voir le message d\'erreur ci-dessus',
                  severityOrder: const [
                    'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'
                  ],
                  csvDialogTitle: 'Exporter les vulnérabilités Trivy',
                  csvFileName: 'trivy_vulns.csv',
                  csvHeader:
                      'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Titre',
                  csvRow: (v) => [
                    v.severity,
                    v.id,
                    v.packageName,
                    v.installedVersion,
                    v.fixedVersion,
                    v.title,
                  ],
                  descriptionOf: (v) => v.title,
                  dateFilter: widget.dateFilter,
                  onDateFilterChanged: widget.onDateFilterChanged,
                  onPropagate: widget.onPropagate,
                ),
                JsonView(json: _jsonOutput),
              ],
            ),
          )
        else if (_isRunning)
          const Expanded(child: _RunningHint())
        else
          const Expanded(child: _EmptyHint()),
      ],
    );
  }
}

// ─── Section configuration ────────────────────────────────────────────────────

class _ConfigSection extends StatelessWidget {
  final TextEditingController fileCtrl;
  final TextEditingController configCtrl;
  final Set<String> selectedSeverities;
  final bool ignoreUnfixed;
  final bool skipDbUpdate;
  final bool isRunning;
  final VoidCallback onPickSbom;
  final VoidCallback onPickSbomAll;
  final VoidCallback onPickConfig;
  final VoidCallback onPickConfigAll;
  final void Function(String sev, bool selected) onSeverityChanged;
  final ValueChanged<bool?> onIgnoreUnfixedChanged;
  final ValueChanged<bool?> onSkipDbUpdateChanged;
  final VoidCallback onRun;
  final VoidCallback onStop;
  final ToolVersionInfo? versionInfo;

  static const _severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

  static const _sevColors = {
    'CRITICAL': Color(0xFFB71C1C),
    'HIGH': Color(0xFFBF360C),
    'MEDIUM': Color(0xFFE65100),
    'LOW': Color(0xFF2E7D32),
    'UNKNOWN': Colors.grey,
  };

  const _ConfigSection({
    required this.fileCtrl,
    required this.configCtrl,
    required this.selectedSeverities,
    required this.ignoreUnfixed,
    required this.skipDbUpdate,
    required this.isRunning,
    required this.onPickSbom,
    required this.onPickSbomAll,
    required this.onPickConfig,
    required this.onPickConfigAll,
    required this.onSeverityChanged,
    required this.onIgnoreUnfixedChanged,
    required this.onSkipDbUpdateChanged,
    required this.onRun,
    required this.onStop,
    this.versionInfo,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Version ──
          Row(
            children: [
              Text('trivy',
                  style: TextStyle(
                      fontSize: 11,
                      color: Theme.of(context)
                          .colorScheme
                          .onSurface
                          .withValues(alpha: 0.5))),
              const SizedBox(width: 8),
              ToolVersionBadge(info: versionInfo),
            ],
          ),
          const SizedBox(height: 10),
          // Fichier SBOM
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
                  style:
                      const TextStyle(fontFamily: 'monospace', fontSize: 13),
                ),
              ),
              const SizedBox(width: 8),
              SplitPickButton(
                filterLabel: '.json .jsonld',
                onPickFiltered: onPickSbom,
                onPickAll: onPickSbomAll,
              ),
            ],
          ),
          const SizedBox(height: 10),

          // --severity checkboxes
          Row(
            mainAxisSize: MainAxisSize.min,
            children: const [
              Text('--severity (laisser vide = tout)',
                  style: TextStyle(fontSize: 11, color: Colors.grey)),
              SizedBox(width: 4),
              HelpIcon(
                'Filtres de sévérité. Seules les vulnérabilités\n'
                'dont la sévérité est cochée sont affichées.\n'
                'Laisser vide = toutes les sévérités.',
              ),
            ],
          ),
          const SizedBox(height: 4),
          Wrap(
            spacing: 4,
            runSpacing: 0,
            children: [
              for (final s in _severities)
                FilterChip(
                  label: Text(s, style: const TextStyle(fontSize: 11)),
                  labelStyle: TextStyle(
                    color: selectedSeverities.contains(s)
                        ? Colors.white
                        : _sevColors[s],
                  ),
                  backgroundColor:
                      (_sevColors[s] ?? Colors.grey).withValues(alpha: 0.1),
                  selectedColor: _sevColors[s] ?? Colors.grey,
                  selected: selectedSeverities.contains(s),
                  onSelected: (v) => onSeverityChanged(s, v),
                ),
            ],
          ),
          const SizedBox(height: 6),

          // --ignore-unfixed + --skip-db-update
          Row(
            children: [
              Expanded(
                child: CheckboxListTile.adaptive(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  title: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: const [
                      Text('--ignore-unfixed',
                          style: TextStyle(fontSize: 12)),
                      SizedBox(width: 4),
                      HelpIcon(
                        'Masque les vulnérabilités sans version\n'
                        'corrigée disponible. Réduit le bruit\n'
                        'dans les résultats.',
                      ),
                    ],
                  ),
                  value: ignoreUnfixed,
                  onChanged: onIgnoreUnfixedChanged,
                  controlAffinity: ListTileControlAffinity.leading,
                ),
              ),
              Expanded(
                child: CheckboxListTile.adaptive(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  title: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: const [
                      Text('--skip-db-update',
                          style: TextStyle(fontSize: 12)),
                      SizedBox(width: 4),
                      HelpIcon(
                        'Utilise la base CVE locale sans la mettre\n'
                        'à jour. Accélère les analyses successives,\n'
                        'mais la base peut être obsolète.',
                      ),
                    ],
                  ),
                  value: skipDbUpdate,
                  onChanged: onSkipDbUpdateChanged,
                  controlAffinity: ListTileControlAffinity.leading,
                ),
              ),
            ],
          ),

          // trivy.yaml
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: configCtrl,
                  decoration: const InputDecoration(
                    label: HelpLabel(
                      'trivy.yaml (optionnel)',
                      'Fichier de configuration Trivy (YAML).\n'
                          'Permet de définir des politiques, des\n'
                          'exceptions ou des sources personnalisées.',
                    ),
                    hintText: '/chemin/vers/trivy.yaml',
                    border: OutlineInputBorder(),
                    isDense: true,
                  ),
                  style:
                      const TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
              ),
              const SizedBox(width: 8),
              SplitPickButton(
                filterLabel: '.yaml .yml',
                onPickFiltered: onPickConfig,
                onPickAll: onPickConfigAll,
              ),
            ],
          ),
          const SizedBox(height: 12),

          SizedBox(
            width: double.infinity,
            child: isRunning
                ? OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                      minimumSize: const Size.fromHeight(42),
                      side: const BorderSide(color: Colors.red),
                      foregroundColor: Colors.red,
                    ),
                    onPressed: onStop,
                    icon: const Icon(Icons.stop),
                    label: const Text('Arrêter'),
                  )
                : FilledButton.icon(
                    style: FilledButton.styleFrom(
                      minimumSize: const Size.fromHeight(42),
                    ),
                    onPressed: onRun,
                    icon: const Icon(Icons.search),
                    label: const Text('Analyser avec trivy'),
                  ),
          ),
        ],
      ),
    );
  }
}

// ─── Bannière résultat ────────────────────────────────────────────────────────

class _TrivyBanner extends StatelessWidget {
  final List<TrivyVuln> vulns;
  final int exitCode;

  const _TrivyBanner({required this.vulns, required this.exitCode});

  @override
  Widget build(BuildContext context) {
    if (vulns.isEmpty) {
      return Container(
        color: Colors.green[50],
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Row(
          children: [
            const Icon(Icons.verified_user, color: Colors.green, size: 18),
            const SizedBox(width: 8),
            Text(
              'Aucune vulnérabilité trouvée',
              style: TextStyle(
                  color: Colors.green[800], fontWeight: FontWeight.w500),
            ),
          ],
        ),
      );
    }

    final counts = <String, int>{};
    for (final v in vulns) {
      counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    }
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
    const colors = {
      'CRITICAL': Color(0xFFB71C1C),
      'HIGH': Color(0xFFBF360C),
      'MEDIUM': Color(0xFFE65100),
      'LOW': Color(0xFF2E7D32),
      'UNKNOWN': Colors.grey,
    };

    return Container(
      color: Colors.orange[50],
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Row(
        children: [
          const Icon(Icons.warning_amber, color: Colors.orange, size: 18),
          const SizedBox(width: 8),
          Text(
            '${vulns.length} vulnérabilité${vulns.length > 1 ? 's' : ''} — ',
            style: const TextStyle(fontWeight: FontWeight.w500),
          ),
          Expanded(
            child: Wrap(
              spacing: 8,
              children: [
                for (final s in order)
                  if (counts.containsKey(s))
                    Text(
                      '${counts[s]} $s',
                      style: TextStyle(
                        fontSize: 12,
                        color: colors[s],
                        fontWeight: FontWeight.bold,
                      ),
                    ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Hints ────────────────────────────────────────────────────────────────────

class _EmptyHint extends StatelessWidget {
  const _EmptyHint();

  @override
  Widget build(BuildContext context) => const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.shield_outlined, size: 56, color: Colors.grey),
            SizedBox(height: 12),
            Text('Sélectionnez un SBOM et lancez l\'analyse',
                style: TextStyle(color: Colors.grey, fontSize: 15)),
            SizedBox(height: 4),
            Text('trivy — Aqua Security vulnerability scanner',
                style: TextStyle(color: Colors.grey, fontSize: 12)),
          ],
        ),
      );
}

class _RunningHint extends StatelessWidget {
  const _RunningHint();

  @override
  Widget build(BuildContext context) => const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 16),
            Text('Analyse trivy en cours…',
                style: TextStyle(color: Colors.grey, fontSize: 15)),
          ],
        ),
      );
}
