import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/cve_date_filter.dart';
import '../models/sbom_result.dart';
import '../services/trivy_runner.dart';
import 'help_icon.dart';
import '../services/version_service.dart';

// ─── Modèle ───────────────────────────────────────────────────────────────────

class TrivyVuln {
  final String id;
  final String severity;
  final String packageName;
  final String installedVersion;
  final String fixedVersion;
  final String title;
  final DateTime? publishedDate;
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
          _ErrorBanner(message: _error!),
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
                _VulnTableView(
                  vulns: _vulns,
                  parseFailed: _parseFailed,
                  dateFilter: widget.dateFilter,
                  onDateFilterChanged: widget.onDateFilterChanged,
                  onPropagate: widget.onPropagate,
                ),
                _JsonView(json: _jsonOutput),
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
              _SplitPickButton(
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
              _SplitPickButton(
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

class _ErrorBanner extends StatelessWidget {
  final String message;
  const _ErrorBanner({required this.message});

  @override
  Widget build(BuildContext context) => Container(
        color: Colors.red[50],
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Row(
          children: [
            const Icon(Icons.error_outline, color: Colors.red, size: 18),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                message,
                style: TextStyle(color: Colors.red[800]),
                maxLines: 3,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      );
}

// ─── Tableau des vulnérabilités ───────────────────────────────────────────────

enum _SortCol { severity, cveId, package }

class _VulnTableView extends StatefulWidget {
  final List<TrivyVuln> vulns;
  final bool parseFailed;
  final CveDateFilter dateFilter;
  final void Function(CveDateFilter)? onDateFilterChanged;
  final void Function(CveDateFilter)? onPropagate;

  const _VulnTableView({
    required this.vulns,
    this.parseFailed = false,
    this.dateFilter = CveDateFilter.empty,
    this.onDateFilterChanged,
    this.onPropagate,
  });

  @override
  State<_VulnTableView> createState() => _VulnTableViewState();
}

class _VulnTableViewState extends State<_VulnTableView> {
  static const _severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

  Set<String> _activeFilters = {};
  final _searchCtrl = TextEditingController();
  String _searchTerm = '';
  _SortCol _sortCol = _SortCol.severity;
  bool _sortAsc = true; // true = ascendant par _sevOrd (Critical=0 en premier)

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  static int _sevOrd(String s) => switch (s.toUpperCase()) {
        'CRITICAL' => 0,
        'HIGH' => 1,
        'MEDIUM' => 2,
        'LOW' => 3,
        _ => 4,
      };

  void _onSort(_SortCol col) => setState(() {
        if (_sortCol == col) {
          _sortAsc = !_sortAsc;
        } else {
          _sortCol = col;
          _sortAsc = col == _SortCol.severity;
        }
      });

  List<TrivyVuln> get _filtered {
    var list = _activeFilters.isEmpty
        ? widget.vulns
        : widget.vulns.where((v) => _activeFilters.contains(v.severity)).toList();
    if (_searchTerm.isNotEmpty) {
      final q = _searchTerm.toLowerCase();
      list = list
          .where((v) =>
              v.packageName.toLowerCase().contains(q) ||
              v.id.toLowerCase().contains(q))
          .toList();
    }
    if (widget.dateFilter.hasConstraints) {
      list = list
          .where((v) => widget.dateFilter.matches(v.publishedDate, v.modifiedDate))
          .toList();
    }
    list = List.of(list)
      ..sort((a, b) {
        final cmp = switch (_sortCol) {
          _SortCol.severity => _sevOrd(a.severity).compareTo(_sevOrd(b.severity)),
          _SortCol.cveId    => a.id.compareTo(b.id),
          _SortCol.package  => a.packageName.compareTo(b.packageName),
        };
        return _sortAsc ? cmp : -cmp;
      });
    return list;
  }

  static String _csv(String s) {
    if (s.contains(',') || s.contains('"') || s.contains('\n')) {
      return '"${s.replaceAll('"', '""')}"';
    }
    return s;
  }

  Future<void> _exportCsv(BuildContext context) async {
    final rows = _filtered;
    final buf = StringBuffer();
    buf.writeln('Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Titre');
    for (final v in rows) {
      buf.writeln([
        _csv(v.severity),
        _csv(v.id),
        _csv(v.packageName),
        _csv(v.installedVersion),
        _csv(v.fixedVersion),
        _csv(v.title),
      ].join(','));
    }
    final path = await FilePicker.saveFile(
      dialogTitle: 'Exporter les vulnérabilités Trivy',
      fileName: 'trivy_vulns.csv',
      type: FileType.custom,
      allowedExtensions: ['csv'],
    );
    if (path == null || !context.mounted) return;
    await File(path).writeAsString(buf.toString());
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content:
            Text('${rows.length} vulnérabilité(s) exportée(s) → $path'),
        duration: const Duration(seconds: 4),
      ));
    }
  }

  static Color _fg(String s) => switch (s.toUpperCase()) {
        'CRITICAL' => const Color(0xFFB71C1C),
        'HIGH' => const Color(0xFFBF360C),
        'MEDIUM' => const Color(0xFFE65100),
        'LOW' => const Color(0xFF2E7D32),
        _ => Colors.grey,
      };

  static Color _bg(String s) => switch (s.toUpperCase()) {
        'CRITICAL' => const Color(0xFFFFEBEE),
        'HIGH' => const Color(0xFFFBE9E7),
        'MEDIUM' => const Color(0xFFFFF3E0),
        'LOW' => const Color(0xFFF1F8E9),
        _ => const Color(0xFFF5F5F5),
      };

  @override
  Widget build(BuildContext context) {
    if (widget.parseFailed) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline, size: 56, color: Colors.red),
            SizedBox(height: 12),
            Text('Sortie trivy illisible : voir le message d\'erreur ci-dessus',
                style: TextStyle(color: Colors.red, fontSize: 15)),
          ],
        ),
      );
    }
    if (widget.vulns.isEmpty) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.verified_user_outlined, size: 56, color: Colors.green),
            SizedBox(height: 12),
            Text('Aucune vulnérabilité détectée',
                style: TextStyle(color: Colors.green, fontSize: 15)),
          ],
        ),
      );
    }

    final counts = <String, int>{};
    for (final v in widget.vulns) {
      counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    }
    final filtered = _filtered;

    return Column(
      children: [
        // ── Filtres + recherche ──
        Container(
          color: Theme.of(context).colorScheme.surfaceContainerLow,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          child: Row(
            children: [
              const Text('Filtre :', style: TextStyle(fontSize: 11)),
              const SizedBox(width: 8),
              Expanded(
                child: Wrap(
                  spacing: 6,
                  runSpacing: 2,
                  children: [
                    for (final s in _severityOrder)
                      if (counts.containsKey(s))
                        FilterChip(
                          label: Text('$s (${counts[s]})'),
                          labelStyle: TextStyle(
                              fontSize: 11,
                              color: _activeFilters.contains(s)
                                  ? Colors.white
                                  : _fg(s)),
                          backgroundColor: _bg(s),
                          selectedColor: _fg(s),
                          selected: _activeFilters.contains(s),
                          onSelected: (v) => setState(() {
                            if (v) {
                              _activeFilters.add(s);
                            } else {
                              _activeFilters.remove(s);
                            }
                          }),
                        ),
                    if (_activeFilters.isNotEmpty)
                      ActionChip(
                        label: const Text('Tout voir',
                            style: TextStyle(fontSize: 11)),
                        onPressed: () => setState(() => _activeFilters = {}),
                      ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              SizedBox(
                width: 200,
                child: TextField(
                  controller: _searchCtrl,
                  onChanged: (v) => setState(() => _searchTerm = v),
                  decoration: InputDecoration(
                    hintText: 'Paquet ou CVE…',
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
                    contentPadding:
                        const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
                    border: const OutlineInputBorder(),
                  ),
                  style: const TextStyle(fontSize: 12),
                ),
              ),
              const SizedBox(width: 4),
              IconButton(
                icon: const Icon(Icons.download_outlined, size: 18),
                tooltip: 'Exporter CSV',
                onPressed:
                    _filtered.isEmpty ? null : () => _exportCsv(context),
              ),
            ],
          ),
        ),

        // ── Filtre date ──
        _DateFilterBar(
          filter: widget.dateFilter,
          onChanged: widget.onDateFilterChanged,
          onPropagate: widget.onPropagate,
        ),

        // ── En-têtes de tri ──
        Container(
          color: Theme.of(context).colorScheme.surfaceContainerHigh,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 3),
          child: Row(
            children: [
              _SortHeader('SÉVÉRITÉ', _sortCol == _SortCol.severity, _sortAsc,
                  () => _onSort(_SortCol.severity)),
              const SizedBox(width: 16),
              _SortHeader('CVE / ID', _sortCol == _SortCol.cveId, _sortAsc,
                  () => _onSort(_SortCol.cveId)),
              const SizedBox(width: 16),
              _SortHeader('PAQUET', _sortCol == _SortCol.package, _sortAsc,
                  () => _onSort(_SortCol.package)),
            ],
          ),
        ),

        // ── Liste ──
        Expanded(
          child: filtered.isEmpty
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        _searchTerm.isNotEmpty
                            ? Icons.search_off
                            : Icons.filter_alt_off_outlined,
                        size: 40,
                        color: Colors.grey,
                      ),
                      const SizedBox(height: 8),
                      Text(
                        _searchTerm.isNotEmpty
                            ? 'Aucun résultat pour "$_searchTerm"'
                            : 'Aucun résultat pour ${_activeFilters.join(', ')}',
                        style: const TextStyle(color: Colors.grey),
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  itemCount: filtered.length,
                  itemBuilder: (_, i) {
                    final v = filtered[i];
                    final fg = _fg(v.severity);
                    final bg = _bg(v.severity);
                    return ListTile(
                      dense: true,
                      leading: Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: bg,
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: fg, width: 0.8),
                        ),
                        child: Text(
                          v.severity,
                          style: TextStyle(
                              fontSize: 10,
                              fontWeight: FontWeight.bold,
                              color: fg),
                        ),
                      ),
                      title: Text(
                        v.id,
                        style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 13,
                            fontWeight: FontWeight.w600),
                      ),
                      subtitle: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Text(
                                v.packageName,
                                style: const TextStyle(
                                    fontFamily: 'monospace', fontSize: 11),
                              ),
                              Text(' ${v.installedVersion}',
                                  style: const TextStyle(
                                      fontSize: 11, color: Colors.grey)),
                              if (v.fixedVersion.isNotEmpty) ...[
                                const Text(' → ',
                                    style: TextStyle(
                                        fontSize: 11, color: Colors.green)),
                                Text(v.fixedVersion,
                                    style: const TextStyle(
                                        fontSize: 11, color: Colors.green)),
                              ],
                            ],
                          ),
                          if (v.title.isNotEmpty)
                            Text(
                              v.title,
                              style: const TextStyle(
                                  fontSize: 11, color: Colors.grey),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                        ],
                      ),
                      isThreeLine: v.title.isNotEmpty,
                    );
                  },
                ),
        ),
      ],
    );
  }
}

// ─── En-tête de colonne triable ───────────────────────────────────────────────

class _SortHeader extends StatelessWidget {
  final String label;
  final bool active;
  final bool ascending;
  final VoidCallback onTap;

  const _SortHeader(this.label, this.active, this.ascending, this.onTap);

  @override
  Widget build(BuildContext context) {
    final color =
        active ? Theme.of(context).colorScheme.primary : Colors.grey[600]!;
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(4),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 2, vertical: 2),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(label,
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: color)),
            if (active) ...[
              const SizedBox(width: 2),
              Icon(ascending ? Icons.arrow_upward : Icons.arrow_downward,
                  size: 11, color: color),
            ],
          ],
        ),
      ),
    );
  }
}

// ─── Vue JSON brut ────────────────────────────────────────────────────────────

class _JsonView extends StatelessWidget {
  final String json;
  const _JsonView({required this.json});

  @override
  Widget build(BuildContext context) {
    if (json.isEmpty) {
      return const Center(child: Text('Pas de sortie JSON.'));
    }
    return Stack(
      children: [
        Container(
          color: const Color(0xFF1E1E1E),
          padding: const EdgeInsets.all(12),
          child: SelectionArea(
            child: SingleChildScrollView(
              child: Text(
                json,
                style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: Color(0xFFD4D4D4)),
              ),
            ),
          ),
        ),
        Positioned(
          top: 8,
          right: 8,
          child: Tooltip(
            message: 'Copier',
            child: IconButton(
              icon: const Icon(Icons.copy_outlined,
                  size: 18, color: Colors.white70),
              onPressed: () => Clipboard.setData(ClipboardData(text: json)),
            ),
          ),
        ),
      ],
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

// ─── Split-button pour sélection de fichier ───────────────────────────────────

class _SplitPickButton extends StatefulWidget {
  final String filterLabel;
  final VoidCallback onPickFiltered;
  final VoidCallback onPickAll;

  const _SplitPickButton({
    required this.filterLabel,
    required this.onPickFiltered,
    required this.onPickAll,
  });

  @override
  State<_SplitPickButton> createState() => _SplitPickButtonState();
}

class _SplitPickButtonState extends State<_SplitPickButton> {
  final MenuController _menu = MenuController();

  @override
  Widget build(BuildContext context) {
    return MenuAnchor(
      controller: _menu,
      menuChildren: [
        MenuItemButton(
          leadingIcon: const Icon(Icons.filter_alt_outlined, size: 16),
          onPressed: () {
            _menu.close();
            widget.onPickFiltered();
          },
          child: Text('Type filtré (${widget.filterLabel})'),
        ),
        MenuItemButton(
          leadingIcon: const Icon(Icons.folder_open, size: 16),
          onPressed: () {
            _menu.close();
            widget.onPickAll();
          },
          child: const Text('Tous les fichiers'),
        ),
      ],
      builder: (context, controller, _) => OutlinedButton.icon(
        onPressed: controller.isOpen ? controller.close : controller.open,
        icon: const Icon(Icons.folder_open, size: 18),
        label: const Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('Choisir'),
            SizedBox(width: 4),
            Icon(Icons.arrow_drop_down, size: 16),
          ],
        ),
      ),
    );
  }
}

// ─── Barre de filtre par date CVE ─────────────────────────────────────────────

class _DateFilterBar extends StatelessWidget {
  final CveDateFilter filter;
  final void Function(CveDateFilter)? onChanged;
  final void Function(CveDateFilter)? onPropagate;

  const _DateFilterBar({
    required this.filter,
    this.onChanged,
    this.onPropagate,
  });

  Future<void> _pickDate(
    BuildContext context,
    DateTime? current,
    void Function(DateTime?) onPicked,
  ) async {
    final now = DateTime.now();
    final picked = await showDatePicker(
      context: context,
      initialDate: current ?? now,
      firstDate: DateTime(1999),
      lastDate: now,
    );
    if (picked != null) onPicked(picked);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        border: Border(
          bottom: BorderSide(color: theme.dividerColor, width: 0.5),
        ),
      ),
      child: Row(
        children: [
          const Icon(Icons.calendar_today_outlined, size: 14),
          const SizedBox(width: 6),
          const Text('Date CVE :', style: TextStyle(fontSize: 11)),
          const SizedBox(width: 6),
          SegmentedButton<CveDateField>(
            segments: const [
              ButtonSegment(
                  value: CveDateField.published,
                  label: Text('Publication', style: TextStyle(fontSize: 10))),
              ButtonSegment(
                  value: CveDateField.modified,
                  label: Text('Modification', style: TextStyle(fontSize: 10))),
              ButtonSegment(
                  value: CveDateField.latest,
                  label: Text('La plus récente', style: TextStyle(fontSize: 10))),
            ],
            selected: {filter.field},
            onSelectionChanged: (s) =>
                onChanged?.call(filter.copyWith(field: s.first)),
            style: ButtonStyle(
              visualDensity: VisualDensity.compact,
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              textStyle: WidgetStateProperty.all(const TextStyle(fontSize: 10)),
            ),
          ),
          const SizedBox(width: 10),
          _DateChip(
            label: filter.after == null
                ? 'Après le…'
                : 'Après : ${_fmt(filter.after!)}',
            active: filter.after != null,
            onTap: () => _pickDate(context, filter.after,
                (d) => onChanged?.call(filter.copyWith(after: d))),
            onClear: filter.after == null
                ? null
                : () => onChanged?.call(filter.copyWith(after: null)),
          ),
          const SizedBox(width: 4),
          _DateChip(
            label: filter.before == null
                ? 'Avant le…'
                : 'Avant : ${_fmt(filter.before!)}',
            active: filter.before != null,
            onTap: () => _pickDate(context, filter.before,
                (d) => onChanged?.call(filter.copyWith(before: d))),
            onClear: filter.before == null
                ? null
                : () => onChanged?.call(filter.copyWith(before: null)),
          ),
          const SizedBox(width: 10),
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(
                width: 16,
                height: 16,
                child: Checkbox(
                  value: filter.includeUndated,
                  onChanged: (v) =>
                      onChanged?.call(filter.copyWith(includeUndated: v ?? false)),
                  materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  visualDensity: VisualDensity.compact,
                ),
              ),
              const SizedBox(width: 4),
              const Text('Sans date', style: TextStyle(fontSize: 11)),
            ],
          ),
          const Spacer(),
          if (onPropagate != null)
            TextButton.icon(
              icon: const Icon(Icons.sync_alt, size: 14),
              label: const Text('Propager aux autres onglets',
                  style: TextStyle(fontSize: 11)),
              style: TextButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              onPressed: () => onPropagate!(filter),
            ),
        ],
      ),
    );
  }

  static String _fmt(DateTime d) =>
      '${d.year.toString().padLeft(4, '0')}-'
      '${d.month.toString().padLeft(2, '0')}-'
      '${d.day.toString().padLeft(2, '0')}';
}

class _DateChip extends StatelessWidget {
  final String label;
  final bool active;
  final VoidCallback onTap;
  final VoidCallback? onClear;

  const _DateChip({
    required this.label,
    required this.active,
    required this.onTap,
    this.onClear,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: active
              ? theme.colorScheme.primaryContainer
              : theme.colorScheme.surfaceContainerHigh,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: active
                ? theme.colorScheme.primary
                : theme.colorScheme.outline,
            width: 0.8,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              label,
              style: TextStyle(
                fontSize: 11,
                color: active
                    ? theme.colorScheme.onPrimaryContainer
                    : theme.colorScheme.onSurfaceVariant,
              ),
            ),
            if (onClear != null) ...[
              const SizedBox(width: 4),
              InkWell(
                onTap: onClear,
                child: Icon(Icons.close, size: 12,
                    color: theme.colorScheme.onPrimaryContainer),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
