import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../models/cve_date_filter.dart';
import '../models/sbom_result.dart';
import '../services/osv_runner.dart';
import '../services/version_service.dart';
import 'help_icon.dart';
import 'vuln_shared.dart';

// ─── Modèle ───────────────────────────────────────────────────────────────────

class OsvVuln implements VulnRow {
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
  final String ecosystem;
  @override
  final DateTime? publishedDate;
  @override
  final DateTime? modifiedDate;

  const OsvVuln({
    required this.id,
    required this.severity,
    required this.packageName,
    required this.installedVersion,
    required this.fixedVersion,
    required this.ecosystem,
    this.publishedDate,
    this.modifiedDate,
  });

  static String _normalizeSeverity(String s) {
    return switch (s.toLowerCase()) {
      'critical' => 'Critical',
      'high' => 'High',
      'medium' || 'moderate' => 'Medium',
      'low' || 'none' => 'Low',
      _ => 'Unknown',
    };
  }

  static int _order(String s) => switch (s.toLowerCase()) {
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        'low' => 3,
        _ => 4,
      };

  static String _cvssToSeverity(String? score) {
    final v = double.tryParse(score ?? '') ?? 0.0;
    if (v >= 9.0) return 'Critical';
    if (v >= 7.0) return 'High';
    if (v >= 4.0) return 'Medium';
    if (v > 0) return 'Low';
    return 'Unknown';
  }

  static DateTime? _parseDate(String? s) {
    if (s == null || s.isEmpty) return null;
    try {
      return DateTime.parse(s).toUtc();
    } catch (_) {
      return null;
    }
  }

  /// Lève une [FormatException] si `raw` n'est pas un JSON osv-scanner
  /// valide, plutôt que de retourner silencieusement une liste vide : un
  /// JSON tronqué/corrompu ne doit pas être confondu avec "aucune
  /// vulnérabilité".
  static List<OsvVuln> fromJson(String raw) {
    final vulns = <OsvVuln>[];
    final data = jsonDecode(raw) as Map<String, dynamic>;
    for (final result in (data['results'] as List? ?? [])) {
      for (final pkg in (result['packages'] as List? ?? [])) {
        final pkgInfo = (pkg['package'] as Map?) ?? {};
        final name = pkgInfo['name'] as String? ?? '';
        final version = pkgInfo['version'] as String? ?? '';
        final ecosystem = pkgInfo['ecosystem'] as String? ?? '';

        // max_severity par vuln id depuis les groupes
        final groupSev = <String, String>{};
        for (final g in (pkg['groups'] as List? ?? [])) {
          final ms = (g['max_severity'] as String?) ?? '';
          for (final id in (g['ids'] as List? ?? [])) {
            groupSev[id as String] = ms;
          }
        }

        for (final v in (pkg['vulnerabilities'] as List? ?? [])) {
          final osvId = v['id'] as String? ?? '';
          final aliases = (v['aliases'] as List?)?.cast<String>() ?? [];
          final cve = aliases.firstWhere(
            (a) => a.startsWith('CVE-'),
            orElse: () => '',
          );
          final displayId = cve.isNotEmpty ? cve : osvId;

          // Sévérité : database_specific > max_severity CVSS > inconnu
          // database_specific.severity est en majuscules dans le JSON OSV
          // (_cvssToSeverity retourne déjà du titre case)
          final dbSev =
              (v['database_specific'] as Map?)?['severity'] as String?;
          final rawSev = (dbSev?.isNotEmpty == true)
              ? dbSev!
              : _cvssToSeverity(groupSev[osvId]);
          final severity = _normalizeSeverity(rawSev);

          // Version corrigée depuis affected[].ranges[].events
          String fixedVersion = '';
          for (final aff in (v['affected'] as List? ?? [])) {
            for (final range in ((aff['ranges'] as List?) ?? [])) {
              for (final event in ((range['events'] as List?) ?? [])) {
                final fixed = (event as Map)['fixed'] as String?;
                if (fixed != null) {
                  fixedVersion = fixed;
                  break;
                }
              }
              if (fixedVersion.isNotEmpty) break;
            }
            if (fixedVersion.isNotEmpty) break;
          }

          vulns.add(OsvVuln(
            id: displayId,
            severity: severity,
            packageName: name,
            installedVersion: version,
            fixedVersion: fixedVersion,
            ecosystem: ecosystem,
            publishedDate: _parseDate(v['published'] as String?),
            modifiedDate: _parseDate(v['modified'] as String?),
          ));
        }
      }
    }
    vulns.sort((a, b) => _order(a.severity).compareTo(_order(b.severity)));
    return vulns;
  }
}

// ─── Widget principal ─────────────────────────────────────────────────────────

class OsvPanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  final void Function(List<OsvVuln>)? onVulnsChanged;
  final CveDateFilter dateFilter;
  final void Function(CveDateFilter)? onDateFilterChanged;
  final void Function(CveDateFilter)? onPropagate;

  const OsvPanel({
    super.key,
    required this.outputFiles,
    this.onVulnsChanged,
    this.dateFilter = CveDateFilter.empty,
    this.onDateFilterChanged,
    this.onPropagate,
  });

  @override
  State<OsvPanel> createState() => _OsvPanelState();
}

class _OsvPanelState extends State<OsvPanel>
    with SingleTickerProviderStateMixin, AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;
  final _runner = OsvRunner();
  final _fileCtrl = TextEditingController();
  final _configCtrl = TextEditingController();
  late final TabController _resultTabs;

  bool _isRunning = false;
  List<OsvVuln> _vulns = [];
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
    VersionService.checkOsv()
        .then((info) { if (mounted) setState(() => _versionInfo = info); });
  }

  @override
  void didUpdateWidget(OsvPanel old) {
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
      allowedExtensions: filtered ? ['toml'] : null,
      dialogTitle: 'Choisir osv-scanner.toml',
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
          configFile:
              _configCtrl.text.trim().isEmpty ? null : _configCtrl.text.trim(),
        )
        .listen(
      (event) {
        if (!mounted) return;
        switch (event) {
          case OsvOutputEvent(:final jsonOutput):
            try {
              final vulns = OsvVuln.fromJson(jsonOutput);
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
                _error = 'Sortie osv-scanner illisible (JSON invalide) : $e';
              });
            }
          case OsvDoneEvent(:final exitCode, :final stderr):
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
          isRunning: _isRunning,
          onPickSbom: _pickSbomFile,
          onPickSbomAll: () => _pickSbomFile(filtered: false),
          onPickConfig: _pickConfigFile,
          onPickConfigAll: () => _pickConfigFile(filtered: false),
          onRun: _analyze,
          onStop: _stop,
          versionInfo: _versionInfo,
        ),
        if (hasDone && _error != null)
          ErrorBanner(message: _error!),
        if (hasDone && _error == null)
          _OsvBanner(vulns: _vulns, exitCode: _exitCode!),
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
                VulnTableView<OsvVuln>(
                  vulns: _vulns,
                  parseFailed: _parseFailed,
                  parseFailedMessage:
                      'Sortie osv-scanner illisible : voir le message d\'erreur ci-dessus',
                  severityOrder: const [
                    'Critical', 'High', 'Medium', 'Low', 'Unknown'
                  ],
                  csvDialogTitle: 'Exporter les vulnérabilités OSV-Scanner',
                  csvFileName: 'osv_vulns.csv',
                  csvHeader:
                      'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Écosystème',
                  csvRow: (v) => [
                    v.severity,
                    v.id,
                    v.packageName,
                    v.installedVersion,
                    v.fixedVersion,
                    v.ecosystem,
                  ],
                  extraColumnHeader: 'ÉCOSYSTÈME',
                  extraOf: (v) => v.ecosystem,
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
  final bool isRunning;
  final VoidCallback onPickSbom;
  final VoidCallback onPickSbomAll;
  final VoidCallback onPickConfig;
  final VoidCallback onPickConfigAll;
  final VoidCallback onRun;
  final VoidCallback onStop;
  final ToolVersionInfo? versionInfo;

  const _ConfigSection({
    required this.fileCtrl,
    required this.configCtrl,
    required this.isRunning,
    required this.onPickSbom,
    required this.onPickSbomAll,
    required this.onPickConfig,
    required this.onPickConfigAll,
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
              Text('osv-scanner',
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
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
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
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: configCtrl,
                  decoration: const InputDecoration(
                    label: HelpLabel(
                      'Fichier de config (optionnel)',
                      'Fichier TOML de configuration osv-scanner.\n'
                          'Permet d\'exclure des CVE, de configurer\n'
                          'des sources ou de définir des politiques.',
                    ),
                    hintText: 'osv-scanner.toml',
                    border: OutlineInputBorder(),
                    isDense: true,
                  ),
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                ),
              ),
              const SizedBox(width: 8),
              SplitPickButton(
                filterLabel: '.toml',
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
                    label: const Text('Analyser avec osv-scanner'),
                  ),
          ),
        ],
      ),
    );
  }
}

// ─── Bannière résultat ────────────────────────────────────────────────────────

class _OsvBanner extends StatelessWidget {
  final List<OsvVuln> vulns;
  final int exitCode;

  const _OsvBanner({required this.vulns, required this.exitCode});

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
    final order = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];

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
                        color: _severityColor(s),
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

  static Color _severityColor(String s) => switch (s.toLowerCase()) {
        'critical' => const Color(0xFFB71C1C),
        'high' => const Color(0xFFBF360C),
        'medium' => const Color(0xFFE65100),
        'low' => const Color(0xFF2E7D32),
        _ => Colors.grey,
      };
}

// ─── Hints ────────────────────────────────────────────────────────────────────

class _EmptyHint extends StatelessWidget {
  const _EmptyHint();

  @override
  Widget build(BuildContext context) => const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.plagiarism_outlined, size: 56, color: Colors.grey),
            SizedBox(height: 12),
            Text('Sélectionnez un SBOM et lancez l\'analyse',
                style: TextStyle(color: Colors.grey, fontSize: 15)),
            SizedBox(height: 4),
            Text('osv-scanner — Google Open Source Vulnerability Database',
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
            Text('Analyse osv-scanner en cours…',
                style: TextStyle(color: Colors.grey, fontSize: 15)),
          ],
        ),
      );
}
