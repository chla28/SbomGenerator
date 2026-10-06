import 'dart:async';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

import '../models/cve_date_filter.dart';
import '../models/layer_scan.dart';
import '../models/sbom_result.dart';
import '../models/scan_session.dart';
import '../services/scan_enrichment.dart';
import '../services/scan_job_runner.dart';
import '../services/session_store.dart';
import 'cra_panel.dart';
import 'dashboard_panel.dart';
import 'grype_panel.dart';
import 'osv_panel.dart';
import 'quality_panel.dart';
import 'sbom_diff_panel.dart';
import 'sbom_licenses_panel.dart';
import 'sbom_merge_panel.dart';
import 'sbom_tree_panel.dart';
import 'pdf_report.dart' show kGuiVersion;
import 'sbom_viewer_panel.dart';
import 'session_bar.dart';
import 'vex_ui.dart';
import 'vuln_shared.dart' show VulnRow;
import '../services/settings_service.dart';
import '../services/vex_controller.dart';
import 'tasks_panel.dart';
import 'trivy_panel.dart';
import '../l10n/l10n.dart';

class ResultsPanel extends StatefulWidget {
  final List<String> logLines;
  final List<OutputFile> outputFiles;
  final List<String> warnings;
  final String? fatalError;
  final bool isRunning;
  final bool isPdfRunning;
  final int? exitCode;
  final int progressCurrent;
  final int progressTotal;
  final int progressPercent;
  final String progressLabel;
  final String? sbomqsOutput;

  /// Historique automatique des analyses ; `null` = pas de sauvegarde.
  final SessionStore? historyStore;

  const ResultsPanel({
    super.key,
    required this.logLines,
    required this.outputFiles,
    required this.warnings,
    this.fatalError,
    required this.isRunning,
    this.isPdfRunning = false,
    this.exitCode,
    this.progressCurrent = 0,
    this.progressTotal = 0,
    this.progressPercent = 0,
    this.progressLabel = '',
    this.sbomqsOutput,
    this.historyStore,
  });

  @override
  State<ResultsPanel> createState() => _ResultsPanelState();
}

class _ResultsPanelState extends State<ResultsPanel>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  final ScrollController _logScroll = ScrollController();

  // État prévisualisation SBOM
  OutputFile? _previewFile;
  String? _previewContent;
  bool _previewLoading = false;

  // Résultats des scanners (null = pas encore exécuté)
  List<GrypeVuln>? _grypeVulns;
  List<OsvVuln>? _osvVulns;
  List<TrivyVuln>? _trivyVulns;

  // Analyses par couche des onglets de scan (source image, option « Par
  // couche ») — transmises au tableau de bord.
  final Map<String, LayerScanResult> _layerScans = {};

  // Signaux d'exploitabilité par scanner (id CVE normalisé → ExploitInfo),
  // fusionnés pour le tableau de bord.
  Map<String, ExploitInfo> _grypeExploit = const {};
  Map<String, ExploitInfo> _osvExploit = const {};
  Map<String, ExploitInfo> _trivyExploit = const {};

  // Cible analysée par chaque scanner (généralement identique) — pour
  // l'en-tête du rapport exporté du tableau de bord.
  String? _grypeTarget;
  String? _osvTarget;
  String? _trivyTarget;

  // Cibles d'une session chargée (prioritaires tant que les onglets de scan
  // n'ont pas produit de nouveaux résultats).
  List<String>? _loadedTargets;

  List<String> get _scanTargets =>
      _loadedTargets ??
      <String?>[
        _grypeTarget,
        _osvTarget,
        _trivyTarget,
      ].whereType<String>().toSet().toList();

  // ── VEX : déclarations de l'utilisateur et masquage des CVE couvertes ────
  final VexController _vex = VexController(persist: SettingsService.saveVex);
  bool _hideVex = true;

  List<GrypeVuln>? get _grypeShown => _filterVex(_grypeVulns);
  List<OsvVuln>? get _osvShown => _filterVex(_osvVulns);
  List<TrivyVuln>? get _trivyShown => _filterVex(_trivyVulns);

  List<T>? _filterVex<T extends VulnRow>(List<T>? l) => !_hideVex
      ? l
      : filterByVex<T>(
          l,
          _vex,
          (v) => (id: v.id, name: v.packageName, version: v.installedVersion),
        );

  /// CVE (id normalisé) retirées de l'affichage par le VEX.
  int get _vexHidden {
    final all = <String>{};
    final shown = <String>{};
    void add(List<VulnRow>? a, List<VulnRow>? f) {
      for (final v in a ?? const <VulnRow>[]) {
        all.add(normalizeCveId(v.id));
      }
      for (final v in f ?? const <VulnRow>[]) {
        shown.add(normalizeCveId(v.id));
      }
    }

    add(_grypeVulns, filterByVex<GrypeVuln>(_grypeVulns, _vex, _vexKey));
    add(_osvVulns, filterByVex<OsvVuln>(_osvVulns, _vex, _vexKey));
    add(_trivyVulns, filterByVex<TrivyVuln>(_trivyVulns, _vex, _vexKey));
    return all.difference(shown).length;
  }

  static ({String id, String name, String version}) _vexKey(VulnRow v) =>
      (id: v.id, name: v.packageName, version: v.installedVersion);

  // ── Sessions : sauvegarde automatique, chargement, tendance ──────────────
  ScanSession? _baseline;
  Timer? _saveTimer;

  ScanSession _currentSession() => ScanSession(
    savedAt: DateTime.now(),
    guiVersion: kGuiVersion,
    targets: _scanTargets,
    grype: _grypeVulns,
    osv: _osvVulns,
    trivy: _trivyVulns,
    exploit: _mergedExploit,
  );

  /// Sauvegarde dans l'historique 2 s après la dernière modification des
  /// résultats (les signaux KEV/EPSS arrivent après les scans).
  void _scheduleSave() {
    _loadedTargets =
        null; // de nouveaux résultats remplacent la session chargée
    final store = widget.historyStore;
    if (store == null) return;
    _saveTimer?.cancel();
    _saveTimer = Timer(const Duration(seconds: 2), () {
      final s = _currentSession();
      if (s.isEmpty) return;
      store.save(s).catchError((Object _) => File(''));
    });
  }

  /// Résultat d'une analyse de la file : remplace celui du scanner concerné.
  void _applyJobResult(ScanJobResult r) {
    if (!mounted) return;
    setState(() {
      switch (r.scanner) {
        case 'Grype':
          _grypeVulns = r.grype;
          _grypeExploit = r.exploit;
          _grypeTarget = r.target;
        case 'OSV-Scanner':
          _osvVulns = r.osv;
          _osvExploit = r.exploit;
          _osvTarget = r.target;
        case 'Trivy':
          _trivyVulns = r.trivy;
          _trivyExploit = r.exploit;
          _trivyTarget = r.target;
      }
    });
    _scheduleSave();
  }

  void _loadSession(ScanSession s) => setState(() {
    _grypeVulns = s.grype;
    _osvVulns = s.osv;
    _trivyVulns = s.trivy;
    // Les signaux sont fusionnés pour le tableau de bord : on les place dans
    // l'un des trois accumulateurs.
    _grypeExploit = s.exploit;
    _osvExploit = const {};
    _trivyExploit = const {};
    _layerScans.clear();
    _loadedTargets = s.targets;
  });

  Map<String, ExploitInfo> get _mergedExploit {
    final out = <String, ExploitInfo>{};
    for (final m in [_grypeExploit, _osvExploit, _trivyExploit]) {
      for (final e in m.entries) {
        final cur = out[e.key];
        // On garde l'entrée qui porte le plus de signal (KEV > … > rien).
        if (cur == null ||
            (!cur.hasAnySignal && e.value.hasAnySignal) ||
            (!cur.inKev && e.value.inKev)) {
          out[e.key] = e.value;
        }
      }
    }
    return out;
  }

  // Filtres date indépendants par scanner
  CveDateFilter _grypeFilter = CveDateFilter.empty;
  CveDateFilter _osvFilter = CveDateFilter.empty;
  CveDateFilter _trivyFilter = CveDateFilter.empty;

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 15, vsync: this);
    _vex.addListener(() {
      if (mounted) setState(() {});
    });
    SettingsService.loadVex().then(_vex.restore);
  }

  @override
  void dispose() {
    _saveTimer?.cancel();
    _vex.dispose();
    _tabs.dispose();
    _logScroll.dispose();
    super.dispose();
  }

  @override
  void didUpdateWidget(ResultsPanel old) {
    super.didUpdateWidget(old);
    // Auto-scroll log
    if (widget.logLines.length != old.logLines.length) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (_logScroll.hasClients) {
          _logScroll.animateTo(
            _logScroll.position.maxScrollExtent,
            duration: const Duration(milliseconds: 150),
            curve: Curves.easeOut,
          );
        }
      });
    }
    // Basculer vers Progression dès le démarrage
    if (widget.isRunning && !old.isRunning) _tabs.animateTo(0);
    // Basculer vers Résultats une fois SBOM + PDF terminés
    final wasBusy = old.isRunning || old.isPdfRunning;
    final isBusy = widget.isRunning || widget.isPdfRunning;
    if (!isBusy && wasBusy && widget.exitCode == 0) {
      _tabs.animateTo(1);
    }
    // Auto-sélectionner un fichier pour la prévisualisation
    if (widget.outputFiles != old.outputFiles && _previewFile == null) {
      _autoSelectPreview();
    }
  }

  void _autoSelectPreview() {
    final previewable = widget.outputFiles
        .where((f) => !f.path.endsWith('.pdf'))
        .firstOrNull;
    if (previewable != null) _loadPreview(previewable);
  }

  Future<void> _loadPreview(OutputFile file) async {
    final l = context.l10n;
    setState(() {
      _previewFile = file;
      _previewLoading = true;
      _previewContent = null;
    });
    try {
      const maxChars = 50000;
      final raw = await File(file.path).readAsString();
      if (!mounted) return;
      setState(() {
        _previewContent = raw.length > maxChars
            ? '${raw.substring(0, maxChars)}\n\n${l.resultsPreviewTruncated(raw.length)}'
            : raw;
        _previewLoading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _previewContent = l.resultsReadError('$e');
        _previewLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isBusy = widget.isRunning || widget.isPdfRunning;
    final hasActivity =
        isBusy || widget.logLines.isNotEmpty || widget.outputFiles.isNotEmpty;

    final previewableFiles = widget.outputFiles
        .where((f) => !f.path.endsWith('.pdf'))
        .toList();

    return Column(
      children: [
        // Barre de progression SBOM
        if (widget.isRunning && widget.progressTotal > 0)
          _ProgressBar(
            current: widget.progressCurrent,
            total: widget.progressTotal,
            percent: widget.progressPercent,
            label: widget.progressLabel,
          ),

        // Bannière PDF en cours
        if (widget.isPdfRunning)
          Container(
            color: Colors.blue[50],
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Row(
              children: [
                const SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: Colors.blue,
                  ),
                ),
                const SizedBox(width: 10),
                Text(
                  context.l10n.resultsPdfConverting,
                  style: TextStyle(fontSize: 13, color: Colors.blue[800]),
                ),
              ],
            ),
          ),

        // Bannière de résultat
        if (!isBusy && widget.exitCode != null)
          _StatusBanner(
            exitCode: widget.exitCode!,
            outputFiles: widget.outputFiles,
            warnings: widget.warnings,
            fatalError: widget.fatalError,
          ),

        // TabBar
        ColoredBox(
          color: theme.colorScheme.surfaceContainerLow,
          child: TabBar(
            controller: _tabs,
            isScrollable: true,
            tabAlignment: TabAlignment.start,
            tabs: [
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    if (widget.isRunning)
                      const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    else
                      const Icon(Icons.terminal, size: 16),
                    const SizedBox(width: 6),
                    Text(context.l10n.tabProgress),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.assignment_outlined, size: 16),
                    const SizedBox(width: 6),
                    Text(
                      widget.outputFiles.isEmpty
                          ? context.l10n.tabResults
                          : context.l10n.tabResultsCount(
                              widget.outputFiles.length,
                            ),
                    ),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.dashboard_outlined, size: 16),
                    const SizedBox(width: 6),
                    Text(context.l10n.tabDashboard),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.playlist_play, size: 16),
                    const SizedBox(width: 6),
                    Text(context.l10n.tabTasks),
                  ],
                ),
              ),
              const Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.security_outlined, size: 16),
                    SizedBox(width: 6),
                    Text('Grype'),
                  ],
                ),
              ),
              const Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.plagiarism_outlined, size: 16),
                    SizedBox(width: 6),
                    Text('OSV-Scanner'),
                  ],
                ),
              ),
              const Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.shield_outlined, size: 16),
                    SizedBox(width: 6),
                    Text('Trivy'),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.gpp_good_outlined, size: 16),
                    const SizedBox(width: 6),
                    Text(context.l10n.tabCra),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.verified_outlined, size: 16),
                    const SizedBox(width: 6),
                    Text(context.l10n.tabQuality),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.account_tree_outlined, size: 16),
                    const SizedBox(width: 6),
                    Text(context.l10n.tabTree),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.compare_arrows, size: 16),
                    const SizedBox(width: 6),
                    Text(context.l10n.tabCompare),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.merge_type, size: 16),
                    const SizedBox(width: 6),
                    Text(context.l10n.tabMerge),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.gavel_outlined, size: 16),
                    const SizedBox(width: 6),
                    Text(context.l10n.tabLicenses),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.manage_search_outlined, size: 16),
                    const SizedBox(width: 6),
                    Text(context.l10n.tabViewer),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.preview_outlined, size: 16),
                    const SizedBox(width: 6),
                    Text(
                      previewableFiles.isEmpty
                          ? context.l10n.tabPreview
                          : context.l10n.tabPreviewCount(
                              previewableFiles.length,
                            ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),

        Expanded(
          child: VexScope(
            controller: _vex,
            child: TabBarView(
              controller: _tabs,
              children: [
                // Tab 0 : Progression
                hasActivity
                    ? Column(
                        children: [
                          if (!widget.isRunning && widget.logLines.isNotEmpty)
                            _LogExportBar(lines: widget.logLines),
                          Expanded(
                            child: _LogView(
                              lines: widget.logLines,
                              scrollController: _logScroll,
                            ),
                          ),
                          if (!isBusy &&
                              widget.exitCode == 0 &&
                              widget.progressTotal > 0)
                            _StatsCard(
                              packageCount: widget.progressTotal,
                              fileCount: widget.outputFiles.length,
                              warningCount: widget.warnings.length,
                            ),
                        ],
                      )
                    : const _EmptyHint(),

                // Tab 1 : Résultats
                _ResultsView(
                  outputFiles: widget.outputFiles,
                  warnings: widget.warnings,
                  fatalError: widget.fatalError,
                  exitCode: widget.exitCode,
                  sbomqsOutput: widget.sbomqsOutput,
                ),

                // Tab 2 : Tableau de bord
                DashboardPanel(
                  grypeVulns: _grypeShown,
                  osvVulns: _osvShown,
                  trivyVulns: _trivyShown,
                  vexBar: VexBar(
                    controller: _vex,
                    hide: _hideVex,
                    onHideChanged: (v) => setState(() => _hideVex = v),
                    hiddenCount: _vexHidden,
                  ),
                  exploitById: _mergedExploit,
                  scanTargets: _scanTargets,
                  layerScans: Map.of(_layerScans),
                  sessions: SessionActions(
                    current: _currentSession,
                    onLoad: _loadSession,
                    baseline: _baseline,
                    onBaseline: (b) => setState(() => _baseline = b),
                    store: widget.historyStore,
                  ),
                ),

                // Tab 3 : Tâches (file d'attente d'analyses)
                TasksPanel(
                  outputFiles: widget.outputFiles,
                  onResult: _applyJobResult,
                ),

                // Tab 4 : Grype
                GrypePanel(
                  outputFiles: widget.outputFiles,
                  onVulnsChanged: (v) {
                    setState(() => _grypeVulns = v);
                    _scheduleSave();
                  },
                  onExploitChanged: (m) {
                    setState(() => _grypeExploit = m);
                    _scheduleSave();
                  },
                  onScanTargetChanged: (t) => setState(() => _grypeTarget = t),
                  onLayerScanChanged: (r) => setState(
                    () => r == null
                        ? _layerScans.remove('Grype')
                        : _layerScans['Grype'] = r,
                  ),
                  dateFilter: _grypeFilter,
                  onDateFilterChanged: (f) => setState(() => _grypeFilter = f),
                  onPropagate: (f) => setState(() {
                    _osvFilter = f;
                    _trivyFilter = f;
                  }),
                ),

                // Tab 5 : OSV-Scanner
                OsvPanel(
                  outputFiles: widget.outputFiles,
                  onVulnsChanged: (v) {
                    setState(() => _osvVulns = v);
                    _scheduleSave();
                  },
                  onExploitChanged: (m) {
                    setState(() => _osvExploit = m);
                    _scheduleSave();
                  },
                  onScanTargetChanged: (t) => setState(() => _osvTarget = t),
                  onLayerScanChanged: (r) => setState(
                    () => r == null
                        ? _layerScans.remove('OSV-Scanner')
                        : _layerScans['OSV-Scanner'] = r,
                  ),
                  dateFilter: _osvFilter,
                  onDateFilterChanged: (f) => setState(() => _osvFilter = f),
                  onPropagate: (f) => setState(() {
                    _grypeFilter = f;
                    _trivyFilter = f;
                  }),
                ),

                // Tab 6 : Trivy
                TrivyPanel(
                  outputFiles: widget.outputFiles,
                  onVulnsChanged: (v) {
                    setState(() => _trivyVulns = v);
                    _scheduleSave();
                  },
                  onExploitChanged: (m) {
                    setState(() => _trivyExploit = m);
                    _scheduleSave();
                  },
                  onScanTargetChanged: (t) => setState(() => _trivyTarget = t),
                  onLayerScanChanged: (r) => setState(
                    () => r == null
                        ? _layerScans.remove('Trivy')
                        : _layerScans['Trivy'] = r,
                  ),
                  dateFilter: _trivyFilter,
                  onDateFilterChanged: (f) => setState(() => _trivyFilter = f),
                  onPropagate: (f) => setState(() {
                    _grypeFilter = f;
                    _osvFilter = f;
                  }),
                ),

                // Tab 7 : Conformité CRA
                CraPanel(outputFiles: widget.outputFiles),

                // Tab 8 : Qualité SBOM
                QualityPanel(outputFiles: widget.outputFiles),

                // Tab 9 : Arborescence SBOM
                SbomTreePanel(outputFiles: widget.outputFiles),

                // Tab 10 : Comparaison SBOM
                SbomDiffPanel(outputFiles: widget.outputFiles),

                // Tab 11 : Fusion SBOM
                SbomMergePanel(outputFiles: widget.outputFiles),

                // Tab 12 : Licences SBOM
                SbomLicensesPanel(outputFiles: widget.outputFiles),

                // Tab 13 : Visionneuse SBOM
                const SbomViewerPanel(),

                // Tab 14 : Aperçu SBOM
                _SbomPreviewTab(
                  files: previewableFiles,
                  selectedFile: _previewFile,
                  content: _previewContent,
                  isLoading: _previewLoading,
                  onSelectFile: _loadPreview,
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

// ─── Progress bar ─────────────────────────────────────────────────────────────

class _ProgressBar extends StatelessWidget {
  final int current;
  final int total;
  final int percent;
  final String label;

  const _ProgressBar({
    required this.current,
    required this.total,
    required this.percent,
    required this.label,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      color: theme.colorScheme.surfaceContainerLowest,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                context.l10n.resultsProgressPackages(current, total),
                style: const TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(width: 12),
              Text(
                '$percent%',
                style: TextStyle(
                  fontSize: 12,
                  color: theme.colorScheme.primary,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const Spacer(),
              if (label.isNotEmpty)
                Flexible(
                  child: Text(
                    label,
                    style: const TextStyle(
                      fontSize: 11,
                      fontFamily: 'monospace',
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
            ],
          ),
          const SizedBox(height: 6),
          LinearProgressIndicator(
            value: total > 0 ? current / total : null,
            minHeight: 6,
            borderRadius: BorderRadius.circular(3),
          ),
        ],
      ),
    );
  }
}

// ─── Status banner ────────────────────────────────────────────────────────────

class _StatusBanner extends StatelessWidget {
  final int exitCode;
  final List<OutputFile> outputFiles;
  final List<String> warnings;
  final String? fatalError;

  const _StatusBanner({
    required this.exitCode,
    required this.outputFiles,
    required this.warnings,
    this.fatalError,
  });

  @override
  Widget build(BuildContext context) {
    final ok = exitCode == 0;
    return Container(
      color: ok ? Colors.green[50] : Colors.red[50],
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Row(
        children: [
          Icon(
            ok ? Icons.check_circle : Icons.error_outline,
            color: ok ? Colors.green[700] : Colors.red[700],
            size: 20,
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              ok
                  ? context.l10n.resultsSummaryOk(outputFiles.length) +
                        (warnings.isNotEmpty
                            ? context.l10n.resultsSummaryWarnings(
                                warnings.length,
                              )
                            : '')
                  : fatalError ??
                        context.l10n.resultsGenerationFailed(exitCode),
              style: TextStyle(
                fontWeight: FontWeight.bold,
                color: ok ? Colors.green[800] : Colors.red[800],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Log export toolbar ───────────────────────────────────────────────────────

class _LogExportBar extends StatelessWidget {
  final List<String> lines;
  const _LogExportBar({required this.lines});

  @override
  Widget build(BuildContext context) {
    return Container(
      color: const Color(0xFF2D2D2D),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [
          TextButton.icon(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: lines.join('\n')));
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text(context.l10n.resultsLogsCopied),
                  duration: const Duration(seconds: 2),
                ),
              );
            },
            icon: const Icon(Icons.copy, size: 14, color: Colors.grey),
            label: Text(
              context.l10n.commonCopy,
              style: const TextStyle(color: Colors.grey, fontSize: 12),
            ),
          ),
          TextButton.icon(
            onPressed: () async {
              final path = await FilePicker.saveFile(
                dialogTitle: context.l10n.resultsSaveLogsTitle,
                fileName: 'sbom_generator.log',
              );
              if (path != null) {
                await File(path).writeAsString(lines.join('\n'));
              }
            },
            icon: const Icon(Icons.save_outlined, size: 14, color: Colors.grey),
            label: Text(
              context.l10n.resultsSave,
              style: const TextStyle(color: Colors.grey, fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Stats card ───────────────────────────────────────────────────────────────

class _StatsCard extends StatelessWidget {
  final int packageCount;
  final int fileCount;
  final int warningCount;

  const _StatsCard({
    required this.packageCount,
    required this.fileCount,
    required this.warningCount,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final accentColor = warningCount > 0 ? Colors.orange : Colors.green;
    return Container(
      margin: const EdgeInsets.all(10),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: accentColor.withValues(alpha: 0.5)),
      ),
      child: Row(
        children: [
          Icon(Icons.check_circle_outline, color: accentColor, size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Wrap(
              spacing: 18,
              runSpacing: 4,
              children: [
                _StatItem(
                  icon: Icons.inventory_2_outlined,
                  label: context.l10n.resultsStatPackages(packageCount),
                ),
                _StatItem(
                  icon: Icons.description_outlined,
                  label: context.l10n.resultsStatFiles(fileCount),
                ),
                if (warningCount > 0)
                  _StatItem(
                    icon: Icons.warning_amber_outlined,
                    label: context.l10n.resultsStatWarnings(warningCount),
                    color: Colors.orange,
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _StatItem extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color? color;

  const _StatItem({required this.icon, required this.label, this.color});

  @override
  Widget build(BuildContext context) {
    final c = color ?? Theme.of(context).colorScheme.onSurface;
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 13, color: c),
        const SizedBox(width: 4),
        Text(label, style: TextStyle(fontSize: 12, color: c)),
      ],
    );
  }
}

// ─── Log view ─────────────────────────────────────────────────────────────────

class _LogView extends StatelessWidget {
  final List<String> lines;
  final ScrollController scrollController;

  const _LogView({required this.lines, required this.scrollController});

  static Color? _lineColor(String line) {
    if (line.startsWith('\$ ')) return Colors.cyan[300];
    if (line.startsWith('Error:')) return Colors.red[300];
    if (line.startsWith('Warning:') ||
        line.startsWith('⚠') ||
        line.startsWith('   •')) {
      return Colors.orange[300];
    }
    if (line.contains('SBOM written')) return Colors.green[300];
    if (line.contains('PDF written')) return Colors.green[300];
    if (line.startsWith('Conversion PDF') ||
        line.startsWith('PDF conversion')) {
      return Colors.lightBlue[300];
    }
    // Messages de progression du CLI (français ou anglais).
    if (line.startsWith('Generating') ||
        line.startsWith('Génération') ||
        line.startsWith('Resolving') ||
        line.startsWith('Résolution') ||
        line.startsWith('Found') ||
        line.startsWith('Analysed') ||
        line.startsWith('Analysés')) {
      return Colors.blue[300];
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      color: const Color(0xFF1E1E1E),
      padding: const EdgeInsets.all(12),
      child: SelectionArea(
        child: ListView.builder(
          controller: scrollController,
          itemCount: lines.length,
          itemBuilder: (_, i) {
            final line = lines[i];
            return Text(
              line,
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 12,
                color: _lineColor(line) ?? const Color(0xFFD4D4D4),
                height: 1.5,
              ),
            );
          },
        ),
      ),
    );
  }
}

// ─── Results view ─────────────────────────────────────────────────────────────

class _ResultsView extends StatelessWidget {
  final List<OutputFile> outputFiles;
  final List<String> warnings;
  final String? fatalError;
  final int? exitCode;
  final String? sbomqsOutput;

  const _ResultsView({
    required this.outputFiles,
    required this.warnings,
    this.fatalError,
    this.exitCode,
    this.sbomqsOutput,
  });

  @override
  Widget build(BuildContext context) {
    if (outputFiles.isEmpty && warnings.isEmpty && fatalError == null) {
      return const _EmptyHint();
    }

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Fichiers générés
        if (outputFiles.isNotEmpty) ...[
          _SectionTitle(
            icon: Icons.insert_drive_file_outlined,
            label: context.l10n.resultsSectionFiles,
          ),
          const SizedBox(height: 8),
          for (final f in outputFiles) _OutputFileCard(file: f),
          const SizedBox(height: 20),
        ],

        // Score sbomqs
        if (sbomqsOutput != null) ...[
          _SectionTitle(
            icon: Icons.analytics_outlined,
            label: context.l10n.resultsSectionScore,
            color: Colors.indigo[600],
          ),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: Colors.indigo[50],
              borderRadius: BorderRadius.circular(6),
              border: Border.all(color: Colors.indigo[200]!),
            ),
            child: SelectableText(
              sbomqsOutput!,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ),
          const SizedBox(height: 20),
        ],

        // Avertissements
        if (warnings.isNotEmpty) ...[
          _SectionTitle(
            icon: Icons.warning_amber_outlined,
            label: context.l10n.resultsSectionWarnings(warnings.length),
            color: Colors.orange[700],
          ),
          const SizedBox(height: 8),
          _WarningsList(warnings: warnings),
          const SizedBox(height: 20),
        ],

        // Erreur fatale
        if (fatalError != null) ...[
          _SectionTitle(
            icon: Icons.error_outline,
            label: context.l10n.resultsSectionError,
            color: Colors.red[700],
          ),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.red[50],
              borderRadius: BorderRadius.circular(6),
              border: Border.all(color: Colors.red[200]!),
            ),
            child: SelectableText(
              fatalError!,
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 12,
                color: Colors.red[800],
              ),
            ),
          ),
        ],
      ],
    );
  }
}

// ─── SBOM Preview tab ─────────────────────────────────────────────────────────

class _SbomPreviewTab extends StatelessWidget {
  final List<OutputFile> files;
  final OutputFile? selectedFile;
  final String? content;
  final bool isLoading;
  final ValueChanged<OutputFile> onSelectFile;

  const _SbomPreviewTab({
    required this.files,
    required this.selectedFile,
    required this.content,
    required this.isLoading,
    required this.onSelectFile,
  });

  @override
  Widget build(BuildContext context) {
    if (files.isEmpty) {
      return _EmptyHint(
        icon: Icons.preview_outlined,
        message: context.l10n.resultsNoPreview,
      );
    }

    return Column(
      children: [
        // Sélecteur de fichier
        Container(
          color: Theme.of(context).colorScheme.surfaceContainerLow,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          child: Row(
            children: [
              const Icon(Icons.file_present_outlined, size: 16),
              const SizedBox(width: 8),
              Expanded(
                child: DropdownButton<OutputFile>(
                  value: selectedFile,
                  isExpanded: true,
                  isDense: true,
                  underline: const SizedBox.shrink(),
                  items: files
                      .map(
                        (f) => DropdownMenuItem(
                          value: f,
                          child: Text(
                            f.path.split('/').last,
                            style: const TextStyle(
                              fontFamily: 'monospace',
                              fontSize: 12,
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      )
                      .toList(),
                  onChanged: (f) {
                    if (f != null) onSelectFile(f);
                  },
                ),
              ),
              if (content != null)
                IconButton(
                  icon: const Icon(Icons.copy_outlined, size: 16),
                  tooltip: context.l10n.resultsCopyContent,
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: content!));
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text(context.l10n.resultsContentCopied),
                        duration: const Duration(seconds: 2),
                      ),
                    );
                  },
                ),
            ],
          ),
        ),

        // Contenu
        Expanded(
          child: isLoading
              ? const Center(child: CircularProgressIndicator())
              : content == null
              ? _EmptyHint(
                  icon: Icons.preview_outlined,
                  message: context.l10n.resultsSelectFile,
                )
              : Container(
                  color: const Color(0xFF1E1E1E),
                  padding: const EdgeInsets.all(12),
                  child: SelectionArea(
                    child: SingleChildScrollView(
                      child: Text(
                        content!,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 12,
                          color: Color(0xFFD4D4D4),
                          height: 1.5,
                        ),
                      ),
                    ),
                  ),
                ),
        ),
      ],
    );
  }
}

// ─── Output file card ─────────────────────────────────────────────────────────

class _OutputFileCard extends StatelessWidget {
  final OutputFile file;
  const _OutputFileCard({required this.file});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final exists = File(file.path).existsSync();
    final ext = file.path.split('.').last;

    final iconColor = switch (ext) {
      'json' || 'jsonld' => theme.colorScheme.primary,
      'md' => Colors.purple[600],
      'adoc' => Colors.teal[600],
      'pdf' => Colors.red[700],
      _ => theme.colorScheme.secondary,
    };

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: Icon(
          ext == 'pdf'
              ? Icons.picture_as_pdf_outlined
              : Icons.description_outlined,
          color: iconColor,
        ),
        title: Text(
          file.path.split('/').last,
          style: const TextStyle(
            fontFamily: 'monospace',
            fontWeight: FontWeight.w600,
          ),
        ),
        subtitle: Text(
          file.path,
          style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
          overflow: TextOverflow.ellipsis,
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              file.size,
              style: TextStyle(
                fontSize: 12,
                color: theme.colorScheme.onSurface.withValues(alpha: 0.6),
              ),
            ),
            const SizedBox(width: 8),
            IconButton(
              icon: const Icon(Icons.copy_outlined, size: 18),
              tooltip: context.l10n.resultsCopyPath,
              onPressed: () {
                Clipboard.setData(ClipboardData(text: file.path));
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(context.l10n.resultsPathCopied),
                    duration: const Duration(seconds: 2),
                  ),
                );
              },
            ),
            if (exists)
              IconButton(
                icon: const Icon(Icons.open_in_new, size: 18),
                tooltip: context.l10n.resultsOpenFile,
                onPressed: () => launchUrl(Uri.file(file.path)),
              ),
          ],
        ),
      ),
    );
  }
}

class _WarningsList extends StatefulWidget {
  final List<String> warnings;
  const _WarningsList({required this.warnings});

  @override
  State<_WarningsList> createState() => _WarningsListState();
}

class _WarningsListState extends State<_WarningsList> {
  bool _expanded = false;
  static const _previewCount = 5;

  @override
  Widget build(BuildContext context) {
    final shown = _expanded
        ? widget.warnings
        : widget.warnings.take(_previewCount).toList();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: Colors.orange[50],
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: Colors.orange[200]!),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              for (final w in shown)
                Padding(
                  padding: const EdgeInsets.only(bottom: 2),
                  child: Text(
                    w,
                    style: const TextStyle(
                      fontSize: 12,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
            ],
          ),
        ),
        if (widget.warnings.length > _previewCount) ...[
          const SizedBox(height: 4),
          TextButton(
            onPressed: () => setState(() => _expanded = !_expanded),
            child: Text(
              _expanded
                  ? context.l10n.resultsCollapse
                  : context.l10n.resultsShowMore(
                      widget.warnings.length - _previewCount,
                    ),
            ),
          ),
        ],
      ],
    );
  }
}

class _SectionTitle extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color? color;

  const _SectionTitle({required this.icon, required this.label, this.color});

  @override
  Widget build(BuildContext context) {
    final c = color ?? Theme.of(context).colorScheme.primary;
    return Row(
      children: [
        Icon(icon, size: 16, color: c),
        const SizedBox(width: 6),
        Text(
          label,
          style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold, color: c),
        ),
      ],
    );
  }
}

class _EmptyHint extends StatelessWidget {
  final IconData icon;
  final String? message;

  const _EmptyHint({this.icon = Icons.inventory_2_outlined, this.message});

  @override
  Widget build(BuildContext context) => Center(
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 56, color: Colors.grey),
        const SizedBox(height: 12),
        Text(
          message ?? context.l10n.resultsEmptyHint,
          style: const TextStyle(color: Colors.grey, fontSize: 15),
          textAlign: TextAlign.center,
        ),
      ],
    ),
  );
}
