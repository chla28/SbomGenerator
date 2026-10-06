import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../models/cve_date_filter.dart';
import '../models/sbom_result.dart';
import '../services/package_scan_service.dart';
import '../services/scan_enrichment.dart';
import '../services/settings_service.dart';
import '../l10n/l10n.dart';
import '../models/layer_scan.dart';
import '../services/layer_scan_service.dart';
import '../services/trivy_runner.dart';
import 'help_icon.dart';
import '../services/version_service.dart';
import 'on_pale.dart';
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
  @override
  final int occurrenceCount;

  const TrivyVuln({
    required this.id,
    required this.severity,
    required this.packageName,
    required this.installedVersion,
    required this.fixedVersion,
    required this.title,
    this.publishedDate,
    this.modifiedDate,
    this.occurrenceCount = 1,
  });

  /// Reconstruit cette entrée avec un nombre d'occurrences fusionnées — voir
  /// [dedupeVulns].
  TrivyVuln withOccurrenceCount(int count) => TrivyVuln(
    id: id,
    severity: severity,
    packageName: packageName,
    installedVersion: installedVersion,
    fixedVersion: fixedVersion,
    title: title,
    publishedDate: publishedDate,
    modifiedDate: modifiedDate,
    occurrenceCount: count,
  );

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
        vulns.add(
          TrivyVuln(
            id: v['VulnerabilityID'] as String? ?? '',
            severity: v['Severity'] as String? ?? 'Unknown',
            packageName: v['PkgName'] as String? ?? '',
            installedVersion: v['InstalledVersion'] as String? ?? '',
            fixedVersion: v['FixedVersion'] as String? ?? '',
            title: v['Title'] as String? ?? '',
            publishedDate: _parseDate(v['PublishedDate'] as String?),
            modifiedDate: _parseDate(v['LastModifiedDate'] as String?),
          ),
        );
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
  final void Function(Map<String, ExploitInfo>)? onExploitChanged;

  /// Cible réellement analysée — pour l'en-tête des rapports exportés.
  final void Function(String target)? onScanTargetChanged;

  /// Analyse par couche du dernier scan (`null` : scan sans couches).
  final void Function(LayerScanResult?)? onLayerScanChanged;
  final CveDateFilter dateFilter;
  final void Function(CveDateFilter)? onDateFilterChanged;
  final void Function(CveDateFilter)? onPropagate;

  const TrivyPanel({
    super.key,
    required this.outputFiles,
    this.onVulnsChanged,
    this.onExploitChanged,
    this.onScanTargetChanged,
    this.onLayerScanChanged,
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
  final _imageCtrl = TextEditingController();
  final _packageCtrl = TextEditingController();
  String _packageDepth = '0';
  final _imagePlatformCtrl = TextEditingController();
  final _configCtrl = TextEditingController();
  late final TabController _resultTabs;

  // Source à analyser : fichier SBOM (par défaut) ou image de conteneur
  ScanSourceKind _sourceKind = ScanSourceKind.sbomFile;

  // Analyse par couche (source image)
  LayerScanSettings _layerSettings = const LayerScanSettings();
  LayerScanResult? _layerScan;
  String? _status;
  bool _layeredCancelled = false;

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

  Map<String, ExploitInfo> _exploitById = const {};
  bool _enrichPending = false;
  bool _enrichOnline = true;
  int _enrichRun = 0;
  String? _scannedTarget;

  ToolVersionInfo? _versionInfo;

  @override
  void initState() {
    super.initState();
    _resultTabs = TabController(length: 2, vsync: this);
    _updateAutoFile();
    SettingsService.loadScanEnrichOnline().then((v) {
      if (mounted) setState(() => _enrichOnline = v);
    });
    VersionService.checkTrivy().then((info) {
      if (mounted) setState(() => _versionInfo = info);
    });
  }

  /// Enrichit les CVE trouvées avec les signaux d'exploitabilité. Trivy
  /// n'expose ni KEV ni EPSS : le réseau est requis (CISA KEV + FIRST EPSS +
  /// PoC).
  Future<void> _enrich(String rawJson, List<TrivyVuln> vulns) async {
    final ids = {for (final v in vulns) normalizeCveId(v.id)}..remove('');
    if (ids.isEmpty) return;
    final run = ++_enrichRun;
    setState(() => _enrichPending = _enrichOnline);
    try {
      final result = await enrichCves(
        ids,
        seed: seedsFromTrivyJson(rawJson),
        online: _enrichOnline,
      );
      if (mounted && run == _enrichRun) {
        setState(() {
          _exploitById = result;
          _enrichPending = false;
        });
        widget.onExploitChanged?.call(result);
      }
    } catch (_) {
      if (mounted && run == _enrichRun) setState(() => _enrichPending = false);
    }
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
    _imageCtrl.dispose();
    _packageCtrl.dispose();
    _imagePlatformCtrl.dispose();
    _configCtrl.dispose();
    _resultTabs.dispose();
    super.dispose();
  }

  void _updateAutoFile() {
    if (widget.outputFiles.isEmpty || _fileCtrl.text.isNotEmpty) return;
    final preferred = widget.outputFiles
        .where(
          (f) => f.path.endsWith('.cdx.json') || f.path.endsWith('.spdx.json'),
        )
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
      dialogTitle: context.l10n.scanPickSbomTitle,
    );
    if (r?.files.single.path != null) {
      setState(() => _fileCtrl.text = r!.files.single.path!);
    }
  }

  Future<void> _pickImageArchive() async {
    final r = await FilePicker.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['tar', 'gz', 'tgz'],
      dialogTitle: context.l10n.scanPickImageArchiveTitle,
    );
    if (r?.files.single.path != null) {
      setState(() => _imageCtrl.text = r!.files.single.path!);
    }
  }

  Future<void> _pickImageOciDir() async {
    final dir = await FilePicker.getDirectoryPath(
      dialogTitle: context.l10n.scanSourcePickOciDir,
    );
    if (dir != null) setState(() => _imageCtrl.text = dir);
  }

  Future<void> _pickConfigFile({bool filtered = true}) async {
    final r = await FilePicker.pickFiles(
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? ['yaml', 'yml'] : null,
      dialogTitle: context.l10n.trivyPickConfigTitle,
    );
    if (r?.files.single.path != null) {
      setState(() => _configCtrl.text = r!.files.single.path!);
    }
  }

  Future<void> _pickPackage() async {
    final result = await FilePicker.pickFiles(
      type: FileType.any,
      dialogTitle: context.l10n.scanPickPackageTitle,
    );
    if (result?.files.single.path != null) {
      setState(() => _packageCtrl.text = result!.files.single.path!);
    }
  }

  void _analyze() {
    if (_sourceKind == ScanSourceKind.package) {
      _analyzePackage();
      return;
    }
    final useImage = _sourceKind == ScanSourceKind.image;
    final target = (useImage ? _imageCtrl.text : _fileCtrl.text).trim();
    if (target.isEmpty) {
      setState(
        () => _error = useImage
            ? context.l10n.scanSourceMissingImage
            : context.l10n.scanSourceMissingSbom,
      );
      return;
    }
    // Une référence de registre (nginx:latest) n'est pas un chemin local :
    // on ne vérifie l'existence que pour un fichier SBOM ou une archive/
    // répertoire OCI local explicitement désigné comme tel (préfixe ./, /, ~).
    if ((!useImage || looksLikeLocalPath(target)) &&
        !File(target).existsSync() &&
        !Directory(target).existsSync()) {
      setState(() => _error = context.l10n.commonFileNotFound(target));
      return;
    }

    final targetLabel = useImage
        ? context.l10n.scanTargetImage(target)
        : context.l10n.scanTargetSbom(target.split(RegExp(r'[/\\]')).last);
    _launch(target, useImage, targetLabel);
  }

  /// Analyse d'un paquet/archive local : génère d'abord son SBOM (avec la
  /// profondeur choisie, voir [PackageScanService]) puis le scanne comme un
  /// fichier SBOM.
  Future<void> _analyzePackage() async {
    final l10n = context.l10n;
    final pkg = _packageCtrl.text.trim();
    if (pkg.isEmpty) {
      setState(() => _error = l10n.scanSourceMissingPackage);
      return;
    }
    if (!File(pkg).existsSync()) {
      setState(() => _error = l10n.commonFileNotFound(pkg));
      return;
    }
    final depth = _packageDepth;
    final name = pkg.split(RegExp(r'[/\\]')).last;
    final label = depth == '0'
        ? 'paquet « $name »'
        : 'paquet « $name » (profondeur $depth)';
    setState(() {
      _isRunning = true;
      _vulns = [];
      _jsonOutput = '';
      _error = null;
      _parseFailed = false;
      _exitCode = null;
      _layerScan = null;
      _status = l10n.scanPackagePreparing;
    });
    final String sbom;
    try {
      sbom = await PackageScanService.prepare(pkg, depth);
    } catch (e) {
      // Arrêt demandé pendant la génération : rien à afficher.
      if (!mounted || !_isRunning) return;
      setState(() {
        _isRunning = false;
        _status = null;
        _exitCode = 1;
        _error = l10n.scanPackageFailed('$e');
      });
      return;
    }
    if (!mounted || !_isRunning) return;
    _launch(sbom, false, label);
  }

  void _launch(String target, bool useImage, String targetLabel) {
    widget.onScanTargetChanged?.call(targetLabel);

    setState(() {
      _isRunning = true;
      _vulns = [];
      _jsonOutput = '';
      _error = null;
      _parseFailed = false;
      _exitCode = null;
      _scannedTarget = targetLabel;
      _layerScan = null;
      _status = null;
    });

    if (useImage && _layerSettings.enabled) {
      _analyzeLayered(target);
      return;
    }
    widget.onLayerScanChanged?.call(null);

    _start(target, useImage).listen(
      (event) {
        if (!mounted) return;
        switch (event) {
          case TrivyOutputEvent(:final jsonOutput):
            try {
              final raw = TrivyVuln.fromJson(jsonOutput);
              // Fusionne les doublons visuels : une même bibliothèque peut
              // être détectée à plusieurs emplacements (ex. jar autonome +
              // copie shadée dans un autre jar) avec la même sévérité/CVE/
              // paquet/version — voir dedupeVulns dans vuln_shared.dart.
              final vulns = dedupeVulns(
                raw,
                (v, n) => v.withOccurrenceCount(n),
              );
              setState(() {
                _jsonOutput = jsonOutput;
                _vulns = vulns;
                _exploitById = const {};
              });
              widget.onVulnsChanged?.call(_vulns);
              _enrich(jsonOutput, vulns);
            } catch (e) {
              setState(() {
                _jsonOutput = jsonOutput;
                _vulns = [];
                _parseFailed = true;
                _error = context.l10n.scanUnreadableOutput('trivy', '$e');
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

  Stream<TrivyEvent> _start(String target, bool useImage) => _runner.run(
    target: target,
    useImage: useImage,
    platform: useImage && _imagePlatformCtrl.text.trim().isNotEmpty
        ? _imagePlatformCtrl.text.trim()
        : null,
    severities: _selectedSeverities.toList(),
    ignoreUnfixed: _ignoreUnfixed,
    skipDbUpdate: _skipDbUpdate,
    configFile: _configCtrl.text.trim().isEmpty
        ? null
        : _configCtrl.text.trim(),
  );

  /// Commandes du popup « CLI Commande » pour le paramétrage courant.
  List<CliCommandSection> _cliSections() {
    if (_sourceKind != ScanSourceKind.package) return _scanCliSections();
    final raw = _packageCtrl.text.trim();
    final pkg = raw.isNotEmpty ? raw : context.l10n.cliPlaceholderPackage;
    final l10n = context.l10n;
    return [
      CliCommandSection(
        l10n.cliCommandPackagePrepare,
        shellCommand(
          SettingsService.cliBinary,
          PackageScanService.prepareArgs(pkg, _packageDepth, cliPackageSbom),
        ),
        note: l10n.cliCommandPackageNote,
      ),
      ..._scanCliSections(sbomTarget: cliPackageSbom, packageTarget: pkg),
    ];
  }

  List<CliCommandSection> _scanCliSections({
    String? sbomTarget,
    String? packageTarget,
  }) {
    final useImage = _sourceKind == ScanSourceKind.image;
    final raw =
        sbomTarget ?? (useImage ? _imageCtrl.text : _fileCtrl.text).trim();
    final target = raw.isNotEmpty
        ? raw
        : (useImage ? '<image>' : '<sbom.cdx.json>');
    final config = _configCtrl.text.trim().isEmpty
        ? null
        : _configCtrl.text.trim();
    final platform = _imagePlatformCtrl.text.trim();
    List<String> args(String t, bool image) => TrivyRunner.buildArgs(
      target: t,
      useImage: image,
      platform: image && platform.isNotEmpty ? platform : null,
      severities: _selectedSeverities.toList(),
      ignoreUnfixed: _ignoreUnfixed,
      skipDbUpdate: _skipDbUpdate,
      configFile: config,
    );
    final layered = useImage && _layerSettings.enabled;
    return [
      layered
          ? CliCommandSection(
              context.l10n.cliCommandExecutedLayered,
              layeredCliSequence(
                cliBinary: SettingsService.cliBinary,
                prepareArgs: LayerScanService.prepareArgs(
                  target,
                  _layerSettings.layerMode,
                  '$cliLayerDir/image.cdx.json',
                ),
                layers: _layerSettings,
                imageScan: shellCommand('trivy', args(target, true)),
                layerScan: (f) => shellCommand(
                  'trivy',
                  args('LAYER_SBOM', false),
                ).replaceAll('LAYER_SBOM', f),
              ),
              note: context.l10n.cliCommandLayerDirNote(cliLayerDir),
            )
          : CliCommandSection(
              context.l10n.cliCommandExecuted,
              shellCommand('trivy', args(target, useImage)),
            ),
      CliCommandSection(
        context.l10n.cliCommandEquivalent,
        shellCommand(
          SettingsService.cliBinary,
          sbomGeneratorScanArgs(
            scanner: 'trivy',
            target: packageTarget ?? target,
            useImage: useImage,
            usePackage: packageTarget != null,
            packageDepth: _packageDepth,
            layers: _layerSettings,
            dateFilter: widget.dateFilter,
            enrichOnline: _enrichOnline,
          ),
        ),
        note: equivalentScanNote(context.l10n, useImage, [
          if (_selectedSeverities.isNotEmpty) '--severity',
          if (_ignoreUnfixed) '--ignore-unfixed',
          if (_skipDbUpdate) '--skip-db-update',
          if (config != null) context.l10n.trivyCliConfigNote,
          if (useImage && platform.isNotEmpty)
            context.l10n.trivyCliPlatformNote,
        ]),
      ),
    ];
  }

  Future<ScanOutput> _scanOnce(String target, bool useImage) async {
    var json = '';
    var code = 1;
    String? err;
    await for (final e in _start(target, useImage)) {
      switch (e) {
        case TrivyOutputEvent(:final jsonOutput):
          json = jsonOutput;
        case TrivyDoneEvent(:final exitCode, :final stderr):
          code = exitCode;
          err = stderr;
      }
    }
    return (json: json, exitCode: code, stderr: err);
  }

  /// Analyse par couche de l'image [image] (voir [LayerScanService.run]) ;
  /// en rattachement, la couche indiquée par trivy lui-même
  /// (`Layer.DiffID`) est prioritaire.
  Future<void> _analyzeLayered(String image) async {
    _layeredCancelled = false;
    try {
      final r = await LayerScanService.run(
        image: image,
        settings: _layerSettings,
        scanOnce: _scanOnce,
        parse: TrivyVuln.fromJson,
        merge: mergeTrivyJson,
        nativeDigests: trivyLayerDigests,
        onStatus: (step) {
          if (mounted) {
            setState(() => _status = layerScanStepLabel(context.l10n, step));
          }
        },
        isCancelled: () => _layeredCancelled,
      );
      if (!mounted) return;
      var vulns = <TrivyVuln>[];
      var parseFailed = false;
      var error = r.stderr;
      if (r.json.isNotEmpty) {
        try {
          vulns = dedupeVulns(
            TrivyVuln.fromJson(r.json),
            (v, n) => v.withOccurrenceCount(n),
          );
          error = null;
        } catch (e) {
          parseFailed = true;
          error = context.l10n.scanUnreadableOutput('trivy', '$e');
        }
      }
      setState(() {
        _isRunning = false;
        _status = null;
        _exitCode = r.exitCode;
        _jsonOutput = r.json;
        _vulns = vulns;
        _parseFailed = parseFailed;
        _error = vulns.isEmpty ? error : null;
        _layerScan = r.layerScan;
        _exploitById = const {};
      });
      widget.onVulnsChanged?.call(_vulns);
      widget.onLayerScanChanged?.call(_layerScan);
      if (vulns.isNotEmpty) _enrich(r.json, vulns);
    } catch (e) {
      if (mounted) {
        setState(() {
          _isRunning = false;
          _status = null;
          _error = '$e';
          _exitCode = 1;
        });
      }
    }
  }

  void _stop() {
    _layeredCancelled = true;
    LayerScanService.kill();
    PackageScanService.kill();
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
          imageCtrl: _imageCtrl,
          imagePlatformCtrl: _imagePlatformCtrl,
          sourceKind: _sourceKind,
          packageCtrl: _packageCtrl,
          packageDepth: _packageDepth,
          onPackageDepthChanged: (d) => setState(() => _packageDepth = d),
          onPickPackage: _pickPackage,
          onSourceKindChanged: (k) => setState(() => _sourceKind = k),
          layerSettings: _layerSettings,
          onLayerSettingsChanged: (v) => setState(() => _layerSettings = v),
          onPickImageArchive: _pickImageArchive,
          onPickImageOciDir: _pickImageOciDir,
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
          cliSections: _cliSections,
          versionInfo: _versionInfo,
        ),
        if (_isRunning && _status != null) ...[
          const LinearProgressIndicator(minHeight: 3),
          ScanStatusLine(_status!),
        ],
        if (hasDone && _error != null) ErrorBanner(message: _error!),
        if (hasDone && _error == null)
          _TrivyBanner(vulns: _vulns, exitCode: _exitCode!),
        if (hasDone)
          ColoredBox(
            color: Theme.of(context).colorScheme.surfaceContainerLow,
            child: TabBar(
              controller: _resultTabs,
              tabs: [
                Tab(
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.security_outlined, size: 16),
                      const SizedBox(width: 6),
                      Text(context.l10n.scanTabVulns),
                    ],
                  ),
                ),
                Tab(
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.data_object, size: 16),
                      const SizedBox(width: 6),
                      Text(context.l10n.scanTabRawJson),
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
                  parseFailedMessage: context.l10n.scanUnreadableOutputShort(
                    'Trivy',
                  ),
                  severityOrder: const [
                    'CRITICAL',
                    'HIGH',
                    'MEDIUM',
                    'LOW',
                    'UNKNOWN',
                  ],
                  toolName: 'Trivy',
                  csvDialogTitle: context.l10n.scanExportCsvDialog('Trivy'),
                  csvFileName: 'trivy_vulns.csv',
                  csvHeader: context.l10n.vulnCsvHeaderTrivy,
                  csvRow: (v) => [
                    v.severity,
                    v.id,
                    v.packageName,
                    v.installedVersion,
                    v.fixedVersion,
                    v.title,
                    '${v.occurrenceCount}',
                  ],
                  descriptionOf: (v) => v.title,
                  dateFilter: widget.dateFilter,
                  onDateFilterChanged: widget.onDateFilterChanged,
                  onPropagate: widget.onPropagate,
                  exploitById: _exploitById,
                  layerScan: _layerScan,
                  scanTarget: _scannedTarget,
                  enrichPending: _enrichPending,
                  enrichOnline: _enrichOnline,
                  onEnrichOnlineChanged: (v) {
                    setState(() => _enrichOnline = v);
                    SettingsService.saveScanEnrichOnline(v);
                    if (_vulns.isNotEmpty && _jsonOutput.isNotEmpty) {
                      _enrich(_jsonOutput, _vulns);
                    }
                  },
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
  final TextEditingController imageCtrl;
  final TextEditingController imagePlatformCtrl;
  final ScanSourceKind sourceKind;
  final TextEditingController packageCtrl;
  final String packageDepth;
  final ValueChanged<String> onPackageDepthChanged;
  final VoidCallback onPickPackage;
  final ValueChanged<ScanSourceKind> onSourceKindChanged;
  final LayerScanSettings layerSettings;
  final ValueChanged<LayerScanSettings> onLayerSettingsChanged;
  final VoidCallback onPickImageArchive;
  final VoidCallback onPickImageOciDir;
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
  final List<CliCommandSection> Function() cliSections;
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
    required this.imageCtrl,
    required this.imagePlatformCtrl,
    required this.sourceKind,
    required this.packageCtrl,
    required this.packageDepth,
    required this.onPackageDepthChanged,
    required this.onPickPackage,
    required this.onSourceKindChanged,
    required this.layerSettings,
    required this.onLayerSettingsChanged,
    required this.onPickImageArchive,
    required this.onPickImageOciDir,
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
    required this.cliSections,
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
              Text(
                'trivy',
                style: TextStyle(
                  fontSize: 11,
                  color: Theme.of(
                    context,
                  ).colorScheme.onSurface.withValues(alpha: 0.5),
                ),
              ),
              const SizedBox(width: 8),
              ToolVersionBadge(info: versionInfo),
            ],
          ),
          const SizedBox(height: 10),
          // ── Source : fichier SBOM ou image de conteneur ──
          ScanSourceToggle(
            kind: sourceKind,
            enabled: !isRunning,
            onChanged: onSourceKindChanged,
          ),
          const SizedBox(height: 8),
          if (sourceKind == ScanSourceKind.sbomFile)
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: fileCtrl,
                    decoration: InputDecoration(
                      labelText: context.l10n.scanSourceSbom,
                      hintText: context.l10n.commonSbomFileHint,
                      border: const OutlineInputBorder(),
                      isDense: true,
                    ),
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 13,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                SplitPickButton(
                  filterLabel: '.json .jsonld',
                  onPickFiltered: onPickSbom,
                  onPickAll: onPickSbomAll,
                ),
              ],
            )
          else if (sourceKind == ScanSourceKind.package)
            PackageSourceField(
              controller: packageCtrl,
              enabled: !isRunning,
              depth: packageDepth,
              onDepthChanged: onPackageDepthChanged,
              onPick: onPickPackage,
            )
          else ...[
            ImageRefField(
              controller: imageCtrl,
              enabled: !isRunning,
              onPickArchive: onPickImageArchive,
              onPickOciDir: onPickImageOciDir,
            ),
            const SizedBox(height: 8),
            SizedBox(
              width: 220,
              child: TextField(
                controller: imagePlatformCtrl,
                enabled: !isRunning,
                decoration: InputDecoration(
                  label: HelpLabel(
                    context.l10n.commonPlatform,
                    context.l10n.scanPlatformHelp('trivy'),
                  ),
                  hintText: context.l10n.commonPlatformHint,
                  border: const OutlineInputBorder(),
                  isDense: true,
                ),
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
            const SizedBox(height: 6),
            LayerScanOptions(
              settings: layerSettings,
              enabled: !isRunning,
              onChanged: onLayerSettingsChanged,
            ),
          ],
          const SizedBox(height: 10),

          // --severity checkboxes
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                context.l10n.trivySeverityLabel,
                style: const TextStyle(fontSize: 11, color: Colors.grey),
              ),
              const SizedBox(width: 4),
              HelpIcon(context.l10n.trivySeverityHelp),
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
                  backgroundColor: (_sevColors[s] ?? Colors.grey).withValues(
                    alpha: 0.1,
                  ),
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
                    children: [
                      const Text(
                        '--ignore-unfixed',
                        style: TextStyle(fontSize: 12),
                      ),
                      const SizedBox(width: 4),
                      HelpIcon(context.l10n.trivyIgnoreUnfixedHelp),
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
                    children: [
                      const Text(
                        '--skip-db-update',
                        style: TextStyle(fontSize: 12),
                      ),
                      const SizedBox(width: 4),
                      HelpIcon(context.l10n.trivySkipDbHelp),
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
                  decoration: InputDecoration(
                    label: HelpLabel(
                      context.l10n.trivyConfigLabel,
                      context.l10n.trivyConfigHelp,
                    ),
                    hintText: context.l10n.trivyConfigHint,
                    border: const OutlineInputBorder(),
                    isDense: true,
                  ),
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
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

          Row(
            children: [
              Expanded(
                child: isRunning
                    ? OutlinedButton.icon(
                        style: OutlinedButton.styleFrom(
                          minimumSize: const Size.fromHeight(42),
                          side: const BorderSide(color: Colors.red),
                          foregroundColor: Colors.red,
                        ),
                        onPressed: onStop,
                        icon: const Icon(Icons.stop),
                        label: Text(context.l10n.commonStopAction),
                      )
                    : FilledButton.icon(
                        style: FilledButton.styleFrom(
                          minimumSize: const Size.fromHeight(42),
                        ),
                        onPressed: onRun,
                        icon: const Icon(Icons.search),
                        label: Text(context.l10n.scanRunButton('trivy')),
                      ),
              ),
              const SizedBox(width: 8),
              CliCommandButton(sections: cliSections, height: 42),
            ],
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
              context.l10n.scanNoVulnFound,
              style: TextStyle(
                color: Colors.green[800],
                fontWeight: FontWeight.w500,
              ),
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
      child: OnPale(
        child: Row(
          children: [
            const Icon(Icons.warning_amber, color: Colors.orange, size: 18),
            const SizedBox(width: 8),
            Text(
              context.l10n.scanBannerCount(vulns.length),
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
      ),
    );
  }
}

// ─── Hints ────────────────────────────────────────────────────────────────────

class _EmptyHint extends StatelessWidget {
  const _EmptyHint();

  @override
  Widget build(BuildContext context) => Center(
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Icon(Icons.shield_outlined, size: 56, color: Colors.grey),
        const SizedBox(height: 12),
        Text(
          context.l10n.scanHintPick,
          style: const TextStyle(color: Colors.grey, fontSize: 15),
        ),
        const SizedBox(height: 4),
        const Text(
          'trivy — Aqua Security vulnerability scanner',
          style: TextStyle(color: Colors.grey, fontSize: 12),
        ),
      ],
    ),
  );
}

class _RunningHint extends StatelessWidget {
  const _RunningHint();

  @override
  Widget build(BuildContext context) => Center(
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        const CircularProgressIndicator(),
        const SizedBox(height: 16),
        Text(
          context.l10n.scanRunningTool('trivy'),
          style: const TextStyle(color: Colors.grey, fontSize: 15),
        ),
      ],
    ),
  );
}
