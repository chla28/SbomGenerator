import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'help_icon.dart';
import 'package:flutter/services.dart';

import '../l10n/l10n.dart';
import '../models/cve_date_filter.dart';
import '../models/layer_scan.dart';
import '../models/sbom_result.dart';
import '../services/grype_runner.dart';
import '../services/layer_scan_service.dart';
import '../services/package_scan_service.dart';
import '../services/scan_enrichment.dart';
import '../services/settings_service.dart';
import '../services/version_service.dart';
import 'vuln_shared.dart';

// ─── Modèle de vulnérabilité ──────────────────────────────────────────────────

class GrypeVuln implements VulnRow {
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
  final String packageType;
  @override
  final DateTime? publishedDate;
  @override
  final DateTime? modifiedDate;
  @override
  final int occurrenceCount;

  const GrypeVuln({
    required this.id,
    required this.severity,
    required this.packageName,
    required this.installedVersion,
    required this.fixedVersion,
    required this.packageType,
    this.publishedDate,
    this.modifiedDate,
    this.occurrenceCount = 1,
  });

  /// Reconstruit cette entrée avec un nombre d'occurrences fusionnées — voir
  /// [dedupeVulns].
  GrypeVuln withOccurrenceCount(int count) => GrypeVuln(
        id: id,
        severity: severity,
        packageName: packageName,
        installedVersion: installedVersion,
        fixedVersion: fixedVersion,
        packageType: packageType,
        publishedDate: publishedDate,
        modifiedDate: modifiedDate,
        occurrenceCount: count,
      );

  static int _order(String s) => switch (s.toLowerCase()) {
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        'low' => 3,
        'negligible' => 4,
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

  /// Lève une [FormatException] si `raw` n'est pas un JSON grype valide,
  /// plutôt que de retourner silencieusement une liste vide : un JSON
  /// tronqué/corrompu ne doit pas être confondu avec "aucune vulnérabilité".
  static List<GrypeVuln> fromJson(String raw) {
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
        publishedDate: _parseDate(vuln['publishedDate'] as String?),
        modifiedDate: _parseDate(vuln['lastModifiedDate'] as String?),
      );
    }).toList();
    vulns.sort((a, b) => _order(a.severity).compareTo(_order(b.severity)));
    return vulns;
  }
}

// ─── Widget principal ─────────────────────────────────────────────────────────

class GrypePanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  final void Function(List<GrypeVuln>)? onVulnsChanged;
  final void Function(Map<String, ExploitInfo>)? onExploitChanged;

  /// Cible réellement analysée (« SBOM x.cdx.json » ou « image nginx:latest »),
  /// rapportée au lancement du scan — pour l'en-tête des rapports exportés.
  final void Function(String target)? onScanTargetChanged;

  /// Analyse par couche du dernier scan (`null` : scan sans couches).
  final void Function(LayerScanResult?)? onLayerScanChanged;
  final CveDateFilter dateFilter;
  final void Function(CveDateFilter)? onDateFilterChanged;
  final void Function(CveDateFilter)? onPropagate;

  const GrypePanel({
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
  State<GrypePanel> createState() => _GrypePanelState();
}

class _GrypePanelState extends State<GrypePanel>
    with SingleTickerProviderStateMixin, AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;
  final _runner = GrypeRunner();
  final _fileCtrl = TextEditingController();
  final _imageCtrl = TextEditingController();
  final _packageCtrl = TextEditingController();
  String _packageDepth = '0';
  final _imagePlatformCtrl = TextEditingController();
  final _configCtrl = TextEditingController();
  final _templateCtrl =
      TextEditingController(text: './grype_csv.tmpl');
  late final TabController _resultTabs;

  // Source à analyser : fichier SBOM (par défaut) ou image de conteneur
  ScanSourceKind _sourceKind = ScanSourceKind.sbomFile;

  // Analyse par couche (source image)
  LayerScanSettings _layerSettings = const LayerScanSettings();
  LayerScanResult? _layerScan;
  String? _status;
  bool _layeredCancelled = false;

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
  bool _parseFailed = false;
  int? _exitCode;

  // Enrichissement exploitabilité (CISA KEV / EPSS / PoC)
  Map<String, ExploitInfo> _exploitById = const {};
  bool _enrichPending = false;
  bool _enrichOnline = true;
  int _enrichRun = 0;
  String? _scannedTarget;

  // Version outil
  ToolVersionInfo? _versionInfo;

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
    SettingsService.loadScanEnrichOnline()
        .then((v) { if (mounted) setState(() => _enrichOnline = v); });
    VersionService.checkGrype()
        .then((info) { if (mounted) setState(() => _versionInfo = info); });
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
    _imageCtrl.dispose();
    _packageCtrl.dispose();
    _imagePlatformCtrl.dispose();
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

  Future<void> _pickSbomFile({bool filtered = true}) async {
    final result = await FilePicker.pickFiles(
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? ['json', 'jsonld'] : null,
      dialogTitle: context.l10n.scanPickSbomTitle,
    );
    if (result?.files.single.path != null) {
      setState(() => _fileCtrl.text = result!.files.single.path!);
    }
  }

  Future<void> _pickImageArchive() async {
    final result = await FilePicker.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['tar', 'gz', 'tgz'],
      dialogTitle: context.l10n.scanPickImageArchiveTitle,
    );
    if (result?.files.single.path != null) {
      setState(() => _imageCtrl.text = result!.files.single.path!);
    }
  }

  Future<void> _pickImageOciDir() async {
    final dir = await FilePicker.getDirectoryPath(
      dialogTitle: context.l10n.scanSourcePickOciDir,
    );
    if (dir != null) setState(() => _imageCtrl.text = dir);
  }

  Future<void> _pickConfigFile({bool filtered = true}) async {
    final result = await FilePicker.pickFiles(
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? ['yaml', 'yml'] : null,
      dialogTitle: context.l10n.grypePickConfigTitle,
    );
    if (result?.files.single.path != null) {
      setState(() => _configCtrl.text = result!.files.single.path!);
    }
  }

  Future<void> _pickTemplateFile({bool filtered = true}) async {
    final result = await FilePicker.pickFiles(
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? ['tmpl', 'tpl', 'txt'] : null,
      dialogTitle: context.l10n.grypePickTemplateTitle,
    );
    if (result?.files.single.path != null) {
      setState(() => _templateCtrl.text = result!.files.single.path!);
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
      setState(() => _error = useImage
          ? context.l10n.scanSourceMissingImage
          : context.l10n.scanSourceMissingSbom);
      return;
    }
    // Une référence de registre (nginx:latest) n'est pas un chemin local :
    // on ne vérifie l'existence que pour un fichier SBOM ou une archive/
    // répertoire OCI local explicitement désigné comme tel (préfixe ./, /, ~).
    if ((!useImage || looksLikeLocalPath(target)) && !File(target).existsSync()
        && !Directory(target).existsSync()) {
      setState(() => _error = context.l10n.commonFileNotFound(target));
      return;
    }

    final targetLabel = useImage
        ? 'image « $target »'
        : 'SBOM ${target.split(RegExp(r'[/\\]')).last}';
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
      _templateOutput = '';
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

    final tmpl = _templateCtrl.text.trim();

    _start(target, useImage, templateFile: tmpl.isEmpty ? null : tmpl)
        .listen(
      (event) {
        if (!mounted) return;
        switch (event) {
          case GrypeOutputEvent(:final jsonOutput):
            try {
              final raw = GrypeVuln.fromJson(jsonOutput);
              // Fusionne les doublons visuels : une même bibliothèque peut
              // être détectée à plusieurs emplacements (ex. jar autonome +
              // copie shadée dans un autre jar) avec la même sévérité/CVE/
              // paquet/version — voir dedupeVulns dans vuln_shared.dart.
              final vulns = dedupeVulns(raw, (v, n) => v.withOccurrenceCount(n));
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
                _error = context.l10n.scanUnreadableOutput('grype', '$e');
              });
            }
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

  Stream<GrypeEvent> _start(String target, bool useImage,
          {String? templateFile}) =>
      _runner.run(
        target: target,
        failOn: _failOn.isEmpty ? null : _failOn,
        onlyFixed: _onlyFixed,
        configFile:
            _configCtrl.text.trim().isEmpty ? null : _configCtrl.text.trim(),
        // La case --platform linux (ci-dessous) vise le mode fichier SBOM,
        // où grype l'ignore (source non-image) : ne pas l'appliquer en
        // mode image, où 'linux' seul (sans arch) est rejeté par grype
        // pour une image multi-plateforme — seul le champ dédié ci-dessous
        // doit fixer la plateforme dans ce mode.
        platformLinux: useImage ? false : _platformLinux,
        platform: useImage && _imagePlatformCtrl.text.trim().isNotEmpty
            ? _imagePlatformCtrl.text.trim()
            : null,
        addCpesIfNone: _addCpesIfNone,
        byCve: _byCve,
        distroVersion: _distroVersion.isEmpty ? null : _distroVersion,
        templateFile: templateFile,
      );

  /// Commandes du popup « CLI Commande » pour le paramétrage courant.
  List<CliCommandSection> _cliSections() {
    if (_sourceKind != ScanSourceKind.package) return _scanCliSections();
    final raw = _packageCtrl.text.trim();
    final pkg = raw.isNotEmpty ? raw : '<paquet>';
    final l10n = context.l10n;
    return [
      CliCommandSection(
        l10n.cliCommandPackagePrepare,
        shellCommand(SettingsService.cliBinary,
            PackageScanService.prepareArgs(pkg, _packageDepth, cliPackageSbom)),
        note: l10n.cliCommandPackageNote,
      ),
      ..._scanCliSections(sbomTarget: cliPackageSbom, packageTarget: pkg),
    ];
  }

  List<CliCommandSection> _scanCliSections(
      {String? sbomTarget, String? packageTarget}) {
    final useImage = _sourceKind == ScanSourceKind.image;
    final raw = sbomTarget ??
        (useImage ? _imageCtrl.text : _fileCtrl.text).trim();
    final target =
        raw.isNotEmpty ? raw : (useImage ? '<image>' : '<sbom.cdx.json>');
    final tmpl = _templateCtrl.text.trim();
    final layered = useImage && _layerSettings.enabled;
    List<String> args(String t, bool image, {bool withTemplate = false}) =>
        GrypeRunner.buildArgs(
          target: t,
          failOn: _failOn.isEmpty ? null : _failOn,
          onlyFixed: _onlyFixed,
          configFile:
              _configCtrl.text.trim().isEmpty ? null : _configCtrl.text.trim(),
          platformLinux: image ? false : _platformLinux,
          platform: image && _imagePlatformCtrl.text.trim().isNotEmpty
              ? _imagePlatformCtrl.text.trim()
              : null,
          addCpesIfNone: _addCpesIfNone,
          byCve: _byCve,
          distroVersion: _distroVersion.isEmpty ? null : _distroVersion,
          templateFile: withTemplate && tmpl.isNotEmpty ? tmpl : null,
          templateOutput: 'grype_template.txt',
        );

    final l10n = context.l10n;
    final native = layered
        ? CliCommandSection(
            l10n.cliCommandExecutedLayered,
            layeredCliSequence(
              cliBinary: SettingsService.cliBinary,
              prepareArgs: LayerScanService.prepareArgs(target,
                  _layerSettings.layerMode, '$cliLayerDir/image.cdx.json'),
              layers: _layerSettings,
              imageScan: shellCommand('grype', args(target, true)),
              layerScan: (f) => shellCommand('grype', args('LAYER_SBOM', false))
                  .replaceAll('LAYER_SBOM', f),
            ),
            note: [
              l10n.cliCommandLayerDirNote(cliLayerDir),
              if (tmpl.isNotEmpty) l10n.grypeCliTemplateNotLayered,
            ].join(' '),
          )
        : CliCommandSection(
            l10n.cliCommandExecuted,
            shellCommand('grype', args(target, useImage, withTemplate: true)),
            note: tmpl.isNotEmpty
                ? l10n.grypeCliTemplateOutputNote('grype_template.txt')
                : null,
          );

    final notCarried = [
      if (tmpl.isNotEmpty) 'template (-t)',
      if (_failOn.isNotEmpty) '--fail-on',
      if (_onlyFixed) '--only-fixed',
      if (_distroVersion.isNotEmpty) '--distro',
      if (_configCtrl.text.trim().isNotEmpty) 'grype.yaml',
      if (useImage && _imagePlatformCtrl.text.trim().isNotEmpty)
        l10n.cliOptionPlatform,
      if (!_addCpesIfNone || !_byCve) l10n.grypeCliCpesByCveUnchecked,
    ];
    return [
      native,
      CliCommandSection(
        l10n.cliCommandEquivalent,
        shellCommand(
          SettingsService.cliBinary,
          sbomGeneratorScanArgs(
            scanner: 'grype',
            target: packageTarget ?? target,
            useImage: useImage,
            usePackage: packageTarget != null,
            packageDepth: _packageDepth,
            layers: _layerSettings,
            dateFilter: widget.dateFilter,
            enrichOnline: _enrichOnline,
          ),
        ),
        note: equivalentScanNote(l10n, useImage, notCarried),
      ),
    ];
  }

  Future<ScanOutput> _scanOnce(String target, bool useImage) async {
    var json = '';
    var code = 1;
    String? err;
    await for (final e in _start(target, useImage)) {
      switch (e) {
        case GrypeOutputEvent(:final jsonOutput):
          json = jsonOutput;
        case GrypeDoneEvent(:final exitCode, :final stderr):
          code = exitCode;
          err = stderr;
        case GrypeTemplateEvent():
          break;
      }
    }
    return (json: json, exitCode: code, stderr: err);
  }

  /// Analyse par couche de l'image [image] (voir [LayerScanService.run]).
  Future<void> _analyzeLayered(String image) async {
    _layeredCancelled = false;
    try {
      final r = await LayerScanService.run(
        image: image,
        settings: _layerSettings,
        scanOnce: _scanOnce,
        parse: GrypeVuln.fromJson,
        merge: mergeGrypeJson,
        onStatus: (step) {
          if (mounted) {
            setState(() => _status = layerScanStepLabel(context.l10n, step));
          }
        },
        isCancelled: () => _layeredCancelled,
      );
      if (!mounted) return;
      var vulns = <GrypeVuln>[];
      var parseFailed = false;
      var error = r.stderr;
      if (r.json.isNotEmpty) {
        try {
          vulns = dedupeVulns(
              GrypeVuln.fromJson(r.json), (v, n) => v.withOccurrenceCount(n));
        } catch (e) {
          parseFailed = true;
          error = context.l10n.scanUnreadableOutput('grype', '$e');
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

  /// Enrichit les CVE trouvées avec les signaux d'exploitabilité (best-effort,
  /// asynchrone). Grype fournit déjà KEV/EPSS/CVSS dans son JSON — le réseau ne
  /// sert qu'au signal PoC quand l'enrichissement en ligne est activé.
  Future<void> _enrich(String rawJson, List<GrypeVuln> vulns) async {
    final ids = {for (final v in vulns) normalizeCveId(v.id)}..remove('');
    if (ids.isEmpty) return;
    final run = ++_enrichRun;
    setState(() => _enrichPending = _enrichOnline);
    try {
      final result = await enrichCves(
        ids,
        seed: seedsFromGrypeJson(rawJson),
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
    final showResults =
        _vulns.isNotEmpty || _jsonOutput.isNotEmpty || _templateOutput.isNotEmpty;

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
          onPickSbomAll: () => _pickSbomFile(filtered: false),
          onPickConfig: _pickConfigFile,
          onPickConfigAll: () => _pickConfigFile(filtered: false),
          onPickTemplate: _pickTemplateFile,
          onPickTemplateAll: () => _pickTemplateFile(filtered: false),
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
          cliSections: _cliSections,
          versionInfo: _versionInfo,
        ),
        const Divider(height: 1),
        if (_isRunning) const LinearProgressIndicator(minHeight: 3),
        if (_isRunning && _status != null) ScanStatusLine(_status!),
        if (!_isRunning && _exitCode != null)
          _GrypeBanner(
              exitCode: _exitCode!, vulns: _vulns, error: _error),
        if (!_isRunning && _error != null && _vulns.isEmpty)
          ErrorBanner(message: _error!),
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
                      Text(context.l10n.grypeTabTable(_vulns.length)),
                    ],
                  ),
                ),
                Tab(
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.data_object, size: 16),
                      const SizedBox(width: 6),
                      Text(context.l10n.grypeTabJson),
                    ],
                  ),
                ),
                Tab(
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.article_outlined, size: 16),
                      const SizedBox(width: 6),
                      Text(context.l10n.grypeTabTemplate),
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
                VulnTableView<GrypeVuln>(
                  vulns: _vulns,
                  parseFailed: _parseFailed,
                  parseFailedMessage:
                      context.l10n.scanUnreadableOutputShort('grype'),
                  severityOrder: const [
                    'Critical', 'High', 'Medium', 'Low', 'Negligible'
                  ],
                  toolName: 'Grype',
                  csvDialogTitle: context.l10n.scanExportCsvDialog('Grype'),
                  csvFileName: 'grype_vulns.csv',
                  csvHeader:
                      'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Type,Emplacements',
                  csvRow: (v) => [
                    v.severity,
                    v.id,
                    v.packageName,
                    v.installedVersion,
                    v.fixedVersion,
                    v.packageType,
                    '${v.occurrenceCount}',
                  ],
                  extraColumnHeader: context.l10n.grypeColType,
                  extraOf: (v) => v.packageType,
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
  final VoidCallback onPickSbomAll;
  final VoidCallback onPickConfig;
  final VoidCallback onPickConfigAll;
  final VoidCallback onPickTemplate;
  final VoidCallback onPickTemplateAll;
  final ValueChanged<bool?> onPlatformLinuxChanged;
  final ValueChanged<bool?> onAddCpesIfNoneChanged;
  final ValueChanged<bool?> onByCveChanged;
  final ValueChanged<String> onDistroVersionChanged;
  final ValueChanged<String> onFailOnChanged;
  final ValueChanged<bool?> onOnlyFixedChanged;
  final VoidCallback onRun;
  final VoidCallback onStop;
  final List<CliCommandSection> Function() cliSections;
  final ToolVersionInfo? versionInfo;

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
    required this.onPickSbomAll,
    required this.onPickConfig,
    required this.onPickConfigAll,
    required this.onPickTemplate,
    required this.onPickTemplateAll,
    required this.onPlatformLinuxChanged,
    required this.onAddCpesIfNoneChanged,
    required this.onByCveChanged,
    required this.onDistroVersionChanged,
    required this.onFailOnChanged,
    required this.onOnlyFixedChanged,
    required this.onRun,
    required this.onStop,
    required this.cliSections,
    this.versionInfo,
  });

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Version ──
          Row(
            children: [
              Text('grype',
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
                      labelText: l10n.scanSourceSbom,
                      hintText: l10n.commonSbomFileHint,
                      border: const OutlineInputBorder(),
                      isDense: true,
                    ),
                    style: const TextStyle(
                        fontFamily: 'monospace', fontSize: 13),
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
                  label: HelpLabel(l10n.commonPlatform, l10n.grypePlatformHelp),
                  hintText: l10n.commonPlatformHint,
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
                helpText: l10n.grypePlatformLinuxHelp,
              ),
              _CheckOption(
                label: '--add-cpes-if-none',
                value: addCpesIfNone,
                enabled: !isRunning,
                onChanged: onAddCpesIfNoneChanged,
                helpText: l10n.grypeAddCpesHelp,
              ),
              _CheckOption(
                label: '--by-cve',
                value: byCve,
                enabled: !isRunning,
                onChanged: onByCveChanged,
                helpText: l10n.grypeByCveHelp,
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
                            v.isEmpty ? l10n.commonNoneFeminine : 'rhel:$v',
                            style: const TextStyle(fontSize: 13),
                          ),
                        ))
                    .toList(),
                enabled: !isRunning,
                onChanged: (v) => onDistroVersionChanged(v ?? ''),
                helpText: l10n.grypeDistroHelp,
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
                            s.isEmpty ? l10n.commonNone : s,
                            style: const TextStyle(fontSize: 13),
                          ),
                        ))
                    .toList(),
                enabled: !isRunning,
                onChanged: (v) => onFailOnChanged(v ?? ''),
                helpText: l10n.grypeFailOnHelp,
              ),
              const SizedBox(width: 8),

              // Only-fixed
              _CheckOption(
                label: '--only-fixed',
                value: onlyFixed,
                enabled: !isRunning,
                onChanged: onOnlyFixedChanged,
                helpText: l10n.grypeOnlyFixedHelp,
              ),

              const Spacer(),

              CliCommandButton(sections: cliSections),
              const SizedBox(width: 8),

              // Bouton Analyser / Stop
              isRunning
                  ? OutlinedButton.icon(
                      onPressed: onStop,
                      icon: const Icon(Icons.stop, size: 18),
                      label: Text(l10n.commonStop),
                      style: OutlinedButton.styleFrom(
                          foregroundColor: Colors.red),
                    )
                  : FilledButton.icon(
                      onPressed: onRun,
                      icon: const Icon(Icons.security, size: 18),
                      label: Text(l10n.commonAnalyze),
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
                  decoration: InputDecoration(
                    label: HelpLabel(l10n.grypeTemplateLabel, l10n.grypeTemplateHelp),
                    hintText: './grype_csv.tmpl',
                    border: const OutlineInputBorder(),
                    isDense: true,
                  ),
                  style: const TextStyle(
                      fontFamily: 'monospace', fontSize: 12),
                ),
              ),
              const SizedBox(width: 8),
              SplitPickButton(
                filterLabel: '.tmpl .tpl .txt',
                onPickFiltered: onPickTemplate,
                onPickAll: onPickTemplateAll,
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
                  decoration: InputDecoration(
                    label: HelpLabel(l10n.grypeConfigLabel, l10n.grypeConfigHelp),
                    hintText: l10n.grypeConfigHint,
                    border: const OutlineInputBorder(),
                    isDense: true,
                  ),
                  style: const TextStyle(
                      fontFamily: 'monospace', fontSize: 12),
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
  final String? helpText;

  const _CheckOption({
    required this.label,
    required this.value,
    required this.enabled,
    required this.onChanged,
    this.helpText,
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
        if (helpText != null) ...[
          const SizedBox(width: 4),
          HelpIcon(helpText!),
        ],
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
  final String? helpText;

  const _LabeledDropdown({
    required this.label,
    required this.value,
    required this.items,
    required this.enabled,
    required this.onChanged,
    this.helpText,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(label,
                style: const TextStyle(
                    fontSize: 11, fontWeight: FontWeight.w500)),
            if (helpText != null) ...[
              const SizedBox(width: 4),
              HelpIcon(helpText!),
            ],
          ],
        ),
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
        ? context.l10n.scanNoVulnerabilities
        : context.l10n.scanSummary(vulns.length, parts.join(', '));

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
                  ? context.l10n.grypeTemplateEmptyRun
                  : context.l10n.grypeTemplateEmptyConfigure,
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
            message: context.l10n.grypeTemplateCopyTooltip,
            child: IconButton(
              icon: const Icon(Icons.copy_outlined,
                  size: 18, color: Colors.white70),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: content));
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(context.l10n.grypeTemplateCopied),
                    duration: const Duration(seconds: 2),
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
  Widget build(BuildContext context) => Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.security_outlined, size: 56, color: Colors.grey),
            const SizedBox(height: 12),
            Text(
              context.l10n.grypeEmptyHint,
              textAlign: TextAlign.center,
              style: const TextStyle(color: Colors.grey, fontSize: 15),
            ),
          ],
        ),
      );
}

class _GrypeRunningHint extends StatelessWidget {
  const _GrypeRunningHint();

  @override
  Widget build(BuildContext context) => Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 16),
            Text(
              context.l10n.grypeRunning,
              style: const TextStyle(color: Colors.grey, fontSize: 15),
            ),
          ],
        ),
      );
}

