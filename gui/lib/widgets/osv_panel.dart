import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../models/cve_date_filter.dart';
import '../models/sbom_result.dart';
import '../models/layer_scan.dart';
import '../services/layer_scan_service.dart';
import '../services/osv_runner.dart';
import '../services/scan_enrichment.dart';
import '../services/settings_service.dart';
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
  @override
  final int occurrenceCount;

  const OsvVuln({
    required this.id,
    required this.severity,
    required this.packageName,
    required this.installedVersion,
    required this.fixedVersion,
    required this.ecosystem,
    this.publishedDate,
    this.modifiedDate,
    this.occurrenceCount = 1,
  });

  /// Reconstruit cette entrée avec un nombre d'occurrences fusionnées — voir
  /// [dedupeVulns].
  OsvVuln withOccurrenceCount(int count) => OsvVuln(
        id: id,
        severity: severity,
        packageName: packageName,
        installedVersion: installedVersion,
        fixedVersion: fixedVersion,
        ecosystem: ecosystem,
        publishedDate: publishedDate,
        modifiedDate: modifiedDate,
        occurrenceCount: count,
      );

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
  final void Function(Map<String, ExploitInfo>)? onExploitChanged;

  /// Cible réellement analysée — pour l'en-tête des rapports exportés.
  final void Function(String target)? onScanTargetChanged;

  /// Analyse par couche du dernier scan (`null` : scan sans couches).
  final void Function(LayerScanResult?)? onLayerScanChanged;
  final CveDateFilter dateFilter;
  final void Function(CveDateFilter)? onDateFilterChanged;
  final void Function(CveDateFilter)? onPropagate;

  const OsvPanel({
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
  State<OsvPanel> createState() => _OsvPanelState();
}

class _OsvPanelState extends State<OsvPanel>
    with SingleTickerProviderStateMixin, AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;
  final _runner = OsvRunner();
  final _fileCtrl = TextEditingController();
  final _imageCtrl = TextEditingController();
  final _configCtrl = TextEditingController();
  late final TabController _resultTabs;

  // Source à analyser : fichier SBOM (par défaut) ou image de conteneur
  ScanSourceKind _sourceKind = ScanSourceKind.sbomFile;

  // Analyse par couche (source image)
  LayerScanSettings _layerSettings = const LayerScanSettings();
  LayerScanResult? _layerScan;
  String? _status;
  bool _layeredCancelled = false;

  bool _isRunning = false;
  List<OsvVuln> _vulns = [];
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
    SettingsService.loadScanEnrichOnline()
        .then((v) { if (mounted) setState(() => _enrichOnline = v); });
    VersionService.checkOsv()
        .then((info) { if (mounted) setState(() => _versionInfo = info); });
  }

  /// Enrichit les CVE trouvées avec les signaux d'exploitabilité. OSV n'expose
  /// ni KEV ni EPSS : le réseau est requis (CISA KEV + FIRST EPSS + PoC).
  Future<void> _enrich(String rawJson, List<OsvVuln> vulns) async {
    final ids = {for (final v in vulns) normalizeCveId(v.id)}..remove('');
    if (ids.isEmpty) return;
    final run = ++_enrichRun;
    setState(() => _enrichPending = _enrichOnline);
    try {
      final result = await enrichCves(
        ids,
        seed: seedsFromOsvJson(rawJson),
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
  void didUpdateWidget(OsvPanel old) {
    super.didUpdateWidget(old);
    if (widget.outputFiles != old.outputFiles) _updateAutoFile();
  }

  @override
  void dispose() {
    _runner.kill();
    _fileCtrl.dispose();
    _imageCtrl.dispose();
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

  Future<void> _pickImageArchive() async {
    final r = await FilePicker.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['tar', 'gz', 'tgz'],
      dialogTitle: 'Choisir une archive image (docker save / OCI)',
    );
    if (r?.files.single.path != null) {
      setState(() => _imageCtrl.text = r!.files.single.path!);
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
    final useImage = _sourceKind == ScanSourceKind.image;
    final target = (useImage ? _imageCtrl.text : _fileCtrl.text).trim();
    if (target.isEmpty) {
      setState(() => _error = useImage
          ? 'Veuillez indiquer une image à analyser.'
          : 'Veuillez sélectionner un fichier SBOM.');
      return;
    }
    // Une référence de registre (nginx:latest) n'est pas un chemin local :
    // on ne vérifie l'existence que pour un fichier SBOM ou une archive
    // locale explicitement désignée comme telle (préfixe ./, /, ~).
    if ((!useImage || looksLikeLocalPath(target)) &&
        !File(target).existsSync()) {
      setState(() => _error = 'Fichier introuvable : $target');
      return;
    }

    final targetLabel = useImage
        ? 'image « $target »'
        : 'SBOM ${target.split(RegExp(r'[/\\]')).last}';
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
          case OsvOutputEvent(:final jsonOutput):
            try {
              final raw = OsvVuln.fromJson(jsonOutput);
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

  Stream<OsvEvent> _start(String target, bool useImage) => _runner.run(
        target: target,
        useImage: useImage,
        configFile:
            _configCtrl.text.trim().isEmpty ? null : _configCtrl.text.trim(),
      );

  Future<ScanOutput> _scanOnce(String target, bool useImage) async {
    var json = '';
    var code = 1;
    String? err;
    await for (final e in _start(target, useImage)) {
      switch (e) {
        case OsvOutputEvent(:final jsonOutput):
          json = jsonOutput;
        case OsvDoneEvent(:final exitCode, :final stderr):
          code = exitCode;
          err = stderr;
      }
    }
    return (json: json, exitCode: code, stderr: err);
  }

  /// Analyse par couche de l'image [image] (voir [LayerScanService.run]) ;
  /// en rattachement, la couche indiquée par osv-scanner lui-même
  /// (`image_origin_details`) est prioritaire.
  Future<void> _analyzeLayered(String image) async {
    _layeredCancelled = false;
    try {
      final r = await LayerScanService.run(
        image: image,
        settings: _layerSettings,
        scanOnce: _scanOnce,
        parse: OsvVuln.fromJson,
        merge: mergeOsvJson,
        nativeDigests: osvLayerDigests,
        onStatus: (st) {
          if (mounted) setState(() => _status = st);
        },
        isCancelled: () => _layeredCancelled,
      );
      if (!mounted) return;
      var vulns = <OsvVuln>[];
      var parseFailed = false;
      var error = r.stderr;
      if (r.json.isNotEmpty) {
        try {
          vulns = dedupeVulns(
              OsvVuln.fromJson(r.json), (v, n) => v.withOccurrenceCount(n));
          error = null;
        } catch (e) {
          parseFailed = true;
          error = 'Sortie osv-scanner illisible (JSON invalide) : $e';
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
          sourceKind: _sourceKind,
          onSourceKindChanged: (k) => setState(() => _sourceKind = k),
          layerSettings: _layerSettings,
          onLayerSettingsChanged: (v) => setState(() => _layerSettings = v),
          onPickImageArchive: _pickImageArchive,
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
        if (_isRunning && _status != null) ...[
          const LinearProgressIndicator(minHeight: 3),
          ScanStatusLine(_status!),
        ],
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
                  toolName: 'OSV-Scanner',
                  csvDialogTitle: 'Exporter les vulnérabilités OSV-Scanner',
                  csvFileName: 'osv_vulns.csv',
                  csvHeader:
                      'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Écosystème,Emplacements',
                  csvRow: (v) => [
                    v.severity,
                    v.id,
                    v.packageName,
                    v.installedVersion,
                    v.fixedVersion,
                    v.ecosystem,
                    '${v.occurrenceCount}',
                  ],
                  extraColumnHeader: 'ÉCOSYSTÈME',
                  extraOf: (v) => v.ecosystem,
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
  final ScanSourceKind sourceKind;
  final ValueChanged<ScanSourceKind> onSourceKindChanged;
  final LayerScanSettings layerSettings;
  final ValueChanged<LayerScanSettings> onLayerSettingsChanged;
  final VoidCallback onPickImageArchive;
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
    required this.imageCtrl,
    required this.sourceKind,
    required this.onSourceKindChanged,
    required this.layerSettings,
    required this.onLayerSettingsChanged,
    required this.onPickImageArchive,
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
            )
          else ...[
            ImageRefField(
              controller: imageCtrl,
              enabled: !isRunning,
              allowOciDir: false,
              onPickArchive: onPickImageArchive,
            ),
            const SizedBox(height: 6),
            LayerScanOptions(
              settings: layerSettings,
              enabled: !isRunning,
              onChanged: onLayerSettingsChanged,
            ),
          ],
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
            Text('Sélectionnez un SBOM ou une image et lancez l\'analyse',
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
