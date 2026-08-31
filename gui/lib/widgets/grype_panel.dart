import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'help_icon.dart';
import 'package:flutter/services.dart';

import '../models/cve_date_filter.dart';
import '../models/sbom_result.dart';
import '../services/grype_runner.dart';
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
  final CveDateFilter dateFilter;
  final void Function(CveDateFilter)? onDateFilterChanged;
  final void Function(CveDateFilter)? onPropagate;

  const GrypePanel({
    super.key,
    required this.outputFiles,
    this.onVulnsChanged,
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
  final _imagePlatformCtrl = TextEditingController();
  final _configCtrl = TextEditingController();
  final _templateCtrl =
      TextEditingController(text: './grype_csv.tmpl');
  late final TabController _resultTabs;

  // Source à analyser : fichier SBOM (par défaut) ou image de conteneur
  ScanSourceKind _sourceKind = ScanSourceKind.sbomFile;

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
      dialogTitle: 'Choisir un fichier SBOM',
    );
    if (result?.files.single.path != null) {
      setState(() => _fileCtrl.text = result!.files.single.path!);
    }
  }

  Future<void> _pickImageArchive() async {
    final result = await FilePicker.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['tar', 'gz', 'tgz'],
      dialogTitle: 'Choisir une archive image (docker save / OCI)',
    );
    if (result?.files.single.path != null) {
      setState(() => _imageCtrl.text = result!.files.single.path!);
    }
  }

  Future<void> _pickImageOciDir() async {
    final dir = await FilePicker.getDirectoryPath(
      dialogTitle: 'Choisir un répertoire OCI layout',
    );
    if (dir != null) setState(() => _imageCtrl.text = dir);
  }

  Future<void> _pickConfigFile({bool filtered = true}) async {
    final result = await FilePicker.pickFiles(
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? ['yaml', 'yml'] : null,
      dialogTitle: 'Choisir grype.yaml',
    );
    if (result?.files.single.path != null) {
      setState(() => _configCtrl.text = result!.files.single.path!);
    }
  }

  Future<void> _pickTemplateFile({bool filtered = true}) async {
    final result = await FilePicker.pickFiles(
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? ['tmpl', 'tpl', 'txt'] : null,
      dialogTitle: 'Choisir un fichier template Grype',
    );
    if (result?.files.single.path != null) {
      setState(() => _templateCtrl.text = result!.files.single.path!);
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
    // on ne vérifie l'existence que pour un fichier SBOM ou une archive/
    // répertoire OCI local explicitement désigné comme tel (préfixe ./, /, ~).
    if ((!useImage || looksLikeLocalPath(target)) && !File(target).existsSync()
        && !Directory(target).existsSync()) {
      setState(() => _error = 'Fichier introuvable : $target');
      return;
    }

    setState(() {
      _isRunning = true;
      _vulns = [];
      _jsonOutput = '';
      _templateOutput = '';
      _error = null;
      _parseFailed = false;
      _exitCode = null;
    });

    final tmpl = _templateCtrl.text.trim();

    _runner
        .run(
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
          distroVersion:
              _distroVersion.isEmpty ? null : _distroVersion,
          templateFile: tmpl.isEmpty ? null : tmpl,
        )
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
              });
              widget.onVulnsChanged?.call(_vulns);
            } catch (e) {
              setState(() {
                _jsonOutput = jsonOutput;
                _vulns = [];
                _parseFailed = true;
                _error = 'Sortie grype illisible (JSON invalide) : $e';
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

  void _stop() {
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
          onSourceKindChanged: (k) => setState(() => _sourceKind = k),
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
          versionInfo: _versionInfo,
        ),
        const Divider(height: 1),
        if (_isRunning) const LinearProgressIndicator(minHeight: 3),
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
                VulnTableView<GrypeVuln>(
                  vulns: _vulns,
                  parseFailed: _parseFailed,
                  parseFailedMessage:
                      'Sortie grype illisible : voir le message d\'erreur ci-dessus',
                  severityOrder: const [
                    'Critical', 'High', 'Medium', 'Low', 'Negligible'
                  ],
                  toolName: 'Grype',
                  csvDialogTitle: 'Exporter les vulnérabilités Grype',
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
                  extraColumnHeader: 'TYPE',
                  extraOf: (v) => v.packageType,
                  dateFilter: widget.dateFilter,
                  onDateFilterChanged: widget.onDateFilterChanged,
                  onPropagate: widget.onPropagate,
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
  final ValueChanged<ScanSourceKind> onSourceKindChanged;
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
  final ToolVersionInfo? versionInfo;

  const _ConfigSection({
    required this.fileCtrl,
    required this.imageCtrl,
    required this.imagePlatformCtrl,
    required this.sourceKind,
    required this.onSourceKindChanged,
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
              onPickArchive: onPickImageArchive,
              onPickOciDir: onPickImageOciDir,
            ),
            const SizedBox(height: 8),
            SizedBox(
              width: 220,
              child: TextField(
                controller: imagePlatformCtrl,
                enabled: !isRunning,
                decoration: const InputDecoration(
                  label: HelpLabel(
                    'Plateforme',
                    'Optionnel. Force la plateforme cible sur une\n'
                        'image multi-architecture, ex. linux/arm64.\n'
                        'Laisser vide = détection automatique par\n'
                        'grype (la case --platform linux ci-dessous ne\n'
                        's\'applique pas en mode image).',
                  ),
                  hintText: 'linux/amd64, linux/arm64…',
                  border: OutlineInputBorder(),
                  isDense: true,
                ),
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
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
                helpText:
                    'Fixe la plateforme cible à linux/amd64.\n'
                    'À activer si Grype ne détecte pas\n'
                    'automatiquement la plateforme de l\'image.',
              ),
              _CheckOption(
                label: '--add-cpes-if-none',
                value: addCpesIfNone,
                enabled: !isRunning,
                onChanged: onAddCpesIfNoneChanged,
                helpText:
                    'Génère des CPE (Common Platform Enumeration)\n'
                    'pour les paquets qui n\'en ont pas.\n'
                    'Améliore le taux de correspondance CVE.',
              ),
              _CheckOption(
                label: '--by-cve',
                value: byCve,
                enabled: !isRunning,
                onChanged: onByCveChanged,
                helpText:
                    'Groupe les résultats par CVE plutôt que par\n'
                    'paquet. Évite les doublons quand plusieurs\n'
                    'paquets sont touchés par la même CVE.',
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
                helpText:
                    'Distribution cible pour l\'évaluation des CVE.\n'
                    'Si vide, Grype tente de la détecter\n'
                    'automatiquement depuis le SBOM.',
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
                helpText:
                    'Sévérité minimum pour que Grype retourne\n'
                    'un code d\'erreur 1 (utile en CI/CD).\n'
                    'Si vide, Grype retourne toujours 0.',
              ),
              const SizedBox(width: 8),

              // Only-fixed
              _CheckOption(
                label: '--only-fixed',
                value: onlyFixed,
                enabled: !isRunning,
                onChanged: onOnlyFixedChanged,
                helpText:
                    'N\'affiche que les vulnérabilités pour lesquelles\n'
                    'une version corrigée est disponible.',
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
                    label: HelpLabel(
                      'Template (-t)',
                      'Modèle Go pour formater la sortie de Grype.\n'
                          'Ex : ./grype_csv.tmpl pour un export CSV.\n'
                          'Voir la doc Grype pour la syntaxe des templates.',
                    ),
                    hintText: './grype_csv.tmpl',
                    border: OutlineInputBorder(),
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
                  decoration: const InputDecoration(
                    label: HelpLabel(
                      'grype.yaml (optionnel)',
                      'Fichier de configuration Grype (YAML).\n'
                          'Permet de définir des exceptions, des sources\n'
                          'de données, ou de personnaliser le comportement.',
                    ),
                    hintText: '/chemin/vers/grype.yaml',
                    border: OutlineInputBorder(),
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
              'Choisissez un fichier SBOM ou une image de conteneur,\n'
              'puis lancez l\'analyse Grype',
              textAlign: TextAlign.center,
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

