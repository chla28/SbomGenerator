import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/sbom_config.dart';
import '../services/settings_service.dart';
import 'help_icon.dart';
import '../l10n/l10n.dart';

class ConfigPanel extends StatefulWidget {
  final SbomConfig config;
  final bool isRunning;
  final VoidCallback onRun;
  final VoidCallback onStop;
  final VoidCallback? onChanged;

  const ConfigPanel({
    super.key,
    required this.config,
    required this.isRunning,
    required this.onRun,
    required this.onStop,
    this.onChanged,
  });

  @override
  State<ConfigPanel> createState() => ConfigPanelState();
}

class ConfigPanelState extends State<ConfigPanel> {
  final _formKey = GlobalKey<FormState>();
  late TextEditingController _inputCtrl;
  late TextEditingController _outputCtrl;
  late TextEditingController _nameCtrl;
  late TextEditingController _sdkCtrl;
  late TextEditingController _rpmDirCtrl;
  late TextEditingController _licenseMapCtrl;
  late TextEditingController _pdfCtrl;
  late TextEditingController _imageCtrl;
  late TextEditingController _binaryCtrl;

  bool _isDragging = false;

  @override
  void initState() {
    super.initState();
    final c = widget.config;
    _inputCtrl = TextEditingController(text: c.inputFile);
    _outputCtrl = TextEditingController(text: c.outputBase);
    _nameCtrl = TextEditingController(text: c.documentName);
    _sdkCtrl = TextEditingController(text: c.sdkVersions);
    _rpmDirCtrl = TextEditingController(text: c.rpmDir);
    _licenseMapCtrl = TextEditingController(text: c.licenseMapFile);
    _pdfCtrl = TextEditingController(text: c.pdfOutputPath);
    _imageCtrl = TextEditingController(text: c.imageRef);
    _binaryCtrl = TextEditingController(text: c.binaryPath);
  }

  @override
  void dispose() {
    for (final c in [
      _inputCtrl,
      _outputCtrl,
      _nameCtrl,
      _sdkCtrl,
      _rpmDirCtrl,
      _licenseMapCtrl,
      _pdfCtrl,
      _imageCtrl,
      _binaryCtrl,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  void _loadProfileInto(SbomConfig loaded) {
    final c = widget.config;
    c.outputBase = loaded.outputBase;
    c.formats = loaded.formats;
    c.documentName = loaded.documentName;
    c.rpmDir = loaded.rpmDir;
    c.licenseMapFile = loaded.licenseMapFile;
    c.sdkVersions = loaded.sdkVersions;
    c.concurrency = loaded.concurrency;
    c.verbose = loaded.verbose;
    c.generatePdf = loaded.generatePdf;
    c.pdfOutputPath = loaded.pdfOutputPath;
    c.enableSbomqs = loaded.enableSbomqs;
    c.imageRef = loaded.imageRef;
    c.ociTool = loaded.ociTool;
    c.binaryPath = loaded.binaryPath;
    c.perLayer = loaded.perLayer;
    c.layerMode = loaded.layerMode;
    c.nestedDepth = loaded.nestedDepth;
    c.nestedFiles = loaded.nestedFiles;
    _outputCtrl.text = c.outputBase;
    _nameCtrl.text = c.documentName;
    _rpmDirCtrl.text = c.rpmDir;
    _licenseMapCtrl.text = c.licenseMapFile;
    _sdkCtrl.text = c.sdkVersions;
    _pdfCtrl.text = c.pdfOutputPath;
    _imageCtrl.text = c.imageRef;
    _binaryCtrl.text = c.binaryPath;
    widget.onChanged?.call();
    setState(() {});
  }

  void _showProfilesDialog(BuildContext context) {
    _sync();
    showDialog<void>(
      context: context,
      builder: (_) => _ProfilesDialog(
        currentConfig: widget.config,
        onLoad: _loadProfileInto,
      ),
    );
  }

  void _sync() {
    final c = widget.config;
    c.inputFile = _inputCtrl.text.trim();
    c.outputBase = _outputCtrl.text.trim();
    c.documentName = _nameCtrl.text.trim();
    c.rpmDir = _rpmDirCtrl.text.trim();
    c.licenseMapFile = _licenseMapCtrl.text.trim();
    c.sdkVersions = _sdkCtrl.text.trim();
    c.pdfOutputPath = _pdfCtrl.text.trim();
    c.imageRef = _imageCtrl.text.trim();
    c.binaryPath = _binaryCtrl.text.trim();
    widget.onChanged?.call();
  }

  void _run() {
    if (!_formKey.currentState!.validate()) return;
    _sync();
    widget.onRun();
  }

  /// Lance la génération (même validation que le bouton) ; sans effet si une
  /// exécution est déjà en cours.
  void triggerRun() {
    if (!widget.isRunning) _run();
  }

  Future<void> _pickFile(
    TextEditingController ctrl, {
    String? title,
    List<String>? extensions,
    List<TextEditingController>? clears,
  }) async {
    final r = await FilePicker.pickFiles(
      dialogTitle: title,
      type: extensions != null ? FileType.custom : FileType.any,
      allowedExtensions: extensions,
    );
    if (r != null && r.files.single.path != null) {
      ctrl.text = r.files.single.path!;
      for (final other in clears ?? const <TextEditingController>[]) {
        other.clear();
      }
      _sync();
      setState(() {});
    }
  }

  Future<void> _pickDir(
    TextEditingController ctrl, {
    String? title,
    VoidCallback? onDone,
    List<TextEditingController>? clears,
  }) async {
    final r = await FilePicker.getDirectoryPath(dialogTitle: title);
    if (r != null) {
      ctrl.text = r;
      for (final other in clears ?? const <TextEditingController>[]) {
        other.clear();
      }
      onDone?.call();
    }
  }

  Future<void> _saveFile(
    TextEditingController ctrl, {
    String? title,
    String? fileName,
  }) async {
    final r = await FilePicker.saveFile(dialogTitle: title, fileName: fileName);
    if (r != null) {
      ctrl.text = r;
      _sync();
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l = context.l10n;
    final c = widget.config;

    return Container(
      width: 390,
      color: theme.colorScheme.surfaceContainerLow,
      child: Form(
        key: _formKey,
        child: Column(
          children: [
            // Header
            Container(
              padding: const EdgeInsets.only(
                left: 16,
                right: 8,
                top: 10,
                bottom: 10,
              ),
              color: theme.colorScheme.primary,
              width: double.infinity,
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      l.cfgTitle,
                      style: TextStyle(
                        color: theme.colorScheme.onPrimary,
                        fontWeight: FontWeight.bold,
                        fontSize: 14,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: Icon(
                      Icons.bookmarks_outlined,
                      color: theme.colorScheme.onPrimary,
                      size: 18,
                    ),
                    tooltip: l.cfgProfilesTooltip,
                    onPressed: () => _showProfilesDialog(context),
                    padding: const EdgeInsets.all(4),
                    constraints: const BoxConstraints(),
                  ),
                ],
              ),
            ),

            Expanded(
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  // ── Entrée ──────────────────────────────────────
                  _Section(
                    title: l.cfgSectionInput,
                    icon: Icons.input,
                    children: [
                      // Drag & drop wrapping le champ fichier d'entrée
                      DropTarget(
                        onDragEntered: (_) =>
                            setState(() => _isDragging = true),
                        onDragExited: (_) =>
                            setState(() => _isDragging = false),
                        onDragDone: (detail) {
                          if (detail.files.isNotEmpty) {
                            _inputCtrl.text = detail.files.first.path;
                            _imageCtrl.clear();
                            _binaryCtrl.clear();
                            _sync();
                          }
                          setState(() => _isDragging = false);
                        },
                        child: AnimatedContainer(
                          duration: const Duration(milliseconds: 150),
                          decoration: _isDragging
                              ? BoxDecoration(
                                  border: Border.all(
                                    color: theme.colorScheme.primary,
                                    width: 2,
                                  ),
                                  borderRadius: BorderRadius.circular(8),
                                )
                              : const BoxDecoration(),
                          child: _FileField(
                            label: l.cfgInputLabel,
                            controller: _inputCtrl,
                            hint: _isDragging
                                ? l.cfgInputHintDrop
                                : l.cfgInputHint,
                            helpText: l.cfgInputHelp,
                            onPickFiltered: () => _pickFile(
                              _inputCtrl,
                              title: l.cfgPickInputFile,
                              extensions: ['lst', 'txt'],
                              clears: [_imageCtrl, _binaryCtrl],
                            ),
                            filterLabel: '.lst .txt',
                            onPick: () => _pickFile(
                              _inputCtrl,
                              title: l.cfgPickInputFile,
                              clears: [_imageCtrl, _binaryCtrl],
                            ),
                            onPickDir: () => _pickDir(
                              _inputCtrl,
                              title: l.cfgPickPackagesDir,
                              onDone: () {
                                _imageCtrl.clear();
                                _sync();
                                setState(() {});
                              },
                              clears: [_imageCtrl, _binaryCtrl],
                            ),
                            onChanged: (v) {
                              if (v.trim().isNotEmpty) {
                                _imageCtrl.clear();
                                _binaryCtrl.clear();
                              }
                              _sync();
                              setState(() {});
                            },
                            // Requis seulement si aucune image OCI / binaire fourni
                            validator: (v) =>
                                (v == null || v.trim().isEmpty) &&
                                    _imageCtrl.text.trim().isEmpty &&
                                    _binaryCtrl.text.trim().isEmpty
                                ? l.cfgInputRequired
                                : null,
                          ),
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        l.cfgDragHint,
                        style: TextStyle(
                          fontSize: 10,
                          color: theme.colorScheme.onSurface.withValues(
                            alpha: 0.45,
                          ),
                          fontStyle: FontStyle.italic,
                        ),
                      ),
                      const SizedBox(height: 8),
                      _NestedDepthOptions(
                        config: widget.config,
                        onChanged: () {
                          _sync();
                          setState(() {});
                        },
                      ),

                      // ── Séparateur OU ──
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 12),
                        child: Row(
                          children: [
                            Expanded(
                              child: Divider(
                                color: theme.colorScheme.outlineVariant,
                              ),
                            ),
                            Padding(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 10,
                              ),
                              child: Text(
                                l.cfgOr,
                                style: TextStyle(
                                  fontSize: 11,
                                  fontWeight: FontWeight.bold,
                                  color: theme.colorScheme.onSurface.withValues(
                                    alpha: 0.4,
                                  ),
                                  letterSpacing: 1.5,
                                ),
                              ),
                            ),
                            Expanded(
                              child: Divider(
                                color: theme.colorScheme.outlineVariant,
                              ),
                            ),
                          ],
                        ),
                      ),

                      // ── Image OCI ──
                      _OciImageField(
                        controller: _imageCtrl,
                        onPickTar: () => _pickFile(
                          _imageCtrl,
                          title: l.cfgPickOciArchive,
                          extensions: ['tar', 'gz', 'tgz'],
                          clears: [_inputCtrl, _binaryCtrl],
                        ),
                        onPickDir: () => _pickDir(
                          _imageCtrl,
                          title: l.cfgPickOciDir,
                          onDone: _sync,
                          clears: [_inputCtrl, _binaryCtrl],
                        ),
                        onChanged: (v) {
                          if (v.trim().isNotEmpty) {
                            _inputCtrl.clear();
                            _binaryCtrl.clear();
                          }
                          _sync();
                          setState(() {});
                        },
                      ),

                      // ── Outil OCI ──
                      if (c.imageRef.isNotEmpty) ...[
                        const SizedBox(height: 10),
                        _OciToolSelector(
                          selected: c.ociTool,
                          onChanged: (tool) => setState(() {
                            c.ociTool = tool;
                            widget.onChanged?.call();
                          }),
                        ),
                        const SizedBox(height: 10),
                        _PerLayerOptions(
                          config: c,
                          onChanged: () => setState(() {
                            widget.onChanged?.call();
                          }),
                        ),
                      ],

                      // ── Séparateur OU ──
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 12),
                        child: Row(
                          children: [
                            Expanded(
                              child: Divider(
                                color: theme.colorScheme.outlineVariant,
                              ),
                            ),
                            Padding(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 10,
                              ),
                              child: Text(
                                l.cfgOr,
                                style: TextStyle(
                                  fontSize: 11,
                                  fontWeight: FontWeight.bold,
                                  color: theme.colorScheme.onSurface.withValues(
                                    alpha: 0.4,
                                  ),
                                  letterSpacing: 1.5,
                                ),
                              ),
                            ),
                            Expanded(
                              child: Divider(
                                color: theme.colorScheme.outlineVariant,
                              ),
                            ),
                          ],
                        ),
                      ),

                      // ── Binaire autonome ──
                      _BinaryField(
                        controller: _binaryCtrl,
                        onPick: () => _pickFile(
                          _binaryCtrl,
                          title: l.cfgPickBinary,
                          clears: [_inputCtrl, _imageCtrl],
                        ),
                        onChanged: (v) {
                          if (v.trim().isNotEmpty) {
                            _inputCtrl.clear();
                            _imageCtrl.clear();
                          }
                          _sync();
                          setState(() {});
                        },
                      ),
                      if (c.binaryPath.isNotEmpty) ...[
                        const SizedBox(height: 6),
                        Text(
                          l.cfgBinarySyftForced,
                          style: TextStyle(
                            fontSize: 10,
                            color: theme.colorScheme.onSurface.withValues(
                              alpha: 0.5,
                            ),
                            fontStyle: FontStyle.italic,
                          ),
                        ),
                      ],

                      const SizedBox(height: 8),
                      _InputTypeLegend(),
                    ],
                  ),
                  const SizedBox(height: 14),

                  // ── Sortie ──────────────────────────────────────
                  _Section(
                    title: l.cfgSectionOutput,
                    icon: Icons.file_download_outlined,
                    children: [
                      _FileField(
                        label: l.cfgOutputBase,
                        controller: _outputCtrl,
                        hint: l.cfgOutputBaseHint,
                        helpText: l.cfgOutputBaseHelp,
                        onPick: () => _saveFile(
                          _outputCtrl,
                          title: l.cfgOutputBaseTitle,
                          fileName: 'sbom',
                        ),
                        onChanged: (_) => _sync(),
                      ),
                      const SizedBox(height: 12),

                      // Format checkboxes
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(
                            l.cfgFormats,
                            style: const TextStyle(
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          const SizedBox(width: 4),
                          HelpIcon(l.cfgFormatsHelp),
                        ],
                      ),
                      const SizedBox(height: 6),
                      for (final fmt in allFormats)
                        _FormatCheckbox(
                          format: fmt,
                          checked: c.formats.contains(fmt),
                          onChanged: (v) => setState(() {
                            if (v) {
                              c.formats.add(fmt);
                            } else if (c.formats.length > 1) {
                              c.formats.remove(fmt);
                              if (fmt == 'asciidoc') c.generatePdf = false;
                            }
                            widget.onChanged?.call();
                          }),
                        ),

                      // Version CycloneDX (visible uniquement si cyclonedx sélectionné)
                      if (c.formats.contains('cyclonedx')) ...[
                        const SizedBox(height: 6),
                        _CycloneDxVersionSelector(
                          selected: c.cycloneDxVersion,
                          onChanged: (v) => setState(() {
                            c.cycloneDxVersion = v;
                            widget.onChanged?.call();
                          }),
                        ),
                      ],

                      // Option PDF (visible uniquement si asciidoc sélectionné)
                      if (c.formats.contains('asciidoc')) ...[
                        const SizedBox(height: 6),
                        const Divider(height: 16),
                        CheckboxListTile.adaptive(
                          dense: true,
                          title: Text(
                            l.cfgPdf,
                            style: const TextStyle(fontSize: 13),
                          ),
                          subtitle: Text(
                            l.cfgPdfSub,
                            style: const TextStyle(fontSize: 11),
                          ),
                          secondary: const Icon(Icons.picture_as_pdf, size: 20),
                          value: c.generatePdf,
                          onChanged: (v) => setState(() {
                            c.generatePdf = v ?? false;
                            widget.onChanged?.call();
                          }),
                          controlAffinity: ListTileControlAffinity.leading,
                        ),
                        if (c.generatePdf) ...[
                          const SizedBox(height: 4),
                          _FileField(
                            label: l.cfgPdfPath,
                            controller: _pdfCtrl,
                            hint: l.cfgPdfPathHint,
                            onPick: () => _saveFile(
                              _pdfCtrl,
                              title: l.cfgPdfSaveTitle,
                              fileName: 'sbom.pdf',
                            ),
                            onChanged: (_) => _sync(),
                          ),
                        ],
                      ],

                      // Preview des fichiers attendus
                      if (c.outputBase.isNotEmpty) ...[
                        const SizedBox(height: 10),
                        _OutputPreview(config: c),
                      ],
                    ],
                  ),
                  const SizedBox(height: 14),

                  // ── Options ─────────────────────────────────────
                  _Section(
                    title: l.cfgSectionOptions,
                    icon: Icons.tune,
                    children: [
                      TextFormField(
                        controller: _nameCtrl,
                        decoration: InputDecoration(
                          label: HelpLabel(l.cfgName, l.cfgNameHelp),
                          hintText: l.cfgNameHint,
                          border: const OutlineInputBorder(),
                          isDense: true,
                          prefixIcon: const Icon(Icons.label_outline),
                        ),
                        onChanged: (_) => _sync(),
                      ),
                      const SizedBox(height: 12),

                      _FileField(
                        label: l.cfgRpmDir,
                        controller: _rpmDirCtrl,
                        hint: l.cfgRpmDirHint,
                        helpText: l.cfgRpmDirHelp,
                        onPick: () => _pickDir(
                          _rpmDirCtrl,
                          title: l.cfgRpmDirTitle,
                          onDone: _sync,
                        ),
                        onChanged: (_) => _sync(),
                      ),
                      const SizedBox(height: 12),

                      _FileField(
                        label: l.cfgLicenseMap,
                        controller: _licenseMapCtrl,
                        hint: l.cfgLicenseMapHint,
                        helpText: l.cfgLicenseMapHelp,
                        onPickFiltered: () => _pickFile(
                          _licenseMapCtrl,
                          title: l.cfgLicenseMapTitle,
                          extensions: ['txt', 'map'],
                        ),
                        filterLabel: '.txt .map',
                        onPick: () => _pickFile(
                          _licenseMapCtrl,
                          title: l.cfgLicenseMapTitle,
                        ),
                        onChanged: (_) => _sync(),
                      ),
                      const SizedBox(height: 12),

                      TextFormField(
                        key: const Key('sdk-versions'),
                        controller: _sdkCtrl,
                        decoration: InputDecoration(
                          label: HelpLabel(
                            l.cfgSdkVersions,
                            l.cfgSdkVersionsHelp,
                          ),
                          hintText: l.cfgSdkVersionsHint,
                          border: const OutlineInputBorder(),
                          isDense: true,
                          prefixIcon: const Icon(Icons.flutter_dash),
                        ),
                        onChanged: (_) => _sync(),
                      ),
                      const SizedBox(height: 14),

                      // Concurrence
                      Row(
                        children: [
                          const Icon(Icons.speed, size: 16),
                          const SizedBox(width: 6),
                          Text(
                            l.cfgConcurrency,
                            style: const TextStyle(fontSize: 12),
                          ),
                          const SizedBox(width: 4),
                          HelpIcon(l.cfgConcurrencyHelp),
                          const Spacer(),
                          Text(
                            c.concurrency == 0
                                ? l.cfgUnlimited
                                : '${c.concurrency}',
                            style: TextStyle(
                              fontSize: 13,
                              fontWeight: FontWeight.bold,
                              color: Theme.of(context).colorScheme.primary,
                            ),
                          ),
                        ],
                      ),
                      Slider(
                        value: c.concurrency.toDouble(),
                        min: 0,
                        max: 16,
                        divisions: 16,
                        label: c.concurrency == 0
                            ? l.cfgUnlimited
                            : '${c.concurrency}',
                        onChanged: (v) => setState(() {
                          c.concurrency = v.round();
                          widget.onChanged?.call();
                        }),
                      ),
                      Text(
                        c.concurrency == 0
                            ? l.cfgConcurrencyZero
                            : l.cfgConcurrencyNote,
                        style: TextStyle(
                          fontSize: 11,
                          color: theme.colorScheme.onSurface.withValues(
                            alpha: 0.5,
                          ),
                        ),
                      ),
                      const SizedBox(height: 8),

                      CheckboxListTile.adaptive(
                        dense: true,
                        title: Text(
                          l.cfgVerbose,
                          style: const TextStyle(fontSize: 13),
                        ),
                        subtitle: Text(
                          l.cfgVerboseSub,
                          style: const TextStyle(fontSize: 11),
                        ),
                        secondary: HelpIcon(l.cfgVerboseHelp),
                        value: c.verbose,
                        onChanged: (v) => setState(() {
                          c.verbose = v ?? false;
                          widget.onChanged?.call();
                        }),
                        controlAffinity: ListTileControlAffinity.leading,
                      ),
                      const Divider(height: 16),

                      CheckboxListTile.adaptive(
                        dense: true,
                        title: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              l.cfgSbomqs,
                              style: const TextStyle(fontSize: 13),
                            ),
                            const SizedBox(width: 4),
                            HelpIcon(l.cfgSbomqsHelp),
                          ],
                        ),
                        subtitle: Text(
                          l.cfgSbomqsSub,
                          style: const TextStyle(fontSize: 11),
                        ),
                        secondary: const Icon(
                          Icons.analytics_outlined,
                          size: 20,
                        ),
                        value: c.enableSbomqs,
                        onChanged: (v) => setState(() {
                          c.enableSbomqs = v ?? false;
                          widget.onChanged?.call();
                        }),
                        controlAffinity: ListTileControlAffinity.leading,
                      ),
                    ],
                  ),
                ],
              ),
            ),

            // Bouton Run / Stop
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
              child: widget.isRunning
                  ? OutlinedButton.icon(
                      style: OutlinedButton.styleFrom(
                        minimumSize: const Size.fromHeight(48),
                        side: const BorderSide(color: Colors.red),
                        foregroundColor: Colors.red,
                      ),
                      onPressed: widget.onStop,
                      icon: const Icon(Icons.stop),
                      label: Text(l.cfgStop),
                    )
                  : FilledButton.icon(
                      style: FilledButton.styleFrom(
                        minimumSize: const Size.fromHeight(48),
                      ),
                      onPressed: _run,
                      icon: const Icon(Icons.play_arrow),
                      label: Text(
                        l.cfgGenerate,
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
            ),
            _CommandPreview(
              commandLine: widget.config.toCommandLine(
                SettingsService.cliBinary,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ─── Prévisualisation de la commande ──────────────────────────────────────────

class _CommandPreview extends StatelessWidget {
  final String commandLine;

  const _CommandPreview({required this.commandLine});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: isDark ? const Color(0xFF1E1E1E) : const Color(0xFF2B2B2B),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: SelectableText(
                '\$ $commandLine',
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 11,
                  color: Color(0xFF80CBC4),
                  height: 1.5,
                ),
              ),
            ),
            const SizedBox(width: 4),
            Tooltip(
              message: context.l10n.cfgCopyCommand,
              child: InkWell(
                borderRadius: BorderRadius.circular(4),
                onTap: () =>
                    Clipboard.setData(ClipboardData(text: commandLine)),
                child: const Padding(
                  padding: EdgeInsets.all(4),
                  child: Icon(Icons.copy, size: 14, color: Color(0xFF80CBC4)),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ─── Sous-widgets ─────────────────────────────────────────────────────────────

class _Section extends StatelessWidget {
  final String title;
  final IconData icon;
  final List<Widget> children;

  const _Section({
    required this.title,
    required this.icon,
    required this.children,
  });

  @override
  Widget build(BuildContext context) {
    final color = Theme.of(context).colorScheme.primary;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(icon, size: 14, color: color),
            const SizedBox(width: 6),
            Text(
              title,
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.bold,
                color: color,
                letterSpacing: 0.5,
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        ...children,
      ],
    );
  }
}

enum _PickKind { filtered, anyFile, directory }

class _FileField extends StatelessWidget {
  final String label;
  final TextEditingController controller;
  final String? hint;
  final String? helpText;
  final VoidCallback onPick;
  final VoidCallback? onPickFiltered;
  final String? filterLabel;
  final VoidCallback? onPickDir;
  final ValueChanged<String>? onChanged;
  final FormFieldValidator<String>? validator;

  const _FileField({
    required this.label,
    required this.controller,
    required this.onPick,
    this.onPickFiltered,
    this.filterLabel,
    this.onPickDir,
    this.hint,
    this.helpText,
    this.onChanged,
    this.validator,
  });

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return TextFormField(
      controller: controller,
      decoration: InputDecoration(
        label: helpText != null
            ? Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(label),
                  const SizedBox(width: 4),
                  HelpIcon(helpText!),
                ],
              )
            : null,
        labelText: helpText == null ? label : null,
        hintText: hint,
        border: const OutlineInputBorder(),
        isDense: true,
        suffixIcon: (onPickFiltered != null || onPickDir != null)
            ? PopupMenuButton<_PickKind>(
                icon: const Icon(Icons.folder_open, size: 18),
                tooltip: l.cfgBrowse,
                onSelected: (kind) => switch (kind) {
                  _PickKind.filtered => onPickFiltered!(),
                  _PickKind.directory => onPickDir!(),
                  _PickKind.anyFile => onPick(),
                },
                itemBuilder: (_) => [
                  if (onPickFiltered != null)
                    PopupMenuItem(
                      value: _PickKind.filtered,
                      child: ListTile(
                        dense: true,
                        contentPadding: EdgeInsets.zero,
                        leading: const Icon(
                          Icons.filter_alt_outlined,
                          size: 16,
                        ),
                        title: Text(l.cfgPickFiltered(filterLabel ?? '')),
                      ),
                    ),
                  PopupMenuItem(
                    value: _PickKind.anyFile,
                    child: ListTile(
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.folder_open, size: 16),
                      title: Text(l.cfgPickAny),
                    ),
                  ),
                  if (onPickDir != null)
                    PopupMenuItem(
                      value: _PickKind.directory,
                      child: ListTile(
                        dense: true,
                        contentPadding: EdgeInsets.zero,
                        leading: const Icon(Icons.folder_outlined, size: 16),
                        title: Text(l.cfgPickDirRecursive),
                      ),
                    ),
                ],
              )
            : IconButton(
                icon: const Icon(Icons.folder_open, size: 18),
                onPressed: onPick,
                tooltip: l.cfgBrowse,
              ),
      ),
      style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
      onChanged: onChanged,
      validator: validator,
    );
  }
}

class _FormatCheckbox extends StatelessWidget {
  final String format;
  final bool checked;
  final ValueChanged<bool> onChanged;

  const _FormatCheckbox({
    required this.format,
    required this.checked,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    final ext = formatExtension(format);
    return CheckboxListTile.adaptive(
      dense: true,
      title: Text(
        formatLabel(format, context.l10n),
        style: const TextStyle(fontSize: 13),
      ),
      subtitle: Text(
        ext,
        style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
      ),
      value: checked,
      onChanged: (v) => onChanged(v ?? false),
      controlAffinity: ListTileControlAffinity.leading,
    );
  }
}

class _OutputPreview extends StatelessWidget {
  final SbomConfig config;
  const _OutputPreview({required this.config});

  @override
  Widget build(BuildContext context) {
    final paths = config.expectedOutputPaths();
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            context.l10n.cfgFilesToGenerate,
            style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 4),
          for (final p in paths)
            Row(
              children: [
                const Icon(Icons.insert_drive_file_outlined, size: 13),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(
                    p,
                    style: const TextStyle(
                      fontSize: 11,
                      fontFamily: 'monospace',
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
        ],
      ),
    );
  }
}

// ─── Dialog de gestion des profils ───────────────────────────────────────────

class _ProfilesDialog extends StatefulWidget {
  final SbomConfig currentConfig;
  final ValueChanged<SbomConfig> onLoad;

  const _ProfilesDialog({required this.currentConfig, required this.onLoad});

  @override
  State<_ProfilesDialog> createState() => _ProfilesDialogState();
}

class _ProfilesDialogState extends State<_ProfilesDialog> {
  List<String> _names = [];
  final _ctrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _refresh() async {
    final names = await SettingsService.listProfiles();
    if (mounted) setState(() => _names = names);
  }

  Future<void> _save() async {
    final name = _ctrl.text.trim();
    if (name.isEmpty) return;
    await SettingsService.saveProfile(name, widget.currentConfig);
    _ctrl.clear();
    await _refresh();
  }

  Future<void> _load(String name) async {
    final config = await SettingsService.loadProfile(name);
    if (config != null && mounted) {
      widget.onLoad(config);
      Navigator.of(context).pop();
    }
  }

  Future<void> _delete(String name) async {
    final l = context.l10n;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: Text(l.cfgProfDeleteTitle),
        content: Text(l.cfgProfDeleteConfirm(name)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(l.homeCancel),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(l.cfgDelete, style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await SettingsService.deleteProfile(name);
      await _refresh();
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l = context.l10n;
    return AlertDialog(
      title: Row(
        children: [
          const Icon(Icons.bookmarks_outlined, size: 20),
          const SizedBox(width: 8),
          Text(l.cfgProfTitle),
        ],
      ),
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Enregistrer ──
            Text(l.cfgProfSaveCurrent, style: theme.textTheme.labelMedium),
            const SizedBox(height: 6),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _ctrl,
                    decoration: InputDecoration(
                      hintText: l.cfgProfNameHint,
                      isDense: true,
                      border: const OutlineInputBorder(),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 8,
                      ),
                    ),
                    onSubmitted: (_) => _save(),
                    style: const TextStyle(fontSize: 13),
                  ),
                ),
                const SizedBox(width: 8),
                FilledButton.icon(
                  icon: const Icon(Icons.save_outlined, size: 16),
                  label: Text(l.cfgProfSave),
                  onPressed: _save,
                  style: FilledButton.styleFrom(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 10,
                    ),
                  ),
                ),
              ],
            ),

            const SizedBox(height: 16),
            const Divider(height: 1),
            const SizedBox(height: 12),

            // ── Liste des profils ──
            Text(l.cfgProfSaved, style: theme.textTheme.labelMedium),
            const SizedBox(height: 6),

            if (_names.isEmpty)
              Container(
                padding: const EdgeInsets.symmetric(vertical: 24),
                alignment: Alignment.center,
                child: Text(
                  l.cfgProfNone,
                  style: const TextStyle(color: Colors.grey),
                ),
              )
            else
              ConstrainedBox(
                constraints: const BoxConstraints(maxHeight: 280),
                child: ListView.builder(
                  shrinkWrap: true,
                  itemCount: _names.length,
                  itemBuilder: (_, i) {
                    final name = _names[i];
                    return ListTile(
                      dense: true,
                      leading: const Icon(Icons.bookmark_outline, size: 18),
                      title: Text(name, style: const TextStyle(fontSize: 13)),
                      trailing: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          TextButton(
                            onPressed: () => _load(name),
                            style: TextButton.styleFrom(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 8,
                                vertical: 4,
                              ),
                            ),
                            child: Text(
                              l.cfgProfLoad,
                              style: const TextStyle(fontSize: 12),
                            ),
                          ),
                          IconButton(
                            icon: const Icon(Icons.delete_outline, size: 17),
                            color: Colors.red[400],
                            tooltip: l.cfgDelete,
                            onPressed: () => _delete(name),
                            padding: EdgeInsets.zero,
                            constraints: const BoxConstraints(),
                          ),
                        ],
                      ),
                    );
                  },
                ),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(l.commonClose),
        ),
      ],
    );
  }
}

// ─── Champ image OCI ─────────────────────────────────────────────────────────

class _OciImageField extends StatelessWidget {
  final TextEditingController controller;
  final VoidCallback onPickTar;
  final VoidCallback onPickDir;
  final ValueChanged<String>? onChanged;

  const _OciImageField({
    required this.controller,
    required this.onPickTar,
    required this.onPickDir,
    this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return TextFormField(
      controller: controller,
      decoration: InputDecoration(
        label: HelpLabel(l.cfgOciLabel, l.cfgOciHelp),
        hintText: l.cfgOciHint,
        border: const OutlineInputBorder(),
        isDense: true,
        prefixIcon: const Icon(Icons.inventory_2_outlined, size: 18),
        suffixIcon: PopupMenuButton<String>(
          icon: const Icon(Icons.folder_open, size: 18),
          tooltip: l.cfgBrowse,
          onSelected: (v) {
            if (v == 'tar') {
              onPickTar();
            } else {
              onPickDir();
            }
          },
          itemBuilder: (_) => [
            PopupMenuItem(
              value: 'tar',
              child: ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.archive_outlined, size: 16),
                title: Text(l.cfgOciTar),
              ),
            ),
            PopupMenuItem(
              value: 'dir',
              child: ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.folder_outlined, size: 16),
                title: Text(l.cfgOciDir),
              ),
            ),
          ],
        ),
      ),
      style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
      onChanged: onChanged,
    );
  }
}

// ─── Binaire autonome (--binary) ───────────────────────────────────────────────

class _BinaryField extends StatelessWidget {
  final TextEditingController controller;
  final VoidCallback onPick;
  final ValueChanged<String>? onChanged;

  const _BinaryField({
    required this.controller,
    required this.onPick,
    this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return TextFormField(
      controller: controller,
      decoration: InputDecoration(
        label: HelpLabel(l.cfgBinaryLabel, l.cfgBinaryHelp),
        hintText: l.cfgBinaryHint,
        border: const OutlineInputBorder(),
        isDense: true,
        prefixIcon: const Icon(Icons.terminal_outlined, size: 18),
        suffixIcon: IconButton(
          icon: const Icon(Icons.folder_open, size: 18),
          tooltip: l.cfgBrowse,
          onPressed: onPick,
        ),
      ),
      style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
      onChanged: onChanged,
    );
  }
}

// ─── Sélecteur d'outil OCI ────────────────────────────────────────────────────

/// Option --depth (descente dans les objets imbriqués de l'entrée : jars d'un
/// RPM, paquets d'une archive…) et --no-nested-files, affichées sous le champ
/// d'entrée.
class _NestedDepthOptions extends StatelessWidget {
  final SbomConfig config;
  final VoidCallback onChanged;

  const _NestedDepthOptions({required this.config, required this.onChanged});

  static String _label(AppLocalizations l, String d) => switch (d) {
    '0' => l.cfgDepth0,
    'all' => l.cfgDepthAll,
    '1' => l.cfgDepth1,
    _ => l.cfgDepthN(d),
  };

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l = context.l10n;
    final style = TextStyle(fontSize: 12, color: theme.colorScheme.onSurface);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(
              Icons.account_tree_outlined,
              size: 14,
              color: theme.colorScheme.secondary,
            ),
            const SizedBox(width: 6),
            Text(l.cfgDepthLabel, style: style),
            const SizedBox(width: 4),
            HelpIcon(l.cfgDepthHelp),
            const SizedBox(width: 12),
            DropdownButton<String>(
              value: config.nestedDepth,
              isDense: true,
              items: [
                for (final d in allNestedDepths)
                  DropdownMenuItem(
                    value: d,
                    child: Text(_label(l, d), style: style),
                  ),
              ],
              onChanged: (v) {
                config.nestedDepth = v ?? '0';
                onChanged();
              },
            ),
          ],
        ),
        if (config.nestedDepth != '0')
          Row(
            children: [
              SizedBox(
                height: 24,
                width: 24,
                child: Checkbox(
                  value: config.nestedFiles,
                  onChanged: (v) {
                    config.nestedFiles = v ?? true;
                    onChanged();
                  },
                ),
              ),
              const SizedBox(width: 6),
              Flexible(child: Text(l.cfgNestedFiles, style: style)),
              const SizedBox(width: 4),
              HelpIcon(l.cfgNestedFilesHelp),
            ],
          ),
      ],
    );
  }
}

/// Option --per-layer (un SBOM par couche de l'image) et sa méthode de calcul
/// (--layer-mode), affichées sous le backend OCI.
class _PerLayerOptions extends StatelessWidget {
  final SbomConfig config;
  final VoidCallback onChanged;

  const _PerLayerOptions({required this.config, required this.onChanged});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l = context.l10n;
    final metadataOk = metadataLayerTools.contains(config.ociTool);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            SizedBox(
              height: 24,
              width: 24,
              child: Checkbox(
                value: config.perLayer,
                onChanged: (v) {
                  config.perLayer = v ?? false;
                  onChanged();
                },
              ),
            ),
            const SizedBox(width: 6),
            Flexible(
              child: Text(
                l.cfgPerLayer,
                style: TextStyle(
                  fontSize: 12,
                  color: theme.colorScheme.onSurface,
                ),
              ),
            ),
            const SizedBox(width: 4),
            HelpIcon(l.cfgPerLayerHelp),
          ],
        ),
        if (config.perLayer) ...[
          const SizedBox(height: 6),
          SegmentedButton<String>(
            style: SegmentedButton.styleFrom(
              textStyle: const TextStyle(fontSize: 11),
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              minimumSize: const Size(0, 30),
            ),
            segments: [
              ButtonSegment(
                value: 'metadata',
                label: Text(l.cfgLayerMetadata),
                icon: const Icon(Icons.bolt_outlined, size: 14),
                enabled: metadataOk,
                tooltip: l.cfgLayerMetadataTip,
              ),
              ButtonSegment(
                value: 'rootfs',
                label: Text(l.cfgLayerRootfs),
                icon: const Icon(Icons.layers_outlined, size: 14),
                tooltip: l.cfgLayerRootfsTip,
              ),
            ],
            selected: {config.effectiveLayerMode},
            onSelectionChanged: (s) {
              config.layerMode = s.first;
              onChanged();
            },
          ),
          if (!metadataOk)
            Padding(
              padding: const EdgeInsets.only(top: 4),
              child: Text(
                l.cfgRootfsForced(
                  ociToolLabels[config.ociTool] ?? config.ociTool,
                ),
                style: TextStyle(
                  fontSize: 10,
                  color: theme.colorScheme.onSurface.withValues(alpha: 0.5),
                  fontStyle: FontStyle.italic,
                ),
              ),
            ),
        ],
      ],
    );
  }
}

class _OciToolSelector extends StatelessWidget {
  final String selected;
  final ValueChanged<String> onChanged;

  const _OciToolSelector({required this.selected, required this.onChanged});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l = context.l10n;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(
              Icons.build_outlined,
              size: 14,
              color: theme.colorScheme.secondary,
            ),
            const SizedBox(width: 6),
            Text(
              l.cfgOciToolLabel,
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w600,
                color: theme.colorScheme.secondary,
              ),
            ),
            const SizedBox(width: 4),
            HelpIcon(l.cfgOciToolHelp),
          ],
        ),
        const SizedBox(height: 6),
        SegmentedButton<String>(
          style: SegmentedButton.styleFrom(
            textStyle: const TextStyle(fontSize: 11),
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            minimumSize: const Size(0, 32),
          ),
          segments: [
            ButtonSegment(
              value: 'syft',
              label: const Text('Syft'),
              icon: const Icon(Icons.search, size: 14),
              tooltip: l.cfgSyftTip,
            ),
            ButtonSegment(
              value: 'trivy',
              label: const Text('Trivy'),
              icon: const Icon(Icons.security, size: 14),
              tooltip: l.cfgTrivyTip,
            ),
            ButtonSegment(
              value: 'skopeo',
              label: const Text('Skopeo'),
              icon: const Icon(Icons.layers_outlined, size: 14),
              tooltip: l.cfgSkopeoTip,
            ),
            ButtonSegment(
              value: 'cdxgen',
              label: const Text('cdxgen'),
              icon: const Icon(Icons.inventory_2_outlined, size: 14),
              tooltip: l.cfgCdxgenTip,
            ),
          ],
          selected: {selected},
          onSelectionChanged: (s) => onChanged(s.first),
        ),
        const SizedBox(height: 4),
        Text(
          selected == 'syft'
              ? l.cfgSyftDesc
              : selected == 'trivy'
              ? l.cfgTrivyDesc
              : selected == 'skopeo'
              ? l.cfgSkopeoDesc
              : l.cfgCdxgenDesc,
          style: TextStyle(
            fontSize: 10,
            color: theme.colorScheme.onSurface.withValues(alpha: 0.5),
            fontStyle: FontStyle.italic,
          ),
        ),
      ],
    );
  }
}

class _CycloneDxVersionSelector extends StatelessWidget {
  final String selected;
  final ValueChanged<String> onChanged;

  const _CycloneDxVersionSelector({
    required this.selected,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l = context.l10n;
    return Padding(
      padding: const EdgeInsets.only(left: 32, bottom: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                l.cfgCdxVersion,
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.secondary,
                ),
              ),
              const SizedBox(width: 4),
              HelpIcon(l.cfgCdxVersionHelp),
            ],
          ),
          const SizedBox(height: 6),
          SegmentedButton<String>(
            style: SegmentedButton.styleFrom(
              textStyle: const TextStyle(fontSize: 11),
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              minimumSize: const Size(0, 28),
            ),
            segments: const [
              ButtonSegment(value: '1.6', label: Text('1.6')),
              ButtonSegment(value: '1.7', label: Text('1.7')),
            ],
            selected: {selected},
            onSelectionChanged: (s) => onChanged(s.first),
          ),
        ],
      ),
    );
  }
}

// ─── Légende des types d'entrée ───────────────────────────────────────────────

class _InputTypeLegend extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final l = context.l10n;
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            l.cfgLegendAccepted,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.bold,
              color: theme.colorScheme.onSurface.withValues(alpha: 0.7),
            ),
          ),
          const SizedBox(height: 4),
          for (final item in [
            (
              l.cfgLegRpmInstalled,
              'bash  ${l.cfgLegOr}  bash-5.1.8-6.el9.x86_64',
            ),
            (l.cfgLegRpmFile, '/path/to/package.rpm'),
            (l.cfgLegWheel, '/path/to/package.whl'),
            (l.cfgLegTar, '/path/to/pkg.tar.gz  ${l.cfgLegOr}  .tgz'),
            (l.cfgLegZip, '/path/to/archive.zip'),
            (l.cfgLegDeb, '/path/to/package.deb'),
            (l.cfgLegJar, '/path/to/lib.jar'),
            ('requirements', '/path/to/requirements.txt'),
            (
              l.cfgLegManifest,
              'go.sum, package-lock.json, pom.xml, pubspec.lock…',
            ),
          ])
            Padding(
              padding: const EdgeInsets.only(top: 2),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SizedBox(
                    width: 100,
                    child: Text(
                      item.$1,
                      style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.w600,
                        color: theme.colorScheme.primary,
                      ),
                    ),
                  ),
                  Expanded(
                    child: Text(
                      item.$2,
                      style: const TextStyle(
                        fontSize: 10,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 6),
          const Divider(height: 8),
          Text(
            l.cfgLegendImage,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.bold,
              color: theme.colorScheme.onSurface.withValues(alpha: 0.7),
            ),
          ),
          const SizedBox(height: 4),
          for (final item in [
            (l.cfgLegRegistry, 'nginx:latest  •  ubuntu@sha256:…'),
            (l.cfgLegTar, '/path/image.tar  (docker save)'),
            (l.cfgLegOciLayout, l.cfgLegOciLayoutVal),
          ])
            Padding(
              padding: const EdgeInsets.only(top: 2),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SizedBox(
                    width: 100,
                    child: Text(
                      item.$1,
                      style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.w600,
                        color: theme.colorScheme.secondary,
                      ),
                    ),
                  ),
                  Expanded(
                    child: Text(
                      item.$2,
                      style: const TextStyle(
                        fontSize: 10,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 6),
          const Divider(height: 8),
          Text(
            l.cfgLegendBinary,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.bold,
              color: theme.colorScheme.onSurface.withValues(alpha: 0.7),
            ),
          ),
          const SizedBox(height: 4),
          Text(
            l.cfgLegendBinaryText,
            style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
          ),
        ],
      ),
    );
  }
}
