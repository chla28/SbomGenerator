import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../models/sbom_config.dart';
import '../services/settings_service.dart';
import 'help_icon.dart';

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
  State<ConfigPanel> createState() => _ConfigPanelState();
}

class _ConfigPanelState extends State<ConfigPanel> {
  final _formKey = GlobalKey<FormState>();
  late TextEditingController _inputCtrl;
  late TextEditingController _outputCtrl;
  late TextEditingController _nameCtrl;
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
    _rpmDirCtrl = TextEditingController(text: c.rpmDir);
    _licenseMapCtrl = TextEditingController(text: c.licenseMapFile);
    _pdfCtrl = TextEditingController(text: c.pdfOutputPath);
    _imageCtrl = TextEditingController(text: c.imageRef);
    _binaryCtrl = TextEditingController(text: c.binaryPath);
  }

  @override
  void dispose() {
    for (final c in [
      _inputCtrl, _outputCtrl, _nameCtrl, _rpmDirCtrl,
      _licenseMapCtrl, _pdfCtrl, _imageCtrl, _binaryCtrl,
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
    _outputCtrl.text = c.outputBase;
    _nameCtrl.text = c.documentName;
    _rpmDirCtrl.text = c.rpmDir;
    _licenseMapCtrl.text = c.licenseMapFile;
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

  Future<void> _pickFile(TextEditingController ctrl,
      {String? title,
      List<String>? extensions,
      List<TextEditingController>? clears}) async {
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

  Future<void> _pickDir(TextEditingController ctrl,
      {String? title,
      VoidCallback? onDone,
      List<TextEditingController>? clears}) async {
    final r = await FilePicker.getDirectoryPath(dialogTitle: title);
    if (r != null) {
      ctrl.text = r;
      for (final other in clears ?? const <TextEditingController>[]) {
        other.clear();
      }
      onDone?.call();
    }
  }

  Future<void> _saveFile(TextEditingController ctrl,
      {String? title, String? fileName}) async {
    final r = await FilePicker.saveFile(
      dialogTitle: title,
      fileName: fileName,
    );
    if (r != null) {
      ctrl.text = r;
      _sync();
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
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
              padding: const EdgeInsets.only(left: 16, right: 8, top: 10, bottom: 10),
              color: theme.colorScheme.primary,
              width: double.infinity,
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      'Configuration',
                      style: TextStyle(
                        color: theme.colorScheme.onPrimary,
                        fontWeight: FontWeight.bold,
                        fontSize: 14,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: Icon(Icons.bookmarks_outlined,
                        color: theme.colorScheme.onPrimary, size: 18),
                    tooltip: 'Profils de configuration',
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
                    title: 'Entrée',
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
                                      width: 2),
                                  borderRadius: BorderRadius.circular(8),
                                )
                              : const BoxDecoration(),
                          child: _FileField(
                            label: 'Paquets à analyser (--input)',
                            controller: _inputCtrl,
                            hint: _isDragging
                                ? 'Déposez un fichier ou un dossier ici…'
                                : 'rpm.lst, un .jar, ou un dossier…',
                            helpText:
                                'Fichier liste (une référence par ligne),\n'
                                'une archive/un paquet unique (.rpm, .deb,\n'
                                '.whl, .jar, .zip, .tar.gz…), ou un dossier\n'
                                'scanné récursivement pour tous ces types.',
                            onPickFiltered: () => _pickFile(
                              _inputCtrl,
                              title: 'Sélectionner le fichier d\'entrée',
                              extensions: ['lst', 'txt'],
                              clears: [_imageCtrl, _binaryCtrl],
                            ),
                            filterLabel: '.lst .txt',
                            onPick: () => _pickFile(
                              _inputCtrl,
                              title: 'Sélectionner le fichier d\'entrée',
                              clears: [_imageCtrl, _binaryCtrl],
                            ),
                            onPickDir: () => _pickDir(
                              _inputCtrl,
                              title: 'Sélectionner un dossier de paquets',
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
                                    ? 'Requis (ou spécifiez une image OCI / un binaire)'
                                    : null,
                          ),
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Glissez-déposez un fichier ou un dossier depuis votre gestionnaire',
                        style: TextStyle(
                          fontSize: 10,
                          color: theme.colorScheme.onSurface
                              .withValues(alpha: 0.45),
                          fontStyle: FontStyle.italic,
                        ),
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
                              padding: const EdgeInsets.symmetric(horizontal: 10),
                              child: Text(
                                'OU',
                                style: TextStyle(
                                  fontSize: 11,
                                  fontWeight: FontWeight.bold,
                                  color: theme.colorScheme.onSurface
                                      .withValues(alpha: 0.4),
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
                          title: 'Sélectionner une archive OCI',
                          extensions: ['tar', 'gz', 'tgz'],
                          clears: [_inputCtrl, _binaryCtrl],
                        ),
                        onPickDir: () => _pickDir(
                          _imageCtrl,
                          title: 'Sélectionner un répertoire OCI layout',
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
                              padding: const EdgeInsets.symmetric(horizontal: 10),
                              child: Text(
                                'OU',
                                style: TextStyle(
                                  fontSize: 11,
                                  fontWeight: FontWeight.bold,
                                  color: theme.colorScheme.onSurface
                                      .withValues(alpha: 0.4),
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
                          title: 'Sélectionner un binaire',
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
                          'Backend : syft (forcé — seul capable d\'analyser un '
                          'binaire autonome)',
                          style: TextStyle(
                            fontSize: 10,
                            color: theme.colorScheme.onSurface
                                .withValues(alpha: 0.5),
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
                    title: 'Sortie',
                    icon: Icons.file_download_outlined,
                    children: [
                      _FileField(
                        label: 'Chemin de base (--output)',
                        controller: _outputCtrl,
                        hint: 'sbom  →  sbom.cdx.json, sbom.spdx.json…',
                        helpText:
                            'Préfixe du chemin de sortie. Le suffixe de\n'
                            'format est ajouté automatiquement.\n'
                            'Ex : sbom → sbom.cdx.json, sbom.spdx.json…',
                        onPick: () => _saveFile(
                          _outputCtrl,
                          title: 'Chemin de base du SBOM',
                          fileName: 'sbom',
                        ),
                        onChanged: (_) => _sync(),
                      ),
                      const SizedBox(height: 12),

                      // Format checkboxes
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Text(
                            'Formats (--format)',
                            style: TextStyle(
                                fontSize: 12, fontWeight: FontWeight.w600),
                          ),
                          const SizedBox(width: 4),
                          const HelpIcon(
                            'Sélectionnez un ou plusieurs formats de sortie.\n'
                            'CycloneDX (1.6 ou 1.7) et SPDX sont les standards industrie.\n'
                            'Markdown et AsciiDoc sont lisibles directement.',
                          ),
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
                          title: const Text(
                            'Convertir en PDF (asciidoctor-pdf)',
                            style: TextStyle(fontSize: 13),
                          ),
                          subtitle: const Text(
                            'Lance asciidoctor-pdf après la génération',
                            style: TextStyle(fontSize: 11),
                          ),
                          secondary:
                              const Icon(Icons.picture_as_pdf, size: 20),
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
                            label: 'Chemin du PDF (optionnel)',
                            controller: _pdfCtrl,
                            hint: 'Défaut : même dossier que .adoc',
                            onPick: () => _saveFile(
                              _pdfCtrl,
                              title: 'Enregistrer le PDF sous…',
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
                    title: 'Options',
                    icon: Icons.tune,
                    children: [
                      TextFormField(
                        controller: _nameCtrl,
                        decoration: const InputDecoration(
                          label: HelpLabel(
                            'Nom du document SBOM (--name)',
                            'Nom logique du document SBOM\n'
                                '(champ metadata.component.name).\n'
                                'Ex : "Mon Application 1.0"',
                          ),
                          hintText: 'Mon Application 1.0',
                          border: OutlineInputBorder(),
                          isDense: true,
                          prefixIcon: Icon(Icons.label_outline),
                        ),
                        onChanged: (_) => _sync(),
                      ),
                      const SizedBox(height: 12),

                      _FileField(
                        label: 'Répertoire RPM local (--rpm-dir)',
                        controller: _rpmDirCtrl,
                        hint: 'Dossier contenant des fichiers .rpm',
                        helpText:
                            'Dossier contenant des fichiers .rpm.\n'
                            'sbom_generator extrait les métadonnées\n'
                            'sans installer les paquets (rpm -qp).',
                        onPick: () => _pickDir(
                          _rpmDirCtrl,
                          title: 'Répertoire de fichiers RPM',
                          onDone: _sync,
                        ),
                        onChanged: (_) => _sync(),
                      ),
                      const SizedBox(height: 12),

                      _FileField(
                        label: 'Override licences (--license-map)',
                        controller: _licenseMapCtrl,
                        hint: 'Fichier "paquet: SPDX-expression"',
                        helpText:
                            'Fichier de substitution de licences,\n'
                            'format "paquet: SPDX-expression" par ligne.\n'
                            'Ex : mon-paquet-interne: MIT',
                        onPickFiltered: () => _pickFile(
                          _licenseMapCtrl,
                          title: 'Fichier de map licences',
                          extensions: ['txt', 'map'],
                        ),
                        filterLabel: '.txt .map',
                        onPick: () => _pickFile(
                          _licenseMapCtrl,
                          title: 'Fichier de map licences',
                        ),
                        onChanged: (_) => _sync(),
                      ),
                      const SizedBox(height: 14),

                      // Concurrence
                      Row(
                        children: [
                          const Icon(Icons.speed, size: 16),
                          const SizedBox(width: 6),
                          const Text('Concurrence (--concurrency)',
                              style: TextStyle(fontSize: 12)),
                          const SizedBox(width: 4),
                          const HelpIcon(
                            'Nombre de paquets analysés simultanément.\n'
                            '0 = illimité (tous en parallèle).\n'
                            'Réduire si les outils externes nécessitent\n'
                            'des accès exclusifs ou si la machine est lente.',
                          ),
                          const Spacer(),
                          Text(
                            c.concurrency == 0
                                ? 'illimitée'
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
                            ? 'illimitée'
                            : '${c.concurrency}',
                        onChanged: (v) => setState(() {
                          c.concurrency = v.round();
                          widget.onChanged?.call();
                        }),
                      ),
                      Text(
                        c.concurrency == 0
                            ? '0 = tous les paquets en parallèle'
                            : '1 = séquentiel  •  défaut : 4',
                        style: TextStyle(
                          fontSize: 11,
                          color: theme.colorScheme.onSurface
                              .withValues(alpha: 0.5),
                        ),
                      ),
                      const SizedBox(height: 8),

                      CheckboxListTile.adaptive(
                        dense: true,
                        title: const Text('Mode verbeux (--verbose)',
                            style: TextStyle(fontSize: 13)),
                        subtitle: const Text(
                          'Affiche les outils détectés et les statistiques',
                          style: TextStyle(fontSize: 11),
                        ),
                        secondary: const HelpIcon(
                          'Affiche pour chaque paquet : outil utilisé,\n'
                          'version, durée de traitement.\n'
                          'Utile pour déboguer les paquets dont la\n'
                          'licence n\'est pas reconnue.',
                        ),
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
                          children: const [
                            Text('Score qualité sbomqs',
                                style: TextStyle(fontSize: 13)),
                            SizedBox(width: 4),
                            HelpIcon(
                              'Exécute sbomqs (Interlynk) sur le SBOM généré\n'
                              'pour calculer un score de conformité (0–10).\n'
                              'Requiert que sbomqs soit installé dans le PATH.',
                            ),
                          ],
                        ),
                        subtitle: const Text(
                          'Analyse le SBOM généré avec sbomqs après génération',
                          style: TextStyle(fontSize: 11),
                        ),
                        secondary:
                            const Icon(Icons.analytics_outlined, size: 20),
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
                      label: const Text('Arrêter la génération'),
                    )
                  : FilledButton.icon(
                      style: FilledButton.styleFrom(
                        minimumSize: const Size.fromHeight(48),
                      ),
                      onPressed: _run,
                      icon: const Icon(Icons.play_arrow),
                      label: const Text(
                        'Générer le SBOM',
                        style: TextStyle(
                            fontSize: 16, fontWeight: FontWeight.bold),
                      ),
                    ),
            ),
            _CommandPreview(
              commandLine: widget.config.toCommandLine(SettingsService.cliBinary),
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
              message: 'Copier la commande',
              child: InkWell(
                borderRadius: BorderRadius.circular(4),
                onTap: () => Clipboard.setData(ClipboardData(text: commandLine)),
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
  Widget build(BuildContext context) => TextFormField(
        controller: controller,
        decoration: InputDecoration(
          label: helpText != null
              ? Row(mainAxisSize: MainAxisSize.min, children: [
                  Text(label),
                  const SizedBox(width: 4),
                  HelpIcon(helpText!),
                ])
              : null,
          labelText: helpText == null ? label : null,
          hintText: hint,
          border: const OutlineInputBorder(),
          isDense: true,
          suffixIcon: (onPickFiltered != null || onPickDir != null)
              ? PopupMenuButton<_PickKind>(
                  icon: const Icon(Icons.folder_open, size: 18),
                  tooltip: 'Parcourir…',
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
                          leading:
                              const Icon(Icons.filter_alt_outlined, size: 16),
                          title: Text('Type filtré ($filterLabel)'),
                        ),
                      ),
                    const PopupMenuItem(
                      value: _PickKind.anyFile,
                      child: ListTile(
                        dense: true,
                        contentPadding: EdgeInsets.zero,
                        leading: Icon(Icons.folder_open, size: 16),
                        title: Text('Tous les fichiers'),
                      ),
                    ),
                    if (onPickDir != null)
                      const PopupMenuItem(
                        value: _PickKind.directory,
                        child: ListTile(
                          dense: true,
                          contentPadding: EdgeInsets.zero,
                          leading: Icon(Icons.folder_outlined, size: 16),
                          title: Text('Dossier (scan récursif)'),
                        ),
                      ),
                  ],
                )
              : IconButton(
                  icon: const Icon(Icons.folder_open, size: 18),
                  onPressed: onPick,
                  tooltip: 'Parcourir…',
                ),
        ),
        style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
        onChanged: onChanged,
        validator: validator,
      );
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
        formatLabels[format] ?? format,
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
          const Text(
            'Fichiers qui seront générés :',
            style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
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
                        fontSize: 11, fontFamily: 'monospace'),
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
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Supprimer le profil'),
        content: Text('Supprimer « $name » ?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Annuler'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Supprimer',
                style: TextStyle(color: Colors.red)),
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
    return AlertDialog(
      title: const Row(
        children: [
          Icon(Icons.bookmarks_outlined, size: 20),
          SizedBox(width: 8),
          Text('Profils de configuration'),
        ],
      ),
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Enregistrer ──
            Text('Enregistrer la configuration actuelle',
                style: theme.textTheme.labelMedium),
            const SizedBox(height: 6),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _ctrl,
                    decoration: const InputDecoration(
                      hintText: 'Nom du profil…',
                      isDense: true,
                      border: OutlineInputBorder(),
                      contentPadding:
                          EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                    ),
                    onSubmitted: (_) => _save(),
                    style: const TextStyle(fontSize: 13),
                  ),
                ),
                const SizedBox(width: 8),
                FilledButton.icon(
                  icon: const Icon(Icons.save_outlined, size: 16),
                  label: const Text('Enregistrer'),
                  onPressed: _save,
                  style: FilledButton.styleFrom(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 12, vertical: 10)),
                ),
              ],
            ),

            const SizedBox(height: 16),
            const Divider(height: 1),
            const SizedBox(height: 12),

            // ── Liste des profils ──
            Text('Profils enregistrés',
                style: theme.textTheme.labelMedium),
            const SizedBox(height: 6),

            if (_names.isEmpty)
              Container(
                padding: const EdgeInsets.symmetric(vertical: 24),
                alignment: Alignment.center,
                child: const Text('Aucun profil enregistré.',
                    style: TextStyle(color: Colors.grey)),
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
                      title: Text(name,
                          style: const TextStyle(fontSize: 13)),
                      trailing: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          TextButton(
                            onPressed: () => _load(name),
                            style: TextButton.styleFrom(
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 8, vertical: 4)),
                            child: const Text('Charger',
                                style: TextStyle(fontSize: 12)),
                          ),
                          IconButton(
                            icon: const Icon(Icons.delete_outline, size: 17),
                            color: Colors.red[400],
                            tooltip: 'Supprimer',
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
          child: const Text('Fermer'),
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
    return TextFormField(
      controller: controller,
      decoration: InputDecoration(
        label: const HelpLabel(
          'Image OCI (--image)',
          'Référence d\'une image conteneur à analyser.\n'
          '• Registre : nginx:latest, ghcr.io/org/app:v1\n'
          '• Archive tar : ./image.tar / .tar.gz / .tgz (docker save)\n'
          '• Répertoire OCI layout : ./oci/ (index.json)',
        ),
        hintText: 'nginx:latest  •  ./image.tar(.gz)  •  ./oci_dir/',
        border: const OutlineInputBorder(),
        isDense: true,
        prefixIcon: const Icon(Icons.inventory_2_outlined, size: 18),
        suffixIcon: PopupMenuButton<String>(
          icon: const Icon(Icons.folder_open, size: 18),
          tooltip: 'Parcourir…',
          onSelected: (v) {
            if (v == 'tar') {
              onPickTar();
            } else {
              onPickDir();
            }
          },
          itemBuilder: (_) => const [
            PopupMenuItem(
              value: 'tar',
              child: ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: Icon(Icons.archive_outlined, size: 16),
                title: Text('Archive tar (.tar / .tar.gz / .tgz)'),
              ),
            ),
            PopupMenuItem(
              value: 'dir',
              child: ListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                leading: Icon(Icons.folder_outlined, size: 16),
                title: Text('Répertoire OCI layout'),
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
    return TextFormField(
      controller: controller,
      decoration: InputDecoration(
        label: const HelpLabel(
          'Binaire autonome (--binary)',
          'Exécutable local à analyser directement (pas une image de '
          'conteneur) — ex. un binaire Go lié statiquement.\n'
          'Force le backend syft : seul capable de lire les métadonnées '
          'embarquées dans un binaire (buildinfo Go via '
          'go-module-binary-cataloger ; classifieur générique syft pour '
          'quelques bibliothèques connues — OpenSSL, zlib, sqlite…).\n'
          'Ne récupère pas les dépendances liées statiquement sans '
          'métadonnée embarquée (C/C++ « fait maison », Rust sans '
          'cargo-auditable).',
        ),
        hintText: '/usr/local/bin/mon-app',
        border: const OutlineInputBorder(),
        isDense: true,
        prefixIcon: const Icon(Icons.terminal_outlined, size: 18),
        suffixIcon: IconButton(
          icon: const Icon(Icons.folder_open, size: 18),
          tooltip: 'Parcourir…',
          onPressed: onPick,
        ),
      ),
      style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
      onChanged: onChanged,
    );
  }
}

// ─── Sélecteur d'outil OCI ────────────────────────────────────────────────────

/// Option --per-layer (un SBOM par couche de l'image) et sa méthode de calcul
/// (--layer-mode), affichées sous le backend OCI.
class _PerLayerOptions extends StatelessWidget {
  final SbomConfig config;
  final VoidCallback onChanged;

  const _PerLayerOptions({required this.config, required this.onChanged});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
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
                'Un SBOM par couche (--per-layer)',
                style: TextStyle(
                  fontSize: 12,
                  color: theme.colorScheme.onSurface,
                ),
              ),
            ),
            const SizedBox(width: 4),
            const HelpIcon(
              'Génère, en plus du SBOM global, un SBOM par couche de l\'image '
              '(<sortie>.layer-NN-<digest>.<ext>, dans chaque format coché) '
              'décrivant le delta de la couche : composants ajoutés ou '
              'modifiés, composants supprimés listés à part. Le SBOM global '
              'indique la couche d\'origine de chaque composant.\n'
              '• Métadonnées : couche d\'origine indiquée par Syft/Trivy — '
              'rapide, ajouts seulement\n'
              '• Rootfs : couches appliquées une à une et réanalysées — '
              'ajouts, modifications, suppressions (seul mode possible '
              'avec Skopeo et cdxgen)',
            ),
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
                label: const Text('Métadonnées'),
                icon: const Icon(Icons.bolt_outlined, size: 14),
                enabled: metadataOk,
                tooltip: 'Couche d\'origine indiquée par le backend',
              ),
              const ButtonSegment(
                value: 'rootfs',
                label: Text('Rootfs'),
                icon: Icon(Icons.layers_outlined, size: 14),
                tooltip: 'Réanalyse du rootfs après chaque couche',
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
                'Mode rootfs forcé : ${ociToolLabels[config.ociTool]} '
                'n\'indique pas la couche d\'origine des paquets',
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

  const _OciToolSelector({
    required this.selected,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(Icons.build_outlined,
                size: 14, color: theme.colorScheme.secondary),
            const SizedBox(width: 6),
            Text(
              'Backend OCI (--oci-tool)',
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w600,
                color: theme.colorScheme.secondary,
              ),
            ),
            const SizedBox(width: 4),
            const HelpIcon(
              'Outil utilisé pour extraire les paquets de l\'image :\n'
              '• Syft (Anchore) — le plus complet, tous écosystèmes\n'
              '• Trivy (Aqua) — rapide, CVE intégrées\n'
              '• Skopeo — extraction manuelle dpkg/rpm/apk\n'
              '• cdxgen (OWASP) — CycloneDX natif, tous écosystèmes',
            ),
          ],
        ),
        const SizedBox(height: 6),
        SegmentedButton<String>(
          style: SegmentedButton.styleFrom(
            textStyle: const TextStyle(fontSize: 11),
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            minimumSize: const Size(0, 32),
          ),
          segments: const [
            ButtonSegment(
              value: 'syft',
              label: Text('Syft'),
              icon: Icon(Icons.search, size: 14),
              tooltip: 'Anchore Syft — tous écosystèmes',
            ),
            ButtonSegment(
              value: 'trivy',
              label: Text('Trivy'),
              icon: Icon(Icons.security, size: 14),
              tooltip: 'Aqua Trivy — tous écosystèmes',
            ),
            ButtonSegment(
              value: 'skopeo',
              label: Text('Skopeo'),
              icon: Icon(Icons.layers_outlined, size: 14),
              tooltip: 'Skopeo + extraction manuelle (dpkg/rpm/apk)',
            ),
            ButtonSegment(
              value: 'cdxgen',
              label: Text('cdxgen'),
              icon: Icon(Icons.inventory_2_outlined, size: 14),
              tooltip: 'OWASP cdxgen — CycloneDX natif, tous écosystèmes',
            ),
          ],
          selected: {selected},
          onSelectionChanged: (s) => onChanged(s.first),
        ),
        const SizedBox(height: 4),
        Text(
          selected == 'syft'
              ? 'Syft (recommandé) — supporte tous les écosystèmes'
              : selected == 'trivy'
                  ? 'Trivy — tous écosystèmes, déjà utilisé pour les CVE'
                  : selected == 'skopeo'
                      ? 'Skopeo — extraction manuelle dpkg / rpm / apk'
                      : 'cdxgen — SBOM CycloneDX natif, tous écosystèmes '
                          '(nécessite Node.js)',
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
    return Padding(
      padding: const EdgeInsets.only(left: 32, bottom: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                'Version (--cyclonedx-version)',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.secondary,
                ),
              ),
              const SizedBox(width: 4),
              const HelpIcon(
                '1.6 — la plus répandue chez les consommateurs actuels (défaut).\n'
                '1.7 — ajoute citations / patentAssertions / distributionConstraints\n'
                '(voir --tlp et --patent-map en ligne de commande).',
              ),
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
            'Types acceptés (fichier liste, paquet unique, ou dossier scanné) :',
            style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.bold,
                color: theme.colorScheme.onSurface.withValues(alpha: 0.7)),
          ),
          const SizedBox(height: 4),
          for (final item in const [
            ('RPM installé', 'bash  ou  bash-5.1.8-6.el9.x86_64'),
            ('Fichier .rpm', '/path/to/package.rpm'),
            ('Wheel Python', '/path/to/package.whl'),
            ('Archive tar', '/path/to/pkg.tar.gz  ou  .tgz'),
            ('Archive .zip', '/path/to/archive.zip'),
            ('Paquet Debian', '/path/to/package.deb'),
            ('Archive Java', '/path/to/lib.jar'),
            ('requirements', '/path/to/requirements.txt'),
            ('Manifeste/lock', 'go.sum, package-lock.json, pom.xml, pubspec.lock…'),
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
                          color: theme.colorScheme.primary),
                    ),
                  ),
                  Expanded(
                    child: Text(
                      item.$2,
                      style: const TextStyle(
                          fontSize: 10, fontFamily: 'monospace'),
                    ),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 6),
          const Divider(height: 8),
          Text(
            'Image OCI (champ --image) :',
            style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.bold,
                color: theme.colorScheme.onSurface.withValues(alpha: 0.7)),
          ),
          const SizedBox(height: 4),
          for (final item in const [
            ('Registre', 'nginx:latest  •  ubuntu@sha256:…'),
            ('Archive tar', '/path/image.tar  (docker save)'),
            ('OCI layout', '/path/oci_dir/  (index.json présent)'),
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
                          color: theme.colorScheme.secondary),
                    ),
                  ),
                  Expanded(
                    child: Text(
                      item.$2,
                      style: const TextStyle(
                          fontSize: 10, fontFamily: 'monospace'),
                    ),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 6),
          const Divider(height: 8),
          Text(
            'Binaire autonome (champ --binary) :',
            style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.bold,
                color: theme.colorScheme.onSurface.withValues(alpha: 0.7)),
          ),
          const SizedBox(height: 4),
          Text(
            'Exécutable local (ex. binaire Go lié statiquement) — force le '
            'backend syft. Dépendances Go embarquées lues systématiquement ; '
            'seul un catalogue fixe de bibliothèques connues (OpenSSL, zlib, '
            'sqlite…) est détecté pour les autres langages.',
            style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
          ),
        ],
      ),
    );
  }
}
