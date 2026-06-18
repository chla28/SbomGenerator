import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import '../models/sbom_config.dart';

class ConfigPanel extends StatefulWidget {
  final SbomConfig config;
  final String projectRoot;
  final bool isRunning;
  final VoidCallback onRun;
  final VoidCallback onStop;
  final ValueChanged<String> onProjectRootChanged;

  const ConfigPanel({
    super.key,
    required this.config,
    required this.projectRoot,
    required this.isRunning,
    required this.onRun,
    required this.onStop,
    required this.onProjectRootChanged,
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
  late TextEditingController _projectRootCtrl;

  @override
  void initState() {
    super.initState();
    final c = widget.config;
    _inputCtrl = TextEditingController(text: c.inputFile);
    _outputCtrl = TextEditingController(text: c.outputBase);
    _nameCtrl = TextEditingController(text: c.documentName);
    _rpmDirCtrl = TextEditingController(text: c.rpmDir);
    _licenseMapCtrl = TextEditingController(text: c.licenseMapFile);
    _projectRootCtrl = TextEditingController(text: widget.projectRoot);
  }

  @override
  void didUpdateWidget(ConfigPanel old) {
    super.didUpdateWidget(old);
    if (widget.projectRoot != old.projectRoot) {
      _projectRootCtrl.text = widget.projectRoot;
    }
  }

  @override
  void dispose() {
    for (final c in [
      _inputCtrl, _outputCtrl, _nameCtrl, _rpmDirCtrl,
      _licenseMapCtrl, _projectRootCtrl,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  void _sync() {
    final c = widget.config;
    c.inputFile = _inputCtrl.text.trim();
    c.outputBase = _outputCtrl.text.trim();
    c.documentName = _nameCtrl.text.trim();
    c.rpmDir = _rpmDirCtrl.text.trim();
    c.licenseMapFile = _licenseMapCtrl.text.trim();
  }

  void _run() {
    if (!_formKey.currentState!.validate()) return;
    _sync();
    widget.onRun();
  }

  Future<void> _pickFile(TextEditingController ctrl,
      {String? title, List<String>? extensions}) async {
    final r = await FilePicker.platform.pickFiles(
      dialogTitle: title,
      type: extensions != null ? FileType.custom : FileType.any,
      allowedExtensions: extensions,
    );
    if (r != null && r.files.single.path != null) {
      ctrl.text = r.files.single.path!;
      _sync();
      setState(() {});
    }
  }

  Future<void> _pickDir(TextEditingController ctrl,
      {String? title, VoidCallback? onDone}) async {
    final r = await FilePicker.platform.getDirectoryPath(dialogTitle: title);
    if (r != null) {
      ctrl.text = r;
      onDone?.call();
    }
  }

  Future<void> _saveFile(TextEditingController ctrl,
      {String? title, String? fileName}) async {
    final r = await FilePicker.platform.saveFile(
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
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              color: theme.colorScheme.primary,
              width: double.infinity,
              child: Text(
                'Configuration',
                style: TextStyle(
                  color: theme.colorScheme.onPrimary,
                  fontWeight: FontWeight.bold,
                  fontSize: 14,
                ),
              ),
            ),

            Expanded(
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  // ── Projet ──────────────────────────────────────
                  _Section(
                    title: 'Projet',
                    icon: Icons.folder_open,
                    children: [
                      _FileField(
                        label: 'Racine du projet sbom_generator',
                        controller: _projectRootCtrl,
                        hint: '/chemin/vers/sbom_generator',
                        onPick: () => _pickDir(
                          _projectRootCtrl,
                          title: 'Sélectionner la racine du projet sbom_generator',
                          onDone: () => widget.onProjectRootChanged(
                              _projectRootCtrl.text.trim()),
                        ),
                        onChanged: (v) =>
                            widget.onProjectRootChanged(v.trim()),
                        validator: (v) =>
                            (v == null || v.trim().isEmpty) ? 'Requis' : null,
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),

                  // ── Entrée ──────────────────────────────────────
                  _Section(
                    title: 'Entrée',
                    icon: Icons.input,
                    children: [
                      _FileField(
                        label: 'Fichier d\'entrée (--input)',
                        controller: _inputCtrl,
                        hint: 'rpm.lst, requirements.txt, …',
                        onPick: () => _pickFile(
                          _inputCtrl,
                          title: 'Sélectionner le fichier d\'entrée',
                          extensions: ['lst', 'txt'],
                        ),
                        onChanged: (_) => _sync(),
                        validator: (v) =>
                            (v == null || v.trim().isEmpty) ? 'Requis' : null,
                      ),
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
                        onPick: () => _saveFile(
                          _outputCtrl,
                          title: 'Chemin de base du SBOM',
                          fileName: 'sbom',
                        ),
                        onChanged: (_) => _sync(),
                      ),
                      const SizedBox(height: 12),

                      // Format checkboxes
                      const Text(
                        'Formats (--format)',
                        style: TextStyle(
                            fontSize: 12, fontWeight: FontWeight.w600),
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
                            }
                          }),
                        ),

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
                          labelText: 'Nom du document SBOM (--name)',
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
                        onPick: () => _pickFile(
                          _licenseMapCtrl,
                          title: 'Fichier de map licences',
                          extensions: ['txt', 'map'],
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
                          const Spacer(),
                          Text(
                            c.concurrency == 0 ? 'illimitée' : '${c.concurrency}',
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
                        onChanged: (v) =>
                            setState(() => c.concurrency = v.round()),
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
                        value: c.verbose,
                        onChanged: (v) =>
                            setState(() => c.verbose = v ?? false),
                        controlAffinity: ListTileControlAffinity.leading,
                      ),
                    ],
                  ),
                ],
              ),
            ),

            // Bouton Run / Stop
            Padding(
              padding: const EdgeInsets.all(16),
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

class _FileField extends StatelessWidget {
  final String label;
  final TextEditingController controller;
  final String? hint;
  final VoidCallback onPick;
  final ValueChanged<String>? onChanged;
  final FormFieldValidator<String>? validator;

  const _FileField({
    required this.label,
    required this.controller,
    required this.onPick,
    this.hint,
    this.onChanged,
    this.validator,
  });

  @override
  Widget build(BuildContext context) => TextFormField(
        controller: controller,
        decoration: InputDecoration(
          labelText: label,
          hintText: hint,
          border: const OutlineInputBorder(),
          isDense: true,
          suffixIcon: IconButton(
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
            'Types acceptés (un par ligne) :',
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
            ('requirements', '/path/to/requirements.txt'),
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
        ],
      ),
    );
  }
}
