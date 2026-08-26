import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../models/sbom_result.dart';
import '../services/sbom_runner.dart';

class SbomLicensesPanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  const SbomLicensesPanel({super.key, required this.outputFiles});

  @override
  State<SbomLicensesPanel> createState() => _SbomLicensesPanelState();
}

class _SbomLicensesPanelState extends State<SbomLicensesPanel>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;

  String? _inputFile;
  final _outputCtrl = TextEditingController(text: 'licences.adoc');
  final _nameCtrl = TextEditingController();

  final SbomRunner _runner = SbomRunner();
  final List<String> _logLines = [];
  bool _running = false;
  int? _exitCode;
  String? _resultPath;

  List<OutputFile> get _sbomFiles => widget.outputFiles
      .where((f) =>
          f.path.endsWith('.cdx.json') ||
          f.path.endsWith('.spdx.json') ||
          f.path.endsWith('.spdx3.jsonld'))
      .toList();

  @override
  void dispose() {
    _outputCtrl.dispose();
    _nameCtrl.dispose();
    _runner.kill();
    super.dispose();
  }

  Future<void> _pickFile() async {
    final r = await FilePicker.pickFiles(
      dialogTitle: 'Sélectionner un fichier SBOM',
      type: FileType.custom,
      allowedExtensions: const ['json'],
    );
    if (r == null || r.files.isEmpty || r.files.first.path == null) return;
    setState(() => _inputFile = r.files.first.path);
  }

  Future<void> _runLicenses() async {
    if (_inputFile == null || _outputCtrl.text.trim().isEmpty) return;
    final outputPath = _outputCtrl.text.trim();
    setState(() {
      _running = true;
      _exitCode = null;
      _resultPath = null;
      _logLines.clear();
    });

    final args = ['licenses', '-i', _inputFile!, '-o', outputPath];
    if (_nameCtrl.text.trim().isNotEmpty) {
      args.addAll(['-n', _nameCtrl.text.trim()]);
    }

    await for (final event in _runner.run(args: args)) {
      if (!mounted) return;
      if (event is SbomLogEvent) {
        setState(() => _logLines.add(event.line));
      } else if (event is SbomDoneEvent) {
        setState(() {
          _running = false;
          _exitCode = event.exitCode;
          _resultPath = event.exitCode == 0 ? outputPath : null;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final theme = Theme.of(context);
    final canRun =
        !_running && _inputFile != null && _outputCtrl.text.trim().isNotEmpty;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              OutlinedButton.icon(
                icon: const Icon(Icons.description_outlined, size: 16),
                label: const Text('Choisir un fichier…'),
                onPressed: _pickFile,
              ),
              const SizedBox(width: 8),
              if (_sbomFiles.isNotEmpty)
                MenuAnchor(
                  builder: (ctx, ctrl, child) => OutlinedButton.icon(
                    icon: const Icon(Icons.folder_outlined, size: 16),
                    label: const Text('Fichiers générés'),
                    onPressed: () => ctrl.isOpen ? ctrl.close() : ctrl.open(),
                  ),
                  menuChildren: [
                    for (final f in _sbomFiles)
                      MenuItemButton(
                        onPressed: () => setState(() => _inputFile = f.path),
                        child: Text(f.path.split('/').last),
                      ),
                  ],
                ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  _inputFile == null
                      ? 'Aucun fichier sélectionné'
                      : _inputFile!,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurface.withValues(alpha: 0.6),
                  ),
                ),
              ),
            ],
          ),
        ),

        Expanded(
          child: Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Text(
                'Sélectionnez un fichier CycloneDX ou SPDX pour générer un '
                'rapport de licences AsciiDoc, regroupé par licence, avec '
                'signalement des licences copyleft et des paquets sans '
                'licence détectée.',
                textAlign: TextAlign.center,
                style: TextStyle(
                    color: theme.colorScheme.onSurface.withValues(alpha: 0.5)),
              ),
            ),
          ),
        ),

        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _outputCtrl,
                  onChanged: (_) => setState(() {}),
                  decoration: const InputDecoration(
                    labelText: 'Fichier de sortie',
                    isDense: true,
                    border: OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _nameCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Nom du document (optionnel)',
                    isDense: true,
                    border: OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                icon: _running
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2))
                    : const Icon(Icons.gavel_outlined, size: 16),
                label: const Text('Générer'),
                onPressed: canRun ? _runLicenses : null,
              ),
            ],
          ),
        ),

        if (_exitCode != null)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            child: Row(
              children: [
                Icon(
                  _exitCode == 0 ? Icons.check_circle : Icons.error,
                  size: 16,
                  color: _exitCode == 0 ? Colors.green[700] : Colors.red[700],
                ),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    _exitCode == 0
                        ? 'Rapport généré → $_resultPath'
                        : 'Échec de la génération (code $_exitCode) — voir le journal ci-dessous.',
                  ),
                ),
              ],
            ),
          ),

        if (_logLines.isNotEmpty)
          SizedBox(
            height: 140,
            child: Container(
              width: double.infinity,
              color: theme.colorScheme.surfaceContainerLow,
              padding: const EdgeInsets.all(8),
              child: SingleChildScrollView(
                child: SelectableText(
                  _logLines.join('\n'),
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
              ),
            ),
          ),
      ],
    );
  }
}
