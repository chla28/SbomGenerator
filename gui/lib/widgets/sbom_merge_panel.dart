import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../models/sbom_result.dart';
import '../services/sbom_runner.dart';
import '../l10n/l10n.dart';

class SbomMergePanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  const SbomMergePanel({super.key, required this.outputFiles});

  @override
  State<SbomMergePanel> createState() => _SbomMergePanelState();
}

class _SbomMergePanelState extends State<SbomMergePanel>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;

  final List<String> _inputFiles = [];
  final _outputCtrl = TextEditingController(text: 'merged.cdx.json');
  final _nameCtrl = TextEditingController();

  final SbomRunner _runner = SbomRunner();
  final List<String> _logLines = [];
  bool _running = false;
  int? _exitCode;
  String? _resultPath;

  List<OutputFile> get _sbomFiles => widget.outputFiles
      .where(
        (f) => f.path.endsWith('.cdx.json') || f.path.endsWith('.spdx.json'),
      )
      .toList();

  @override
  void dispose() {
    _outputCtrl.dispose();
    _nameCtrl.dispose();
    _runner.kill();
    super.dispose();
  }

  Future<void> _pickFiles({bool filtered = true}) async {
    final r = await FilePicker.pickFiles(
      dialogTitle: context.l10n.mergePickTitle,
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? const ['json', 'jsonld'] : null,
      allowMultiple: true,
    );
    if (r == null) return;
    setState(() {
      for (final f in r.files) {
        if (f.path != null && !_inputFiles.contains(f.path)) {
          _inputFiles.add(f.path!);
        }
      }
    });
  }

  void _addGenerated(String path) {
    if (!_inputFiles.contains(path)) setState(() => _inputFiles.add(path));
  }

  void _remove(String path) => setState(() => _inputFiles.remove(path));

  Future<void> _runMerge() async {
    if (_inputFiles.length < 2 || _outputCtrl.text.trim().isEmpty) return;
    final outputPath = _outputCtrl.text.trim();
    setState(() {
      _running = true;
      _exitCode = null;
      _resultPath = null;
      _logLines.clear();
    });

    final args = ['merge', ..._inputFiles, '-o', outputPath];
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
    final canMerge =
        !_running &&
        _inputFiles.length >= 2 &&
        _outputCtrl.text.trim().isNotEmpty;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              MenuAnchor(
                builder: (ctx, ctrl, child) => OutlinedButton.icon(
                  icon: const Icon(Icons.add, size: 16),
                  label: Text(context.l10n.mergeAddFiles),
                  onPressed: () => ctrl.isOpen ? ctrl.close() : ctrl.open(),
                ),
                menuChildren: [
                  MenuItemButton(
                    leadingIcon: const Icon(
                      Icons.filter_alt_outlined,
                      size: 16,
                    ),
                    onPressed: () => _pickFiles(),
                    child: const Text('.json / .jsonld'),
                  ),
                  MenuItemButton(
                    leadingIcon: const Icon(Icons.folder_open, size: 16),
                    onPressed: () => _pickFiles(filtered: false),
                    child: Text(context.l10n.mergeAllFiles),
                  ),
                ],
              ),
              const SizedBox(width: 8),
              if (_sbomFiles.isNotEmpty)
                MenuAnchor(
                  builder: (ctx, ctrl, child) => OutlinedButton.icon(
                    icon: const Icon(Icons.folder_outlined, size: 16),
                    label: Text(context.l10n.commonGeneratedFiles),
                    onPressed: () => ctrl.isOpen ? ctrl.close() : ctrl.open(),
                  ),
                  menuChildren: [
                    for (final f in _sbomFiles)
                      MenuItemButton(
                        onPressed: () => _addGenerated(f.path),
                        child: Text(f.path.split('/').last),
                      ),
                  ],
                ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  context.l10n.mergeSelected(_inputFiles.length) +
                      (_inputFiles.length < 2
                          ? context.l10n.mergeAtLeastTwo
                          : ''),
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
          child: _inputFiles.isEmpty
              ? Center(
                  child: Text(
                    context.l10n.mergeHint,
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: theme.colorScheme.onSurface.withValues(alpha: 0.5),
                    ),
                  ),
                )
              : ListView.builder(
                  itemCount: _inputFiles.length,
                  itemBuilder: (_, i) => ListTile(
                    dense: true,
                    leading: const Icon(Icons.description_outlined, size: 18),
                    title: Text(_inputFiles[i].split('/').last),
                    subtitle: Text(
                      _inputFiles[i],
                      style: const TextStyle(fontSize: 10),
                      overflow: TextOverflow.ellipsis,
                    ),
                    trailing: IconButton(
                      icon: const Icon(Icons.close, size: 16),
                      onPressed: () => _remove(_inputFiles[i]),
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
                  decoration: InputDecoration(
                    labelText: context.l10n.commonOutputFile,
                    isDense: true,
                    border: const OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _nameCtrl,
                  decoration: InputDecoration(
                    labelText: context.l10n.commonDocNameOptional,
                    isDense: true,
                    border: const OutlineInputBorder(),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                icon: _running
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.merge_type, size: 16),
                label: Text(context.l10n.mergeButton),
                onPressed: canMerge ? _runMerge : null,
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
                        ? context.l10n.mergeOk(_resultPath ?? '')
                        : context.l10n.mergeFailed(_exitCode ?? -1),
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
