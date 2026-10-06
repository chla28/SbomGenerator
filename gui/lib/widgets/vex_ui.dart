import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../l10n/l10n.dart';
import '../models/vex.dart';
import '../services/vex_controller.dart';
import 'pdf_report.dart' show kGuiVersion;

/// Donne accès aux déclarations VEX depuis la fiche d'une CVE, où qu'elle
/// s'affiche (onglets de scan, tableau de bord).
class VexScope extends InheritedNotifier<VexController> {
  const VexScope({
    super.key,
    required VexController controller,
    required super.child,
  }) : super(notifier: controller);

  static VexController? maybeOf(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<VexScope>()?.notifier;
}

String vexStatusLabel(AppLocalizations l, String status) => switch (status) {
  'not_affected' => l.vexStatusNotAffected,
  'affected' => l.vexStatusAffected,
  'fixed' => l.vexStatusFixed,
  _ => l.vexStatusInvestigation,
};

String vexJustificationLabel(AppLocalizations l, String j) => switch (j) {
  'component_not_present' => l.vexJustComponentNotPresent,
  'vulnerable_code_not_present' => l.vexJustCodeNotPresent,
  'vulnerable_code_not_in_execute_path' => l.vexJustNotInExecutePath,
  'vulnerable_code_cannot_be_controlled_by_adversary' =>
    l.vexJustCannotBeControlled,
  'inline_mitigations_already_exist' => l.vexJustInlineMitigations,
  _ => j,
};

/// Une ligne lisible pour une déclaration : « non affectée — code jamais… ».
String vexSummary(AppLocalizations l, VexStatement s) {
  final j = s.justification == null
      ? ''
      : ' — ${vexJustificationLabel(l, s.justification!)}';
  return '${vexStatusLabel(l, s.status)}$j';
}

/// Dialogue de saisie d'une déclaration VEX. [packages] : paquets (« nom
/// version ») concernés par la CVE, proposés comme portée.
Future<VexStatement?> showVexDialog(
  BuildContext context, {
  required String vulnId,
  required List<({String name, String version})> packages,
  VexStatement? existing,
}) => showDialog<VexStatement>(
  context: context,
  builder: (_) =>
      _VexDialog(vulnId: vulnId, packages: packages, existing: existing),
);

class _VexDialog extends StatefulWidget {
  final String vulnId;
  final List<({String name, String version})> packages;
  final VexStatement? existing;
  const _VexDialog({
    required this.vulnId,
    required this.packages,
    this.existing,
  });

  @override
  State<_VexDialog> createState() => _VexDialogState();
}

class _VexDialogState extends State<_VexDialog> {
  late String _status = widget.existing?.status ?? 'not_affected';
  late String? _justification = widget.existing?.justification;
  late final _impact = TextEditingController(
    text: widget.existing?.impactStatement ?? '',
  );
  // Portée : `null` = tous les paquets ; sinon « nom@version ».
  late String? _scope = _initialScope();
  String? _error;

  String? _initialScope() {
    final p = widget.existing?.products;
    if (p != null) return p.isEmpty ? null : p.first;
    return widget.packages.isEmpty
        ? null
        : '${widget.packages.first.name}@${widget.packages.first.version}';
  }

  @override
  void dispose() {
    _impact.dispose();
    super.dispose();
  }

  void _save() {
    final l = context.l10n;
    if (_status == 'not_affected' && _justification == null) {
      setState(() => _error = l.vexNeedJustification);
      return;
    }
    Navigator.pop(
      context,
      VexStatement(
        vulnId: widget.vulnId,
        products: _scope == null ? const [] : [_scope!],
        status: _status,
        justification: _status == 'not_affected' ? _justification : null,
        impactStatement: _impact.text.trim().isEmpty
            ? null
            : _impact.text.trim(),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final scopes = <String?>[
      for (final p in widget.packages) '${p.name}@${p.version}',
      if (_scope != null &&
          !widget.packages.any((p) => '${p.name}@${p.version}' == _scope))
        _scope,
      null,
    ];
    return AlertDialog(
      title: Text(l.vexDialogTitle(widget.vulnId)),
      content: SizedBox(
        width: 460,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              DropdownButtonFormField<String>(
                key: const Key('vex-status'),
                initialValue: _status,
                decoration: InputDecoration(labelText: l.vexFieldStatus),
                items: [
                  for (final s in vexStatuses)
                    DropdownMenuItem(
                      value: s,
                      child: Text(vexStatusLabel(l, s)),
                    ),
                ],
                onChanged: (v) => setState(() => _status = v!),
              ),
              if (_status == 'not_affected')
                DropdownButtonFormField<String>(
                  key: const Key('vex-justification'),
                  initialValue: _justification,
                  isExpanded: true,
                  decoration: InputDecoration(
                    labelText: l.vexFieldJustification,
                  ),
                  items: [
                    for (final j in vexJustifications)
                      DropdownMenuItem(
                        value: j,
                        child: Text(vexJustificationLabel(l, j)),
                      ),
                  ],
                  onChanged: (v) => setState(() {
                    _justification = v;
                    _error = null;
                  }),
                ),
              TextField(
                key: const Key('vex-impact'),
                controller: _impact,
                maxLines: 2,
                decoration: InputDecoration(labelText: l.vexFieldImpact),
              ),
              DropdownButtonFormField<String?>(
                key: const Key('vex-scope'),
                initialValue: _scope,
                isExpanded: true,
                decoration: InputDecoration(labelText: l.vexFieldScope),
                items: [
                  for (final s in scopes)
                    DropdownMenuItem(value: s, child: Text(s ?? l.vexScopeAll)),
                ],
                onChanged: (v) => setState(() => _scope = v),
              ),
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 8),
                  child: Text(
                    _error!,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(l.homeCancel),
        ),
        FilledButton(
          key: const Key('vex-save'),
          onPressed: _save,
          child: Text(l.vexSave),
        ),
      ],
    );
  }
}

/// Section VEX de la fiche d'une CVE : déclaration existante ou bouton pour
/// en créer une.
class CveVexRow extends StatelessWidget {
  final VexController controller;
  final String vulnId;
  final List<({String name, String version})> packages;
  const CveVexRow({
    super.key,
    required this.controller,
    required this.vulnId,
    required this.packages,
  });

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    VexStatement? current;
    for (final p in packages) {
      current = controller.find(vulnId, p.name, p.version);
      if (current != null) break;
    }
    if (packages.isEmpty) current = controller.find(vulnId, '', '');
    Future<void> edit() async {
      final s = await showVexDialog(
        context,
        vulnId: vulnId,
        packages: packages,
        existing: current,
      );
      if (s != null) controller.set(s);
    }

    return Row(
      children: [
        const Icon(Icons.rule, size: 14),
        const SizedBox(width: 6),
        if (current == null)
          TextButton(
            key: const Key('vex-declare'),
            onPressed: edit,
            child: Text(l.vexDeclare),
          )
        else ...[
          Flexible(
            child: Text(
              l.vexCurrent(
                vexSummary(l, current),
                current.impactStatement == null
                    ? ''
                    : ' (${current.impactStatement})',
              ),
              style: const TextStyle(fontSize: 12),
            ),
          ),
          TextButton(onPressed: edit, child: Text(l.vexEdit)),
          TextButton(
            onPressed: () => controller.remove(current!),
            child: Text(l.vexRemove),
          ),
        ],
      ],
    );
  }
}

/// Barre VEX du tableau de bord : résumé, masquage, import / export, liste.
class VexBar extends StatelessWidget {
  final VexController controller;
  final bool hide;
  final ValueChanged<bool> onHideChanged;

  /// Nombre de CVE actuellement masquées par le VEX.
  final int hiddenCount;
  const VexBar({
    super.key,
    required this.controller,
    required this.hide,
    required this.onHideChanged,
    required this.hiddenCount,
  });

  Future<void> _import(BuildContext context) async {
    final l = context.l10n;
    final picked = await FilePicker.pickFiles(
      dialogTitle: l.vexDialogImport,
      type: FileType.custom,
      allowedExtensions: ['json'],
    );
    final path = picked?.files.single.path;
    if (path == null) return;
    try {
      final doc = jsonDecode(await File(path).readAsString());
      final n = controller.merge(parseVex(doc as Map<String, dynamic>));
      if (!context.mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(l.vexImported(n))));
    } catch (e) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(l.vexInvalid('$e'))));
    }
  }

  Future<void> _export(BuildContext context, bool cdx) async {
    final l = context.l10n;
    if (controller.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(l.vexNothingToExport)));
      return;
    }
    final path = await FilePicker.saveFile(
      dialogTitle: l.vexDialogExport,
      fileName: cdx ? 'vex.cdx.json' : 'vex.openvex.json',
      type: FileType.custom,
      allowedExtensions: ['json'],
    );
    if (path == null) return;
    final doc = cdx
        ? controller.toCycloneDx('sbom-generator-gui', kGuiVersion)
        : controller.toOpenVex('sbom-generator-gui', kGuiVersion);
    await File(path).writeAsString('${encodeVex(doc)}\n');
    if (!context.mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(l.vexExported(path))));
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) => Card(
        key: const Key('vex-bar'),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          child: Wrap(
            spacing: 8,
            runSpacing: 4,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              const Icon(Icons.rule, size: 18),
              Text(
                l.vexBarSummary(controller.statements.length),
                style: const TextStyle(fontWeight: FontWeight.w600),
              ),
              if (!controller.isEmpty)
                FilterChip(
                  key: const Key('vex-hide'),
                  label: Text(l.vexHideSuppressed(hiddenCount)),
                  selected: hide,
                  onSelected: onHideChanged,
                ),
              TextButton.icon(
                icon: const Icon(Icons.file_open_outlined, size: 18),
                label: Text(l.vexImport),
                onPressed: () => _import(context),
              ),
              PopupMenuButton<bool>(
                tooltip: l.vexExport,
                onSelected: (cdx) => _export(context, cdx),
                itemBuilder: (_) => [
                  PopupMenuItem(value: false, child: Text(l.vexExportOpenVex)),
                  PopupMenuItem(value: true, child: Text(l.vexExportCdx)),
                ],
                child: Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 6,
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.upload_file, size: 18),
                      const SizedBox(width: 4),
                      Text(l.vexExport),
                    ],
                  ),
                ),
              ),
              if (!controller.isEmpty)
                TextButton(
                  onPressed: () => showDialog<void>(
                    context: context,
                    builder: (_) => _VexListDialog(controller: controller),
                  ),
                  child: Text(l.vexManage),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _VexListDialog extends StatelessWidget {
  final VexController controller;
  const _VexListDialog({required this.controller});

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) => AlertDialog(
        title: Text(l.vexManageTitle),
        content: SizedBox(
          width: 560,
          height: 360,
          child: ListView(
            children: [
              for (final s in controller.statements)
                ListTile(
                  dense: true,
                  title: Text(s.vulnId),
                  subtitle: Text(
                    '${s.products.isEmpty ? l.vexAnyPackage : s.products.join(', ')}'
                    ' · ${vexSummary(l, s)}',
                  ),
                  trailing: IconButton(
                    tooltip: l.vexRemove,
                    icon: const Icon(Icons.delete_outline, size: 18),
                    onPressed: () => controller.remove(s),
                  ),
                ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: controller.isEmpty
                ? null
                : () {
                    controller.clear();
                    Navigator.pop(context);
                  },
            child: Text(l.vexClearAll),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l.commonClose),
          ),
        ],
      ),
    );
  }
}
