import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../i18n.dart';
import '../services/save_dialog.dart';
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

String vexStatusLabel(String status) => switch (status) {
  'not_affected' => tr('non affectée'),
  'affected' => tr('affectée'),
  'fixed' => tr('corrigée'),
  _ => tr('à l\'étude'),
};

String vexJustificationLabel(String j) => switch (j) {
  'component_not_present' => tr('composant absent'),
  'vulnerable_code_not_present' => tr('code vulnérable absent'),
  'vulnerable_code_not_in_execute_path' => tr('code vulnérable jamais exécuté'),
  'vulnerable_code_cannot_be_controlled_by_adversary' =>
    tr('code non contrôlable par un attaquant'),
  'inline_mitigations_already_exist' => tr('mesures d\'atténuation déjà en place'),
  _ => j,
};

/// Une ligne lisible pour une déclaration : « non affectée — code jamais… ».
String vexSummary(VexStatement s) {
  final j = s.justification == null
      ? ''
      : ' — ${vexJustificationLabel( s.justification!)}';
  return '${vexStatusLabel( s.status)}$j';
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
    if (_status == 'not_affected' && _justification == null) {
      setState(() => _error = tr('Une justification est requise pour « non affectée ».'));
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
    final scopes = <String?>[
      for (final p in widget.packages) '${p.name}@${p.version}',
      if (_scope != null &&
          !widget.packages.any((p) => '${p.name}@${p.version}' == _scope))
        _scope,
      null,
    ];
    return AlertDialog(
      title: Text(tr('Déclaration VEX — {id}', {'id': widget.vulnId})),
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
                decoration: InputDecoration(labelText: tr('État')),
                items: [
                  for (final s in vexStatuses)
                    DropdownMenuItem(
                      value: s,
                      child: Text(vexStatusLabel( s)),
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
                    labelText: tr('Justification'),
                  ),
                  items: [
                    for (final j in vexJustifications)
                      DropdownMenuItem(
                        value: j,
                        child: Text(vexJustificationLabel( j)),
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
                decoration: InputDecoration(labelText: tr('Explication (facultative)')),
              ),
              DropdownButtonFormField<String?>(
                key: const Key('vex-scope'),
                initialValue: _scope,
                isExpanded: true,
                decoration: InputDecoration(labelText: tr('Portée')),
                items: [
                  for (final s in scopes)
                    DropdownMenuItem(value: s, child: Text(s ?? tr('Tous les paquets'))),
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
          child: Text(tr('Annuler')),
        ),
        FilledButton(
          key: const Key('vex-save'),
          onPressed: _save,
          child: Text(tr('Enregistrer')),
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
            child: Text(tr('Déclarer via VEX…')),
          )
        else ...[
          Flexible(
            child: Text(
              tr('VEX : {status}{detail}', {'status': vexSummary( current), 'detail': current.impactStatement == null
                    ? ''
                    : ' (${current.impactStatement})'}),
              style: const TextStyle(fontSize: 12),
            ),
          ),
          TextButton(onPressed: edit, child: Text(tr('Modifier'))),
          TextButton(
            onPressed: () => controller.remove(current!),
            child: Text(tr('Retirer')),
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
    final picked = await FilePicker.pickFile(
      dialogTitle: tr('Importer un document VEX'),
      type: FileType.custom,
      allowedExtensions: ['json'],
    );
    final path = picked?.path;
    if (path == null) return;
    try {
      final doc = jsonDecode(await File(path).readAsString());
      final n = controller.merge(parseVex(doc as Map<String, dynamic>));
      if (!context.mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(tr('{count} déclaration(s) VEX importée(s)', {'count': n}))));
    } catch (e) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(tr('Document VEX illisible : {error}', {'error': '$e'}))));
    }
  }

  Future<void> _export(BuildContext context, String format) async {
    if (controller.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(tr('Aucune déclaration VEX à exporter.'))));
      return;
    }
    final path = await pickSavePath(
      dialogTitle: tr('Exporter les déclarations VEX'),
      fileName: switch (format) {
        'cyclonedx' => 'vex.cdx.json',
        'csaf' => 'vex.csaf.json',
        _ => 'vex.openvex.json',
      },
      type: FileType.custom,
      allowedExtensions: ['json'],
    );
    if (path == null) return;
    final doc = switch (format) {
      'cyclonedx' => controller.toCycloneDx('sbom-generator-gui', kGuiVersion),
      'csaf' => controller.toCsaf('sbom-generator-gui', kGuiVersion),
      _ => controller.toOpenVex('sbom-generator-gui', kGuiVersion),
    };
    await File(path).writeAsString('${encodeVex(doc)}\n');
    if (!context.mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(tr('VEX exporté → {path}', {'path': path}))));
  }

  @override
  Widget build(BuildContext context) {
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
                (isPlural(controller.statements.length) ? tr('VEX : {count} déclarations', {'count': controller.statements.length}) : tr('VEX : {count} déclaration', {'count': controller.statements.length})),
                style: const TextStyle(fontWeight: FontWeight.w600),
              ),
              if (!controller.isEmpty)
                FilterChip(
                  key: const Key('vex-hide'),
                  label: Text(tr('Masquer les CVE couvertes par un VEX ({count})', {'count': hiddenCount})),
                  selected: hide,
                  onSelected: onHideChanged,
                ),
              TextButton.icon(
                icon: const Icon(Icons.file_open_outlined, size: 18),
                label: Text(tr('Importer un VEX…')),
                onPressed: () => _import(context),
              ),
              PopupMenuButton<String>(
                tooltip: tr('Exporter'),
                onSelected: (format) => _export(context, format),
                itemBuilder: (_) => [
                  PopupMenuItem(value: 'openvex', child: Text(tr('OpenVEX (.json)'))),
                  PopupMenuItem(value: 'cyclonedx', child: Text(tr('CycloneDX VEX (.json)'))),
                  PopupMenuItem(value: 'csaf', child: Text(tr('CSAF 2.0 VEX (.json)'))),
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
                      Text(tr('Exporter')),
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
                  child: Text(tr('Gérer')),
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
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) => AlertDialog(
        title: Text(tr('Déclarations VEX')),
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
                    '${s.products.isEmpty ? tr('tous les paquets') : s.products.join(', ')}'
                    ' · ${vexSummary( s)}',
                  ),
                  trailing: IconButton(
                    tooltip: tr('Retirer'),
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
            child: Text(tr('Tout retirer')),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(tr('Fermer')),
          ),
        ],
      ),
    );
  }
}
