import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../i18n.dart';
import '../services/save_dialog.dart';
import '../models/remediation.dart';
import 'grype_panel.dart';
import 'osv_panel.dart';
import 'trivy_panel.dart';
import 'vuln_shared.dart' show csvEscape, severityFg;

/// Entrées de remédiation depuis les résultats des trois scanners.
List<RemediationInput> remediationInputs({
  List<GrypeVuln>? grype,
  List<OsvVuln>? osv,
  List<TrivyVuln>? trivy,
}) => [
  for (final v in grype ?? const <GrypeVuln>[])
    (
      scanner: 'Grype',
      id: v.id,
      severity: v.severity,
      packageName: v.packageName,
      installedVersion: v.installedVersion,
      fixedVersion: v.fixedVersion,
    ),
  for (final v in osv ?? const <OsvVuln>[])
    (
      scanner: 'OSV-Scanner',
      id: v.id,
      severity: v.severity,
      packageName: v.packageName,
      installedVersion: v.installedVersion,
      fixedVersion: v.fixedVersion,
    ),
  for (final v in trivy ?? const <TrivyVuln>[])
    (
      scanner: 'Trivy',
      id: v.id,
      severity: v.severity,
      packageName: v.packageName,
      installedVersion: v.installedVersion,
      fixedVersion: v.fixedVersion,
    ),
];

String _gain(double g) => g.toStringAsFixed(g >= 100 ? 0 : 1);

/// Plan de remédiation en CSV (une ligne par paquet).
String remediationCsv(List<RemediationItem> items, String header) {
  final buf = StringBuffer()..writeln(header);
  for (final i in items) {
    buf.writeln(
      [
        i.packageName,
        i.installedVersion,
        i.targetVersion ?? '',
        '${i.fixed.length}',
        '${i.kevFixed}',
        '${i.unfixed.length}',
        _gain(i.gain),
      ].map(csvEscape).join(','),
    );
  }
  return buf.toString();
}

/// Plan de remédiation en texte (une ligne par paquet) — pour le presse-papiers.
String remediationText(List<RemediationItem> items) => [
  for (final i in items)
    if (i.targetVersion != null)
      '${i.packageName} ${i.installedVersion} -> ${i.targetVersion}  '
          '(${i.fixed.map((c) => c.id).join(', ')})',
].join('\n');

/// Section « Remédiation » du tableau de bord : par paquet, la mise à jour qui
/// corrige le plus de risque.
class RemediationSection extends StatefulWidget {
  final List<RemediationItem> items;
  const RemediationSection({super.key, required this.items});

  @override
  State<RemediationSection> createState() => _RemediationSectionState();
}

class _RemediationSectionState extends State<RemediationSection> {
  static const _collapsedCount = 8;
  bool _showAll = false;

  Future<void> _exportCsv() async {
    final csv = remediationCsv(widget.items, tr('paquet,version installée,version cible,CVE corrigées,dont KEV,CVE sans correctif,gain de risque'));
    final path = await pickSavePath(
      dialogTitle: tr('Exporter le plan de remédiation'),
      fileName: 'remediation.csv',
      type: FileType.custom,
      allowedExtensions: ['csv'],
    );
    if (path == null) return;
    await File(path).writeAsString(csv);
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(tr('Plan de remédiation exporté → {path}', {'path': path}))));
  }

  Future<void> _copy() async {
    await Clipboard.setData(ClipboardData(text: remediationText(widget.items)));
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(tr('Plan de remédiation copié'))));
  }

  @override
  Widget build(BuildContext context) {
    final items = widget.items;
    if (items.isEmpty) return const SizedBox.shrink();
    final shown = _showAll ? items : items.take(_collapsedCount).toList();
    return Card(
      key: const Key('remediation-section'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.build_circle_outlined, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    tr('Remédiation : quoi mettre à jour'),
                    style: const TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 13,
                    ),
                  ),
                ),
                IconButton(
                  tooltip: tr('Copier la liste'),
                  icon: const Icon(Icons.copy, size: 18),
                  onPressed: _copy,
                ),
                IconButton(
                  tooltip: tr('Exporter en CSV'),
                  icon: const Icon(Icons.download_outlined, size: 18),
                  onPressed: _exportCsv,
                ),
              ],
            ),
            Text(
              (isPlural(items.length) ? tr('{count} paquets à mettre à jour, classés par gain de risque (sévérité, exploitation active KEV, EPSS).', {'count': items.length}) : tr('1 paquet à mettre à jour, classés par gain de risque (sévérité, exploitation active KEV, EPSS).')),
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            for (final i in shown) _RemediationTile(item: i),
            if (items.length > _collapsedCount)
              Align(
                alignment: Alignment.centerLeft,
                child: TextButton(
                  onPressed: () => setState(() => _showAll = !_showAll),
                  child: Text(
                    _showAll ? tr('Réduire la liste') : tr('Afficher les {count} paquets', {'count': items.length}),
                  ),
                ),
              ),
            const SizedBox(height: 4),
            Text(
              tr('Heuristique : la version cible est la plus petite qui corrige toutes les CVE corrigeables du paquet ; vérifiez-la avec votre gestionnaire de paquets.'),
              style: Theme.of(
                context,
              ).textTheme.bodySmall?.copyWith(fontStyle: FontStyle.italic),
            ),
          ],
        ),
      ),
    );
  }
}

class _RemediationTile extends StatelessWidget {
  /// CVE listées au dépliage d'un paquet (le reste est résumé).
  static const _maxListed = 200;

  final RemediationItem item;
  const _RemediationTile({required this.item});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final target = item.targetVersion;
    final title = target == null
        ? tr('{pkg} {from} — aucun correctif connu', {'pkg': item.packageName, 'from': item.installedVersion})
        : tr('{pkg} {from} → {to}', {'pkg': item.packageName, 'from': item.installedVersion, 'to': target});
    final details = <String>[
      if (item.fixed.isNotEmpty) (isPlural(item.fixed.length) ? tr('{count} CVE corrigées', {'count': item.fixed.length}) : tr('1 CVE corrigée')),
      if (item.kevFixed > 0) tr('{count} exploitée(s) (KEV)', {'count': item.kevFixed}),
      if (item.unfixed.isNotEmpty) (isPlural(item.unfixed.length) ? tr('{count} CVE resteront sans correctif', {'count': item.unfixed.length}) : tr('1 CVE restera sans correctif')),
      if (item.fixed.isNotEmpty) tr('Gain de risque : {gain}', {'gain': _gain(item.gain)}),
    ];
    final all = [...item.fixed, ...item.unfixed];
    return ExpansionTile(
      key: ValueKey('remed-${item.packageName}-${item.installedVersion}'),
      tilePadding: EdgeInsets.zero,
      dense: true,
      leading: Icon(
        target == null ? Icons.block : Icons.upgrade,
        size: 20,
        color: severityFg(item.worstFixedSeverity),
      ),
      title: Text(
        title,
        style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
      ),
      subtitle: Text(details.join(' · '), style: theme.textTheme.bodySmall),
      children: [
        // Un seul widget de texte (et non un par CVE) : un paquet du noyau peut
        // porter des milliers de CVE, et un widget sélectionnable par ligne
        // figeait l'interface au dépliage.
        Align(
          alignment: Alignment.centerLeft,
          child: Padding(
            padding: const EdgeInsets.only(left: 36, bottom: 6),
            child: SelectionArea(
              child: Text.rich(
                TextSpan(
                  children: [
                    for (final c in all.take(_maxListed)) ...[
                      TextSpan(
                        text: '${c.severity.toUpperCase()}  ',
                        style: TextStyle(
                          color: severityFg(c.severity),
                          fontWeight: FontWeight.bold,
                          fontSize: 11,
                        ),
                      ),
                      TextSpan(
                        text:
                            '${c.id}${c.inKev ? '  KEV' : ''}'
                            '${c.hasFix ? '' : '  ✗'}\n',
                        style: const TextStyle(fontSize: 12),
                      ),
                    ],
                    if (all.length > _maxListed)
                      TextSpan(
                        text: tr('… et {count} autre(s) CVE (voir l\'export CSV ou le détail ci-dessus)', {'count': all.length - _maxListed}),
                        style: theme.textTheme.bodySmall,
                      ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}
