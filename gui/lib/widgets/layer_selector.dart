import 'package:flutter/material.dart';

import '../models/layer_nav.dart';
import '../l10n/l10n.dart';

/// Menu « SBOM global / couche N » d'un jeu de SBOM produit avec
/// `--per-layer`, et bandeau descriptif de la couche affichée.
class LayerSelector extends StatelessWidget {
  final LayerNav nav;
  final String currentPath;
  final LayerDocInfo info;

  /// Libellés des couches lus dans le SBOM global (instruction, compteurs) ;
  /// conservés d'un fichier à l'autre par l'appelant.
  final Map<int, String> layerLabels;
  final ValueChanged<String> onOpen;

  const LayerSelector({
    super.key,
    required this.nav,
    required this.currentPath,
    required this.info,
    required this.layerLabels,
    required this.onOpen,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final total = nav.layers.isEmpty ? 0 : nav.layers.last.index;
    final items = <DropdownMenuItem<String>>[
      if (nav.globalPath != null)
        DropdownMenuItem(
          value: nav.globalPath,
          child: Text(
            context.l10n.layerGlobalSbom,
            style: const TextStyle(fontSize: 12),
          ),
        ),
      for (final l in nav.layers)
        DropdownMenuItem(
          value: l.path,
          child: Text(
            context.l10n.layerOption(l.index, total, l.shortDigest) +
                (layerLabels[l.index] != null
                    ? '  ${layerLabels[l.index]}'
                    : ''),
            style: const TextStyle(fontSize: 12),
            overflow: TextOverflow.ellipsis,
          ),
        ),
    ];
    final value = items.any((i) => i.value == currentPath) ? currentPath : null;

    return Container(
      width: double.infinity,
      color: theme.colorScheme.tertiaryContainer.withValues(alpha: 0.35),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                Icons.layers_outlined,
                size: 16,
                color: theme.colorScheme.tertiary,
              ),
              const SizedBox(width: 6),
              Text(
                context.l10n.layerCount(nav.layers.length),
                style: const TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: DropdownButton<String>(
                  key: const Key('layer-selector'),
                  value: value,
                  isExpanded: true,
                  isDense: true,
                  underline: const SizedBox.shrink(),
                  items: items,
                  onChanged: (p) {
                    if (p != null && p != currentPath) onOpen(p);
                  },
                ),
              ),
              if (info.removed.isNotEmpty)
                Tooltip(
                  message: info.removed.join('\n'),
                  child: Chip(
                    visualDensity: VisualDensity.compact,
                    label: Text(
                      context.l10n.layerRemovedChip(info.removed.length),
                      style: const TextStyle(fontSize: 11),
                    ),
                    avatar: const Icon(Icons.remove_circle_outline, size: 14),
                  ),
                ),
            ],
          ),
          for (final line in info.lines)
            Text(
              line,
              style: TextStyle(
                fontSize: 11,
                color: theme.colorScheme.onSurface.withValues(alpha: 0.75),
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
        ],
      ),
    );
  }
}
