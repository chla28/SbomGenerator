// ─── Composants et helpers partagés entre grype_panel, trivy_panel et
// osv_panel : les trois onglets de scan de vulnérabilités affichent une
// table triable/filtrable/exportable sur le même modèle et dupliquaient
// jusqu'ici ce code presque à l'identique.

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/cve_date_filter.dart';

// ─── Couleurs de sévérité ───────────────────────────────────────────────────

/// Couleur de premier plan (texte/icône) associée à une sévérité de
/// vulnérabilité. Insensible à la casse ('Critical', 'CRITICAL', 'critical'
/// donnent le même résultat).
Color severityFg(String severity) => switch (severity.toLowerCase()) {
      'critical' => const Color(0xFFB71C1C),
      'high' => const Color(0xFFBF360C),
      'medium' => const Color(0xFFE65100),
      'low' => const Color(0xFF2E7D32),
      'negligible' => Colors.grey,
      _ => Colors.grey,
    };

/// Couleur de fond associée à une sévérité de vulnérabilité.
Color severityBg(String severity) => switch (severity.toLowerCase()) {
      'critical' => const Color(0xFFFFEBEE),
      'high' => const Color(0xFFFBE9E7),
      'medium' => const Color(0xFFFFF3E0),
      'low' => const Color(0xFFF1F8E9),
      'negligible' => const Color(0xFFF5F5F5),
      _ => const Color(0xFFF5F5F5),
    };

// ─── Export CSV ─────────────────────────────────────────────────────────────

/// Échappe une valeur pour l'écriture dans un fichier CSV (RFC 4180).
String csvEscape(String s) {
  if (s.contains(',') || s.contains('"') || s.contains('\n')) {
    return '"${s.replaceAll('"', '""')}"';
  }
  return s;
}

// ─── Bannière d'erreur ──────────────────────────────────────────────────────

class ErrorBanner extends StatelessWidget {
  final String message;
  const ErrorBanner({super.key, required this.message});

  @override
  Widget build(BuildContext context) => Container(
        color: Colors.red[50],
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Icon(Icons.error_outline, color: Colors.red, size: 18),
            const SizedBox(width: 8),
            Expanded(
              child: SelectableText(
                message,
                style: TextStyle(color: Colors.red[800], fontSize: 13),
                maxLines: 5,
              ),
            ),
          ],
        ),
      );
}

// ─── Vue JSON brut ────────────────────────────────────────────────────────

class JsonView extends StatelessWidget {
  final String json;
  const JsonView({super.key, required this.json});

  String _pretty() {
    try {
      return const JsonEncoder.withIndent('  ').convert(jsonDecode(json));
    } catch (_) {
      return json;
    }
  }

  @override
  Widget build(BuildContext context) {
    if (json.isEmpty) {
      return const Center(child: Text('Pas de sortie JSON.'));
    }
    final pretty = _pretty();
    return Stack(
      children: [
        Container(
          color: const Color(0xFF1E1E1E),
          padding: const EdgeInsets.all(12),
          child: SelectionArea(
            child: SingleChildScrollView(
              child: Text(
                pretty,
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
            message: 'Copier le JSON',
            child: IconButton(
              icon: const Icon(Icons.copy_outlined,
                  size: 18, color: Colors.white70),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: json));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('JSON copié'),
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

// ─── En-tête de colonne triable ─────────────────────────────────────────────

class SortHeader extends StatelessWidget {
  final String label;
  final bool active;
  final bool ascending;
  final VoidCallback onTap;
  final double? width;

  const SortHeader(this.label, this.active, this.ascending, this.onTap,
      {super.key, this.width});

  @override
  Widget build(BuildContext context) {
    final color =
        active ? Theme.of(context).colorScheme.primary : Colors.grey[600]!;
    Widget cell = InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(4),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 2, vertical: 2),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(label,
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: color)),
            if (active) ...[
              const SizedBox(width: 2),
              Icon(ascending ? Icons.arrow_upward : Icons.arrow_downward,
                  size: 11, color: color),
            ],
          ],
        ),
      ),
    );
    return width != null ? SizedBox(width: width, child: cell) : cell;
  }
}

// ─── Split-button pour sélection de fichier avec filtre ───────────────────

class SplitPickButton extends StatefulWidget {
  final String filterLabel;
  final VoidCallback onPickFiltered;
  final VoidCallback onPickAll;

  const SplitPickButton({
    super.key,
    required this.filterLabel,
    required this.onPickFiltered,
    required this.onPickAll,
  });

  @override
  State<SplitPickButton> createState() => _SplitPickButtonState();
}

class _SplitPickButtonState extends State<SplitPickButton> {
  final MenuController _menu = MenuController();

  @override
  Widget build(BuildContext context) {
    return MenuAnchor(
      controller: _menu,
      menuChildren: [
        MenuItemButton(
          leadingIcon: const Icon(Icons.filter_alt_outlined, size: 16),
          onPressed: () {
            _menu.close();
            widget.onPickFiltered();
          },
          child: Text('Type filtré (${widget.filterLabel})'),
        ),
        MenuItemButton(
          leadingIcon: const Icon(Icons.folder_open, size: 16),
          onPressed: () {
            _menu.close();
            widget.onPickAll();
          },
          child: const Text('Tous les fichiers'),
        ),
      ],
      builder: (context, controller, _) => OutlinedButton.icon(
        onPressed: controller.isOpen ? controller.close : controller.open,
        icon: const Icon(Icons.folder_open, size: 18),
        label: const Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('Choisir'),
            SizedBox(width: 4),
            Icon(Icons.arrow_drop_down, size: 16),
          ],
        ),
      ),
    );
  }
}

// ─── Barre de filtre par date CVE ───────────────────────────────────────────

class DateFilterBar extends StatelessWidget {
  final CveDateFilter filter;
  final void Function(CveDateFilter)? onChanged;
  final void Function(CveDateFilter)? onPropagate;

  const DateFilterBar({
    super.key,
    required this.filter,
    this.onChanged,
    this.onPropagate,
  });

  Future<void> _pickDate(
    BuildContext context,
    DateTime? current,
    void Function(DateTime?) onPicked,
  ) async {
    final now = DateTime.now();
    final picked = await showDatePicker(
      context: context,
      initialDate: current ?? now,
      firstDate: DateTime(1999),
      lastDate: now,
    );
    if (picked != null) onPicked(picked);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        border: Border(
          bottom: BorderSide(color: theme.dividerColor, width: 0.5),
        ),
      ),
      child: Row(
        children: [
          const Icon(Icons.calendar_today_outlined, size: 14),
          const SizedBox(width: 6),
          const Text('Date CVE :', style: TextStyle(fontSize: 11)),
          const SizedBox(width: 6),
          // Champ de date (published / modified / latest)
          SegmentedButton<CveDateField>(
            segments: const [
              ButtonSegment(
                  value: CveDateField.published,
                  label: Text('Publication', style: TextStyle(fontSize: 10))),
              ButtonSegment(
                  value: CveDateField.modified,
                  label:
                      Text('Modification', style: TextStyle(fontSize: 10))),
              ButtonSegment(
                  value: CveDateField.latest,
                  label: Text('La plus récente',
                      style: TextStyle(fontSize: 10))),
            ],
            selected: {filter.field},
            onSelectionChanged: (s) =>
                onChanged?.call(filter.copyWith(field: s.first)),
            style: ButtonStyle(
              visualDensity: VisualDensity.compact,
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              textStyle:
                  WidgetStateProperty.all(const TextStyle(fontSize: 10)),
            ),
          ),
          const SizedBox(width: 10),
          // Après le
          DateChip(
            label: filter.after == null
                ? 'Après le…'
                : 'Après : ${_fmtDate(filter.after!)}',
            active: filter.after != null,
            onTap: () => _pickDate(context, filter.after,
                (d) => onChanged?.call(filter.copyWith(after: d))),
            onClear: filter.after == null
                ? null
                : () => onChanged?.call(filter.copyWith(after: null)),
          ),
          const SizedBox(width: 4),
          // Avant le
          DateChip(
            label: filter.before == null
                ? 'Avant le…'
                : 'Avant : ${_fmtDate(filter.before!)}',
            active: filter.before != null,
            onTap: () => _pickDate(context, filter.before,
                (d) => onChanged?.call(filter.copyWith(before: d))),
            onClear: filter.before == null
                ? null
                : () => onChanged?.call(filter.copyWith(before: null)),
          ),
          const SizedBox(width: 10),
          // Inclure CVE sans date
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(
                width: 16,
                height: 16,
                child: Checkbox(
                  value: filter.includeUndated,
                  onChanged: (v) => onChanged
                      ?.call(filter.copyWith(includeUndated: v ?? false)),
                  materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  visualDensity: VisualDensity.compact,
                ),
              ),
              const SizedBox(width: 4),
              const Text('Sans date', style: TextStyle(fontSize: 11)),
            ],
          ),
          const Spacer(),
          // Bouton Propager
          if (onPropagate != null)
            TextButton.icon(
              icon: const Icon(Icons.sync_alt, size: 14),
              label: const Text('Propager aux autres onglets',
                  style: TextStyle(fontSize: 11)),
              style: TextButton.styleFrom(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              onPressed: () => onPropagate!(filter),
            ),
        ],
      ),
    );
  }

  static String _fmtDate(DateTime d) =>
      '${d.year.toString().padLeft(4, '0')}-'
      '${d.month.toString().padLeft(2, '0')}-'
      '${d.day.toString().padLeft(2, '0')}';
}

class DateChip extends StatelessWidget {
  final String label;
  final bool active;
  final VoidCallback onTap;
  final VoidCallback? onClear;

  const DateChip({
    super.key,
    required this.label,
    required this.active,
    required this.onTap,
    this.onClear,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: active
              ? theme.colorScheme.primaryContainer
              : theme.colorScheme.surfaceContainerHigh,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: active
                ? theme.colorScheme.primary
                : theme.colorScheme.outline,
            width: 0.8,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              label,
              style: TextStyle(
                fontSize: 11,
                color: active
                    ? theme.colorScheme.onPrimaryContainer
                    : theme.colorScheme.onSurfaceVariant,
              ),
            ),
            if (onClear != null) ...[
              const SizedBox(width: 4),
              InkWell(
                onTap: onClear,
                child: Icon(Icons.close,
                    size: 12, color: theme.colorScheme.onPrimaryContainer),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
