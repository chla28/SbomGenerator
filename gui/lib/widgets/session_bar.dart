import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../l10n/l10n.dart';
import '../models/scan_session.dart';
import '../services/session_store.dart';
import 'vuln_shared.dart' show severityFg;

/// Liens entre le tableau de bord et l'état des résultats (porté par
/// `ResultsPanel`) : session courante, chargement, comparaison, historique.
class SessionActions {
  /// Session construite à partir des résultats courants.
  final ScanSession Function() current;

  /// Charge une session dans le tableau de bord.
  final void Function(ScanSession) onLoad;

  /// Session de référence de la tendance (`null` = pas de comparaison).
  final ScanSession? baseline;
  final void Function(ScanSession?) onBaseline;

  /// Historique automatique ; `null` = désactivé (tests).
  final SessionStore? store;

  const SessionActions({
    required this.current,
    required this.onLoad,
    required this.baseline,
    required this.onBaseline,
    this.store,
  });
}

String _day(DateTime d) {
  final l = d.toLocal();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${l.year}-${two(l.month)}-${two(l.day)} ${two(l.hour)}:${two(l.minute)}';
}

/// Barre d'actions de session + carte de tendance, en tête du tableau de bord.
class SessionBar extends StatelessWidget {
  final SessionActions actions;
  const SessionBar({super.key, required this.actions});

  Future<void> _save(BuildContext context) async {
    final l = context.l10n;
    final session = actions.current();
    if (session.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(l.sessNothingToSave)));
      return;
    }
    final path = await FilePicker.saveFile(
      dialogTitle: l.sessDialogSave,
      fileName: SessionStore.fileNameFor(session),
      type: FileType.custom,
      allowedExtensions: ['json'],
    );
    if (path == null) return;
    await File(path).writeAsString(session.encode());
    if (!context.mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(l.sessSaved(path))));
  }

  Future<void> _open(BuildContext context) async {
    final l = context.l10n;
    final picked = await FilePicker.pickFiles(
      dialogTitle: l.sessDialogOpen,
      type: FileType.custom,
      allowedExtensions: ['json'],
    );
    final path = picked?.files.single.path;
    if (path == null) return;
    try {
      final s = ScanSession.decode(await File(path).readAsString());
      actions.onLoad(s);
      if (!context.mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(l.sessLoaded(_day(s.savedAt)))));
    } catch (e) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(l.sessInvalid('$e'))));
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final baseline = actions.baseline;
    final store = actions.store;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            OutlinedButton.icon(
              key: const Key('session-save'),
              icon: const Icon(Icons.save_outlined, size: 18),
              label: Text(l.sessSave),
              onPressed: () => _save(context),
            ),
            OutlinedButton.icon(
              key: const Key('session-open'),
              icon: const Icon(Icons.folder_open, size: 18),
              label: Text(l.sessOpen),
              onPressed: () => _open(context),
            ),
            if (store != null)
              OutlinedButton.icon(
                key: const Key('session-history'),
                icon: const Icon(Icons.history, size: 18),
                label: Text(l.sessHistory),
                onPressed: () => showDialog<void>(
                  context: context,
                  builder: (_) => SessionHistoryDialog(
                    store: store,
                    onOpen: actions.onLoad,
                    onCompare: actions.onBaseline,
                  ),
                ),
              ),
          ],
        ),
        if (baseline != null) ...[
          const SizedBox(height: 12),
          TrendCard(
            baseline: baseline,
            current: actions.current(),
            onClear: () => actions.onBaseline(null),
          ),
        ],
      ],
    );
  }
}

/// Évolution du nombre de CVE entre une session de référence et les résultats
/// courants.
class TrendCard extends StatelessWidget {
  final ScanSession baseline;
  final ScanSession current;
  final VoidCallback onClear;
  const TrendCard({
    super.key,
    required this.baseline,
    required this.current,
    required this.onClear,
  });

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final t = SessionTrend.compare(baseline, current);
    final same = t.added.isEmpty && t.removed.isEmpty;
    final newOnes = t.added.entries.toList()
      ..sort((a, b) => _rank(b.value).compareTo(_rank(a.value)));
    return Card(
      key: const Key('trend-card'),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.trending_up, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    l.sessTrendTitle(_day(baseline.savedAt)),
                    style: const TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 13,
                    ),
                  ),
                ),
                TextButton(onPressed: onClear, child: Text(l.sessTrendClear)),
              ],
            ),
            const SizedBox(height: 4),
            if (same)
              Text(l.sessTrendNone)
            else
              Wrap(
                spacing: 16,
                runSpacing: 4,
                children: [
                  Text(
                    l.sessTrendNew(t.added.length),
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      color: t.added.isEmpty ? null : severityFg('high'),
                    ),
                  ),
                  Text(
                    l.sessTrendFixed(t.removed.length),
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      color: t.removed.isEmpty ? null : severityFg('low'),
                    ),
                  ),
                  Text(l.sessTrendSame(t.unchanged)),
                  Text(l.sessTrendTotals(t.beforeTotal, t.afterTotal)),
                ],
              ),
            if (newOnes.isNotEmpty) ...[
              const SizedBox(height: 8),
              Text(
                l.sessTrendNewList,
                style: Theme.of(context).textTheme.bodySmall,
              ),
              Wrap(
                spacing: 6,
                runSpacing: 2,
                children: [
                  for (final e in newOnes.take(12))
                    Chip(
                      visualDensity: VisualDensity.compact,
                      label: Text(
                        '${SessionTrend.idOf(e.key)} · '
                        '${SessionTrend.packageOf(e.key)}',
                        style: TextStyle(
                          fontSize: 11,
                          color: severityFg(e.value),
                        ),
                      ),
                    ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  static int _rank(String s) => switch (s) {
    'critical' => 4,
    'high' => 3,
    'medium' => 2,
    'low' => 1,
    _ => 0,
  };
}

/// Historique des analyses : ouvrir, comparer, supprimer.
class SessionHistoryDialog extends StatefulWidget {
  final SessionStore store;
  final void Function(ScanSession) onOpen;
  final void Function(ScanSession) onCompare;

  /// Liste initiale déjà chargée (tests) ; sinon lue dans [store].
  final Future<List<SessionEntry>>? initialEntries;
  const SessionHistoryDialog({
    super.key,
    required this.store,
    required this.onOpen,
    required this.onCompare,
    this.initialEntries,
  });

  @override
  State<SessionHistoryDialog> createState() => _SessionHistoryDialogState();
}

class _SessionHistoryDialogState extends State<SessionHistoryDialog> {
  late Future<List<SessionEntry>> _entries =
      widget.initialEntries ?? widget.store.list();

  void _reload() => setState(() => _entries = widget.store.list());

  Future<void> _clear() async {
    final l = context.l10n;
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        content: Text(l.sessClearConfirm),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(c, false),
            child: Text(l.homeCancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(c, true),
            child: Text(l.sessClearHistory),
          ),
        ],
      ),
    );
    if (ok != true) return;
    await widget.store.clear();
    if (mounted) _reload();
  }

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    return AlertDialog(
      title: Row(
        children: [
          const Icon(Icons.history, size: 20),
          const SizedBox(width: 8),
          Text(l.sessHistoryTitle),
        ],
      ),
      content: SizedBox(
        width: 560,
        height: 380,
        child: FutureBuilder<List<SessionEntry>>(
          future: _entries,
          builder: (context, snap) {
            if (!snap.hasData) {
              return const Center(child: CircularProgressIndicator());
            }
            final list = snap.data!;
            if (list.isEmpty) {
              return Center(child: Text(l.sessHistoryEmpty));
            }
            return ListView(
              children: [
                for (final e in list)
                  ListTile(
                    dense: true,
                    title: Text(
                      e.session.targets.isEmpty
                          ? '—'
                          : e.session.targets.join(', '),
                      overflow: TextOverflow.ellipsis,
                    ),
                    subtitle: Text(
                      '${_day(e.session.savedAt)} · '
                      '${l.sessHistoryItem(e.session.uniqueCveCount)}',
                    ),
                    trailing: Wrap(
                      children: [
                        TextButton(
                          onPressed: () {
                            widget.onOpen(e.session);
                            Navigator.pop(context);
                          },
                          child: Text(l.sessOpenAction),
                        ),
                        TextButton(
                          onPressed: () {
                            widget.onCompare(e.session);
                            Navigator.pop(context);
                          },
                          child: Text(l.sessCompareAction),
                        ),
                        IconButton(
                          tooltip: l.sessDeleteAction,
                          icon: const Icon(Icons.delete_outline, size: 18),
                          onPressed: () async {
                            await widget.store.delete(e.file);
                            if (mounted) _reload();
                          },
                        ),
                      ],
                    ),
                  ),
              ],
            );
          },
        ),
      ),
      actions: [
        TextButton(onPressed: _clear, child: Text(l.sessClearHistory)),
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(l.commonClose),
        ),
      ],
    );
  }
}
