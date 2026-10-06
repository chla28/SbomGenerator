import 'dart:async';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../l10n/l10n.dart';
import '../models/sbom_result.dart';
import '../services/scan_job_runner.dart';
import '../services/scan_queue.dart';
import '../services/settings_service.dart';

/// Onglet « Tâches » : file d'attente d'analyses de vulnérabilités, exécutées
/// une à une, annulables et relançables ; les résultats alimentent le tableau
/// de bord.
class TasksPanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  final void Function(ScanJobResult) onResult;

  /// File fournie par l'appelant (tests) ; sinon créée avec les vrais scanners.
  final ScanQueue? queue;

  const TasksPanel({
    super.key,
    required this.outputFiles,
    required this.onResult,
    this.queue,
  });

  @override
  State<TasksPanel> createState() => _TasksPanelState();
}

class _TasksPanelState extends State<TasksPanel>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;

  late final ScanQueue _queue;
  late final bool _ownsQueue;
  String? _target;
  final Set<String> _selected = {...kScanners};
  String? _message;
  Timer? _tick;

  @override
  void initState() {
    super.initState();
    _ownsQueue = widget.queue == null;
    _queue =
        widget.queue ??
        ScanQueue(
          makeScanJobExecutor(
            onResult: widget.onResult,
            enrichOnline: SettingsService.loadScanEnrichOnline,
          ),
        );
    _queue.addListener(_onQueue);
    _autoTarget();
  }

  void _onQueue() {
    if (!mounted) return;
    setState(() {});
    // Rafraîchit la durée des analyses en cours.
    _tick?.cancel();
    if (_queue.isBusy) {
      _tick = Timer.periodic(const Duration(seconds: 1), (_) {
        if (mounted) setState(() {});
      });
    }
  }

  @override
  void didUpdateWidget(TasksPanel old) {
    super.didUpdateWidget(old);
    if (widget.outputFiles != old.outputFiles) _autoTarget();
  }

  void _autoTarget() {
    if (_target != null) return;
    final f = widget.outputFiles
        .where(
          (f) =>
              f.path.endsWith('.cdx.json') ||
              f.path.endsWith('.spdx.json') ||
              f.path.endsWith('.json') ||
              f.path.endsWith('.jsonld'),
        )
        .firstOrNull;
    if (f != null) _target = f.path;
  }

  @override
  void dispose() {
    _tick?.cancel();
    _queue.removeListener(_onQueue);
    if (_ownsQueue) {
      _queue.cancelAll();
      _queue.dispose();
    }
    super.dispose();
  }

  Future<void> _browse() async {
    final r = await FilePicker.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['json', 'jsonld'],
      dialogTitle: context.l10n.tasksPickDialog,
    );
    final path = r?.files.single.path;
    if (path != null) setState(() => _target = path);
  }

  void _enqueue() {
    final l = context.l10n;
    if (_target == null) {
      setState(() => _message = l.tasksNeedTarget);
      return;
    }
    if (_selected.isEmpty) {
      setState(() => _message = l.tasksNeedScanner);
      return;
    }
    setState(() => _message = null);
    for (final s in kScanners) {
      if (_selected.contains(s)) _queue.add(s, _target!);
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final l = context.l10n;
    final theme = Theme.of(context);
    final jobs = _queue.jobs;
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(l.tasksIntro, style: theme.textTheme.bodySmall),
          const SizedBox(height: 12),
          Row(
            children: [
              Text(
                '${l.tasksTargetLabel} : ',
                style: const TextStyle(fontWeight: FontWeight.w600),
              ),
              Expanded(
                child: Text(
                  _target ?? l.tasksTargetNone,
                  overflow: TextOverflow.ellipsis,
                  key: const Key('tasks-target'),
                ),
              ),
              TextButton.icon(
                icon: const Icon(Icons.folder_open, size: 18),
                label: Text(l.tasksBrowse),
                onPressed: _browse,
              ),
            ],
          ),
          Wrap(
            spacing: 12,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              for (final s in kScanners)
                FilterChip(
                  key: Key('tasks-scanner-$s'),
                  label: Text(s),
                  selected: _selected.contains(s),
                  onSelected: (v) => setState(
                    () => v ? _selected.add(s) : _selected.remove(s),
                  ),
                ),
              FilledButton.icon(
                key: const Key('tasks-enqueue'),
                icon: const Icon(Icons.playlist_add, size: 18),
                label: Text(l.tasksEnqueue),
                onPressed: _enqueue,
              ),
            ],
          ),
          if (_message != null)
            Padding(
              padding: const EdgeInsets.only(top: 6),
              child: Text(
                _message!,
                style: TextStyle(color: theme.colorScheme.error),
              ),
            ),
          const Divider(height: 24),
          Row(
            children: [
              TextButton.icon(
                icon: const Icon(Icons.stop_circle_outlined, size: 18),
                label: Text(l.tasksCancelAll),
                onPressed: _queue.isBusy ? _queue.cancelAll : null,
              ),
              TextButton.icon(
                icon: const Icon(Icons.clear_all, size: 18),
                label: Text(l.tasksClearFinished),
                onPressed: jobs.any((j) => j.isFinished)
                    ? _queue.clearFinished
                    : null,
              ),
            ],
          ),
          Expanded(
            child: jobs.isEmpty
                ? Center(child: Text(l.tasksEmpty))
                : ListView(
                    children: [
                      for (final j in jobs)
                        _JobTile(
                          key: ValueKey('job-${j.id}'),
                          job: j,
                          queue: _queue,
                        ),
                    ],
                  ),
          ),
        ],
      ),
    );
  }
}

class _JobTile extends StatelessWidget {
  final ScanJob job;
  final ScanQueue queue;
  const _JobTile({super.key, required this.job, required this.queue});

  @override
  Widget build(BuildContext context) {
    final l = context.l10n;
    final scheme = Theme.of(context).colorScheme;
    final name = job.target.split(RegExp(r'[/\\]')).last;
    final secs = job.duration?.inSeconds;
    final (icon, color, text) = switch (job.status) {
      ScanJobStatus.queued => (
        Icons.schedule,
        scheme.outline,
        l.tasksStatusQueued,
      ),
      ScanJobStatus.running => (
        Icons.sync,
        scheme.primary,
        l.tasksStatusRunning,
      ),
      ScanJobStatus.done => (
        Icons.check_circle_outline,
        Colors.green.shade700,
        l.tasksStatusDone(job.findings ?? 0),
      ),
      ScanJobStatus.failed => (
        Icons.error_outline,
        scheme.error,
        l.tasksStatusFailed(job.error ?? ''),
      ),
      ScanJobStatus.cancelled => (
        Icons.cancel_outlined,
        scheme.outline,
        l.tasksStatusCancelled,
      ),
    };
    return ListTile(
      dense: true,
      leading: job.status == ScanJobStatus.running
          ? const SizedBox(
              width: 20,
              height: 20,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : Icon(icon, color: color),
      title: Text('${job.scanner} · $name'),
      subtitle: Text(
        '$text${secs != null && job.status != ScanJobStatus.queued ? ' · ${l.tasksDuration(secs)}' : ''}',
        style: TextStyle(color: color),
      ),
      trailing: Wrap(
        children: [
          if (job.status == ScanJobStatus.queued ||
              job.status == ScanJobStatus.running)
            IconButton(
              tooltip: l.tasksCancel,
              icon: const Icon(Icons.stop_circle_outlined),
              onPressed: () => queue.cancel(job.id),
            ),
          if (job.status == ScanJobStatus.failed ||
              job.status == ScanJobStatus.cancelled)
            IconButton(
              tooltip: l.tasksRetry,
              icon: const Icon(Icons.replay),
              onPressed: () => queue.retry(job.id),
            ),
          if (job.status != ScanJobStatus.running)
            IconButton(
              tooltip: l.tasksRemove,
              icon: const Icon(Icons.close),
              onPressed: () => queue.remove(job.id),
            ),
        ],
      ),
    );
  }
}
