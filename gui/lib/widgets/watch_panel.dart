import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../i18n.dart';
import '../models/sbom_result.dart';
import '../models/watch_history.dart';
import '../services/sbom_runner.dart';

/// Onglet « Suivi » : évolution des CVE relevées par `watch` et vérification
/// de la signature cosign d'un SBOM.
class WatchPanel extends StatefulWidget {
  final List<OutputFile> outputFiles;

  /// Dossier d'état ouvert d'emblée (sinon : à choisir).
  final String? initialDir;

  /// Sélecteur de dossier (injectable pour les tests).
  final Future<String?> Function()? pickDirectory;

  const WatchPanel({
    super.key,
    this.outputFiles = const [],
    this.initialDir,
    this.pickDirectory,
  });

  @override
  State<WatchPanel> createState() => _WatchPanelState();
}

class _WatchPanelState extends State<WatchPanel>
    with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;

  String? _dir;
  List<SbomHistory> _histories = const [];

  final _sbomCtrl = TextEditingController();
  final _bundleCtrl = TextEditingController();
  final _keyCtrl = TextEditingController();
  final _identityCtrl = TextEditingController();
  final _issuerCtrl = TextEditingController();
  final _runner = SbomRunner();
  final _log = <String>[];
  bool _verifying = false;
  int? _exitCode;

  @override
  void initState() {
    super.initState();
    final first = widget.outputFiles
        .where((f) => f.path.endsWith('.json') || f.path.endsWith('.jsonld'))
        .firstOrNull;
    if (first != null) _sbomCtrl.text = first.path;
    if (widget.initialDir != null) _load(widget.initialDir!);
  }

  @override
  void dispose() {
    for (final c in [
      _sbomCtrl,
      _bundleCtrl,
      _keyCtrl,
      _identityCtrl,
      _issuerCtrl,
    ]) {
      c.dispose();
    }
    _runner.kill();
    super.dispose();
  }

  void _load(String dir) {
    setState(() {
      _dir = dir;
      _histories = loadHistories(Directory(dir));
    });
  }

  Future<void> _pickDir() async {
    final pick =
        widget.pickDirectory ??
        () => FilePicker.getDirectoryPath(
          dialogTitle: tr('Dossier d\'état de watch'),
        );
    final dir = await pick();
    if (dir != null) _load(dir);
  }

  Future<void> _pickInto(TextEditingController c, String title) async {
    final f = await FilePicker.pickFile(dialogTitle: title);
    if (f?.path != null) setState(() => c.text = f!.path!);
  }

  bool get _canVerify =>
      !_verifying &&
      _sbomCtrl.text.trim().isNotEmpty &&
      (_keyCtrl.text.trim().isNotEmpty ||
          (_identityCtrl.text.trim().isNotEmpty &&
              _issuerCtrl.text.trim().isNotEmpty));

  Future<void> _verify() async {
    setState(() {
      _verifying = true;
      _exitCode = null;
      _log.clear();
    });
    final args = verifyArgs(
      sbom: _sbomCtrl.text.trim(),
      bundle: _bundleCtrl.text.trim(),
      key: _keyCtrl.text.trim(),
      identity: _identityCtrl.text.trim(),
      issuer: _issuerCtrl.text.trim(),
    );
    await for (final e in _runner.run(args: args)) {
      if (!mounted) return;
      if (e is SbomLogEvent) {
        setState(() => _log.add(e.line));
      } else if (e is SbomDoneEvent) {
        setState(() {
          _verifying = false;
          _exitCode = e.exitCode;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final theme = Theme.of(context);
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        Row(
          children: [
            OutlinedButton.icon(
              key: const Key('watch-pick-dir'),
              icon: const Icon(Icons.folder_open, size: 16),
              label: Text(tr('Dossier d\'état…')),
              onPressed: _pickDir,
            ),
            const SizedBox(width: 8),
            if (_dir != null) ...[
              IconButton(
                tooltip: tr('Actualiser'),
                icon: const Icon(Icons.refresh, size: 18),
                onPressed: () => _load(_dir!),
              ),
              Expanded(
                child: Text(
                  _dir!,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall,
                ),
              ),
            ],
          ],
        ),
        const SizedBox(height: 8),
        if (_dir == null)
          Text(
            tr(
              'Choisissez le dossier --state-dir utilisé par « sbom_generator watch » pour voir l\'évolution des CVE.',
            ),
            key: const Key('watch-hint'),
          )
        else if (_histories.isEmpty)
          Text(
            tr(
              'Aucun historique dans ce dossier (lancer « watch » au moins une fois).',
            ),
            key: const Key('watch-empty'),
          )
        else
          for (final h in _histories) _HistoryCard(history: h),
        const Divider(height: 32),
        Text(
          tr('Vérifier la signature d\'un SBOM (cosign)'),
          style: theme.textTheme.titleSmall,
        ),
        const SizedBox(height: 8),
        _field(
          key: const Key('verify-sbom'),
          ctrl: _sbomCtrl,
          label: tr('SBOM'),
          onPick: () => _pickInto(_sbomCtrl, tr('Choisir le SBOM')),
        ),
        _field(
          ctrl: _bundleCtrl,
          label: tr('Bundle (défaut : <sbom>.bundle)'),
          onPick: () => _pickInto(_bundleCtrl, tr('Choisir le bundle')),
        ),
        _field(
          key: const Key('verify-key'),
          ctrl: _keyCtrl,
          label: tr('Clé publique cosign'),
          onPick: () => _pickInto(_keyCtrl, tr('Choisir la clé publique')),
        ),
        _field(
          key: const Key('verify-identity'),
          ctrl: _identityCtrl,
          label: tr('… ou identité du certificat'),
        ),
        _field(
          key: const Key('verify-issuer'),
          ctrl: _issuerCtrl,
          label: tr('… et émetteur OIDC'),
        ),
        Align(
          alignment: Alignment.centerLeft,
          child: FilledButton.icon(
            key: const Key('verify-run'),
            icon: const Icon(Icons.verified_outlined, size: 16),
            label: Text(tr('Vérifier')),
            onPressed: _canVerify ? _verify : null,
          ),
        ),
        if (_exitCode != null) _Verdict(code: _exitCode!),
        if (_log.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: SelectableText(
              _log.join('\n'),
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ),
      ],
    );
  }

  Widget _field({
    Key? key,
    required TextEditingController ctrl,
    required String label,
    VoidCallback? onPick,
  }) => Padding(
    padding: const EdgeInsets.only(bottom: 8),
    child: TextField(
      key: key,
      controller: ctrl,
      onChanged: (_) => setState(() {}),
      decoration: InputDecoration(
        labelText: label,
        isDense: true,
        border: const OutlineInputBorder(),
        suffixIcon: onPick == null
            ? null
            : IconButton(
                icon: const Icon(Icons.folder_open, size: 18),
                onPressed: onPick,
              ),
      ),
    ),
  );
}

class _Verdict extends StatelessWidget {
  final int code;
  const _Verdict({required this.code});

  @override
  Widget build(BuildContext context) {
    final (label, color, icon) = switch (code) {
      0 => (tr('Signature valide'), Colors.green, Icons.check_circle),
      2 => (tr('Signature INVALIDE'), Colors.red, Icons.cancel),
      _ => (tr('Vérification impossible'), Colors.orange, Icons.error_outline),
    };
    return Padding(
      key: const Key('verify-verdict'),
      padding: const EdgeInsets.only(top: 8),
      child: Row(
        children: [
          Icon(icon, color: color),
          const SizedBox(width: 6),
          Text(
            label,
            style: TextStyle(color: color, fontWeight: FontWeight.w600),
          ),
        ],
      ),
    );
  }
}

Color _severityColor(String s) => switch (s) {
  'critical' => const Color(0xFFB71C1C),
  'high' => const Color(0xFFBF360C),
  'medium' => const Color(0xFFE65100),
  'low' => const Color(0xFF2E7D32),
  _ => Colors.grey,
};

const _severityOrder = ['critical', 'high', 'medium', 'low'];

class _HistoryCard extends StatelessWidget {
  final SbomHistory history;
  const _HistoryCard({required this.history});

  @override
  Widget build(BuildContext context) {
    final last = history.last!;
    final d = history.delta;
    final theme = Theme.of(context);
    return Card(
      key: Key('history-${history.name}'),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    history.name,
                    style: theme.textTheme.titleSmall,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Text(
                  tr('{total} CVE', {'total': last.total}) +
                      (d == 0 ? '' : '  (${d > 0 ? '+' : ''}$d)'),
                  style: TextStyle(
                    fontWeight: FontWeight.w600,
                    color: d > 0
                        ? Colors.red
                        : d < 0
                        ? Colors.green
                        : null,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            SizedBox(
              height: 90,
              child: CustomPaint(
                key: Key('chart-${history.name}'),
                size: Size.infinite,
                painter: _StackedBars(history.points, theme.dividerColor),
              ),
            ),
            const SizedBox(height: 4),
            Wrap(
              spacing: 12,
              children: [
                for (final s in _severityOrder)
                  if ((last.bySeverity[s] ?? 0) > 0)
                    Text(
                      '■ $s ${last.bySeverity[s]}',
                      style: TextStyle(color: _severityColor(s), fontSize: 12),
                    ),
                Text(
                  tr('dernier passage : {date}', {
                    'date': last.at
                        .toLocal()
                        .toIso8601String()
                        .substring(0, 16)
                        .replaceFirst('T', ' '),
                  }),
                  style: theme.textTheme.bodySmall,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

/// Une barre empilée par passage (sévérités), les plus récents à droite.
class _StackedBars extends CustomPainter {
  final List<HistoryPoint> points;
  final Color axis;
  _StackedBars(this.points, this.axis);

  @override
  void paint(Canvas canvas, Size size) {
    final visible = points.length > 60
        ? points.sublist(points.length - 60)
        : points;
    final max = visible.fold<int>(1, (m, p) => p.total > m ? p.total : m);
    final w = size.width / visible.length;
    final paint = Paint();
    canvas.drawLine(
      Offset(0, size.height),
      Offset(size.width, size.height),
      Paint()..color = axis,
    );
    for (var i = 0; i < visible.length; i++) {
      var y = size.height;
      final p = visible[i];
      final known = {for (final s in _severityOrder) s: p.bySeverity[s] ?? 0};
      final other = p.total - known.values.fold<int>(0, (a, b) => a + b);
      for (final e in [...known.entries, MapEntry('unknown', other)]) {
        if (e.value <= 0) continue;
        final h = size.height * e.value / max;
        paint.color = _severityColor(e.key);
        canvas.drawRect(
          Rect.fromLTWH(i * w + w * 0.15, y - h, w * 0.7, h),
          paint,
        );
        y -= h;
      }
    }
  }

  @override
  bool shouldRepaint(_StackedBars old) =>
      old.points != points || old.axis != axis;
}
