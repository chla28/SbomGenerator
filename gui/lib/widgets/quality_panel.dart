import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/sbom_result.dart';

// ─── Modèles sbomqs ──────────────────────────────────────────────────────────

class _SbomqsCheck {
  final String category;
  final String name;
  final double score;
  final double maxScore;
  final String description;

  const _SbomqsCheck({
    required this.category,
    required this.name,
    required this.score,
    required this.maxScore,
    required this.description,
  });

  bool get passed => score >= maxScore;

  static double _num(dynamic v) {
    if (v == null) return 0;
    if (v is num) return v.toDouble();
    return double.tryParse(v.toString()) ?? 0;
  }

  static _SbomqsCheck fromJson(Map<String, dynamic> j) => _SbomqsCheck(
        category: (j['check_category'] ?? j['category'] ?? '').toString().trim(),
        name: (j['check_name'] ?? j['name'] ?? '').toString().trim(),
        score: _num(j['current_score'] ?? j['score']),
        maxScore: _num(j['max_score']),
        description: (j['check_result'] ?? j['description'] ?? '').toString().trim(),
      );
}

class _SbomqsResult {
  final String spec;
  final String specVersion;
  final int numComponents;
  final double score;
  final double maxScore;
  final List<_SbomqsCheck> checks;

  const _SbomqsResult({
    required this.spec,
    required this.specVersion,
    required this.numComponents,
    required this.score,
    required this.maxScore,
    required this.checks,
  });

  static _SbomqsResult? fromJson(Map<String, dynamic> root) {
    try {
      final files = root['files'] as List?;
      if (files == null || files.isEmpty) return null;
      final f = files.first as Map<String, dynamic>;

      // Score peut être dans un sous-objet "score" ou directement à la racine du fichier
      final scoreMap = (f['score'] is Map)
          ? f['score'] as Map<String, dynamic>
          : f;

      final rawChecks = (scoreMap['checks'] ??
              (f['score'] is Map ? null : f['checks'])) as List?;
      final checks = rawChecks
              ?.map((c) => _SbomqsCheck.fromJson(c as Map<String, dynamic>))
              .toList() ??
          [];

      return _SbomqsResult(
        spec: (f['spec'] as String? ?? '').toUpperCase(),
        specVersion:
            (f['spec_version'] ?? f['specVersion'] ?? '').toString(),
        numComponents: (f['num_components'] as int?) ?? 0,
        score: _SbomqsCheck._num(
            scoreMap['avg_score'] ?? scoreMap['score'] ?? f['avg_score']),
        maxScore:
            _SbomqsCheck._num(scoreMap['max_score'] ?? f['max_score'] ?? 10),
        checks: checks,
      );
    } catch (_) {
      return null;
    }
  }
}

// ─── Modèles sbom-scorecard ──────────────────────────────────────────────────

class _ScorecardCategory {
  final String label;
  final int score;
  const _ScorecardCategory({required this.label, required this.score});
}

class _ScorecardResult {
  final int total;
  final List<_ScorecardCategory> categories;
  const _ScorecardResult({required this.total, required this.categories});

  // Parsing de la sortie texte de sbom-scorecard
  static _ScorecardResult? parse(String text) {
    final lines = text.split('\n');
    final categories = <_ScorecardCategory>[];
    int total = 0;

    // On ignore les lignes de métadonnées connues
    const metaKeys = {
      'spec', 'specversion', 'filename', 'packages',
      'score for', 'file', 'name', 'format'
    };

    for (final raw in lines) {
      final line = raw.trim();
      if (line.isEmpty) continue;

      // Ligne "Total : 69" ou "Total: 69"
      final tMatch =
          RegExp(r'^total\s*:?\s*(\d+)', caseSensitive: false).firstMatch(line);
      if (tMatch != null) {
        total = int.tryParse(tMatch.group(1)!) ?? 0;
        continue;
      }

      // Ligne "  Quality : 75" ou "NTIA-minimum : 88"
      final cMatch = RegExp(r'^([a-z][a-z0-9\-\s]+?)\s*:+\s*(\d+)\s*$',
              caseSensitive: false)
          .firstMatch(line);
      if (cMatch != null) {
        final label = cMatch.group(1)!.trim().toLowerCase();
        if (!metaKeys.any((k) => label.startsWith(k))) {
          final score = int.tryParse(cMatch.group(2)!) ?? 0;
          categories.add(_ScorecardCategory(label: cMatch.group(1)!.trim(), score: score));
        }
      }
    }

    if (categories.isEmpty && total == 0) return null;
    return _ScorecardResult(total: total, categories: categories);
  }

  // Parsing JSON (si sbom-scorecard supporte --format json)
  static _ScorecardResult? fromJson(Map<String, dynamic> j) {
    try {
      final scores = (j['scores'] ?? j['score'] ?? j) as Map<String, dynamic>;
      final cats = <_ScorecardCategory>[];
      int tot = 0;
      scores.forEach((k, v) {
        if (k.toLowerCase() == 'total') {
          tot = (v as num).toInt();
        } else {
          cats.add(_ScorecardCategory(label: k, score: (v as num).toInt()));
        }
      });
      if (cats.isEmpty && tot == 0) return null;
      return _ScorecardResult(total: tot, categories: cats);
    } catch (_) {
      return null;
    }
  }
}

// ─── Widget principal ────────────────────────────────────────────────────────

class QualityPanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  const QualityPanel({super.key, required this.outputFiles});

  @override
  State<QualityPanel> createState() => _QualityPanelState();
}

class _QualityPanelState extends State<QualityPanel>
    with AutomaticKeepAliveClientMixin {
  final _fileCtrl = TextEditingController();
  bool _isRunning = false;

  _SbomqsResult? _sbomqsResult;
  String? _sbomqsRaw;
  String? _sbomqsError;

  _ScorecardResult? _scorecardResult;
  String? _scorecardRaw;
  String? _scorecardError;

  @override
  bool get wantKeepAlive => true;

  @override
  void dispose() {
    _fileCtrl.dispose();
    super.dispose();
  }

  @override
  void didUpdateWidget(QualityPanel old) {
    super.didUpdateWidget(old);
    if (widget.outputFiles != old.outputFiles && _fileCtrl.text.isEmpty) {
      _updateAutoFile();
    }
  }

  void _updateAutoFile() {
    final f = widget.outputFiles
        .where((f) =>
            f.path.endsWith('.cdx.json') || f.path.endsWith('.spdx.json'))
        .firstOrNull ??
        widget.outputFiles
        .where((f) =>
            f.path.endsWith('.json') || f.path.endsWith('.jsonld'))
        .firstOrNull;
    if (f != null) setState(() => _fileCtrl.text = f.path);
  }

  Future<void> _pickFile({bool filtered = true}) async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Sélectionner un fichier SBOM',
      type: filtered ? FileType.custom : FileType.any,
      allowedExtensions: filtered ? ['json', 'jsonld'] : null,
    );
    if (result != null && result.files.single.path != null) {
      setState(() => _fileCtrl.text = result.files.single.path!);
    }
  }

  Future<void> _analyze() async {
    final path = _fileCtrl.text.trim();
    if (path.isEmpty) return;
    setState(() {
      _isRunning = true;
      _sbomqsResult = null;
      _sbomqsRaw = null;
      _sbomqsError = null;
      _scorecardResult = null;
      _scorecardRaw = null;
      _scorecardError = null;
    });
    await Future.wait([_runSbomqs(path), _runScorecard(path)]);
    if (mounted) setState(() => _isRunning = false);
  }

  Future<void> _runSbomqs(String path) async {
    try {
      final result =
          await Process.run('sbomqs', ['score', '-f', 'json', path]);
      final stdout = (result.stdout as String).trim();
      if (!mounted) return;
      if (result.exitCode == 0 || result.exitCode == 1) {
        _SbomqsResult? parsed;
        try {
          parsed =
              _SbomqsResult.fromJson(jsonDecode(stdout) as Map<String, dynamic>);
        } catch (_) {}
        setState(() {
          _sbomqsRaw = stdout;
          _sbomqsResult = parsed;
          if (parsed == null && stdout.isEmpty) {
            _sbomqsError = 'Aucun résultat retourné par sbomqs';
          }
        });
      } else {
        final stderr = (result.stderr as String).trim();
        setState(() => _sbomqsError =
            stderr.isNotEmpty ? stderr : 'Erreur sbomqs (exit ${result.exitCode})');
      }
    } on ProcessException {
      if (mounted) {
        setState(() => _sbomqsError =
            'sbomqs introuvable — installez-le et ajoutez-le au PATH');
      }
    } catch (e) {
      if (mounted) setState(() => _sbomqsError = e.toString());
    }
  }

  Future<void> _runScorecard(String path) async {
    try {
      final result =
          await Process.run('sbom-scorecard', ['score', path]);
      final stdout = (result.stdout as String).trim();
      if (!mounted) return;
      if (result.exitCode == 0) {
        _ScorecardResult? parsed;
        // Essai JSON
        try {
          parsed = _ScorecardResult.fromJson(
              jsonDecode(stdout) as Map<String, dynamic>);
        } catch (_) {}
        parsed ??= _ScorecardResult.parse(stdout);
        setState(() {
          _scorecardRaw = stdout;
          _scorecardResult = parsed;
        });
      } else {
        final stderr = (result.stderr as String).trim();
        setState(() => _scorecardError = stderr.isNotEmpty
            ? stderr
            : 'Erreur sbom-scorecard (exit ${result.exitCode})');
      }
    } on ProcessException {
      if (mounted) {
        setState(() => _scorecardError =
            'sbom-scorecard introuvable — installez-le et ajoutez-le au PATH');
      }
    } catch (e) {
      if (mounted) setState(() => _scorecardError = e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _ConfigSection(
          fileCtrl: _fileCtrl,
          isRunning: _isRunning,
          onPick: _pickFile,
          onAnalyze: _analyze,
        ),
        if (_isRunning) const LinearProgressIndicator(),
        Expanded(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (_sbomqsRaw == null && _sbomqsError == null &&
                    _scorecardRaw == null && _scorecardError == null &&
                    !_isRunning)
                  const _HintCard(),
                if (_sbomqsRaw != null || _sbomqsError != null)
                  _SbomqsSection(
                    result: _sbomqsResult,
                    rawOutput: _sbomqsRaw,
                    error: _sbomqsError,
                  ),
                if ((_sbomqsRaw != null || _sbomqsError != null) &&
                    (_scorecardRaw != null || _scorecardError != null))
                  const SizedBox(height: 16),
                if (_scorecardRaw != null || _scorecardError != null)
                  _ScorecardSection(
                    result: _scorecardResult,
                    rawOutput: _scorecardRaw,
                    error: _scorecardError,
                  ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

// ─── Barre de configuration ──────────────────────────────────────────────────

class _ConfigSection extends StatelessWidget {
  final TextEditingController fileCtrl;
  final bool isRunning;
  final void Function({bool filtered}) onPick;
  final VoidCallback onAnalyze;

  const _ConfigSection({
    required this.fileCtrl,
    required this.isRunning,
    required this.onPick,
    required this.onAnalyze,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          Expanded(
            child: TextFormField(
              controller: fileCtrl,
              decoration: InputDecoration(
                labelText: 'Fichier SBOM',
                isDense: true,
                suffixIcon: _SplitPickButton(onPick: onPick),
              ),
            ),
          ),
          const SizedBox(width: 12),
          FilledButton.icon(
            onPressed: isRunning ? null : onAnalyze,
            icon: const Icon(Icons.analytics_outlined, size: 18),
            label: const Text('Analyser'),
          ),
        ],
      ),
    );
  }
}

// ─── Hint initial ────────────────────────────────────────────────────────────

class _HintCard extends StatelessWidget {
  const _HintCard();

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          children: [
            Icon(Icons.verified_outlined,
                size: 48, color: Theme.of(context).colorScheme.primary),
            const SizedBox(height: 12),
            const Text(
              'Évaluation de la qualité SBOM',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            const Text(
              'Sélectionnez un fichier SBOM puis cliquez sur Analyser.\n'
              'L\'analyse utilise sbomqs (Interlynk) et sbom-scorecard (eBay).',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 13),
            ),
          ],
        ),
      ),
    );
  }
}

// ─── Section sbomqs ──────────────────────────────────────────────────────────

class _SbomqsSection extends StatefulWidget {
  final _SbomqsResult? result;
  final String? rawOutput;
  final String? error;

  const _SbomqsSection(
      {required this.result, required this.rawOutput, required this.error});

  @override
  State<_SbomqsSection> createState() => _SbomqsSectionState();
}

class _SbomqsSectionState extends State<_SbomqsSection> {
  final Set<String> _activeFilters = {};
  bool _showRaw = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final result = widget.result;

    return Card(
      clipBehavior: Clip.antiAlias,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // En-tête
          Container(
            color: theme.colorScheme.primaryContainer,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            child: Row(
              children: [
                Icon(Icons.verified_outlined,
                    size: 20,
                    color: theme.colorScheme.onPrimaryContainer),
                const SizedBox(width: 8),
                Text(
                  'sbomqs',
                  style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                      color: theme.colorScheme.onPrimaryContainer),
                ),
                if (result != null) ...[
                  const SizedBox(width: 8),
                  Text(
                    '${result.spec} ${result.specVersion}',
                    style: TextStyle(
                        fontSize: 12,
                        color: theme.colorScheme.onPrimaryContainer
                            .withValues(alpha: 0.7)),
                  ),
                ],
                const Spacer(),
                if (result != null)
                  _ScoreBadge(
                    score: result.score,
                    maxScore: result.maxScore,
                    large: true,
                  ),
                if (widget.rawOutput != null) ...[
                  const SizedBox(width: 8),
                  IconButton(
                    icon: Icon(_showRaw ? Icons.table_chart : Icons.code,
                        size: 18),
                    tooltip: _showRaw ? 'Vue tableau' : 'JSON brut',
                    color: theme.colorScheme.onPrimaryContainer,
                    onPressed: () =>
                        setState(() => _showRaw = !_showRaw),
                  ),
                  IconButton(
                    icon: const Icon(Icons.copy, size: 18),
                    tooltip: 'Copier',
                    color: theme.colorScheme.onPrimaryContainer,
                    onPressed: () => Clipboard.setData(
                        ClipboardData(text: widget.rawOutput!)),
                  ),
                ],
              ],
            ),
          ),

          // Erreur
          if (widget.error != null)
            Padding(
              padding: const EdgeInsets.all(16),
              child: _ErrorBanner(message: widget.error!),
            )
          // JSON brut
          else if (_showRaw && widget.rawOutput != null)
            _RawOutput(text: widget.rawOutput!)
          // Tableau
          else if (result != null) ...[
            if (result.checks.isNotEmpty) ...[
              _CategoryFilter(
                checks: result.checks,
                activeFilters: _activeFilters,
                onToggle: (cat) => setState(() {
                  if (_activeFilters.contains(cat)) {
                    _activeFilters.remove(cat);
                  } else {
                    _activeFilters.add(cat);
                  }
                }),
              ),
              _SbomqsTable(
                checks: result.checks,
                activeFilters: _activeFilters,
              ),
            ] else
              const Padding(
                padding: EdgeInsets.all(16),
                child: Text('Aucun critère détaillé disponible.'),
              ),
          ] else if (widget.rawOutput != null)
            _RawOutput(text: widget.rawOutput!),
        ],
      ),
    );
  }
}

// ─── Filtre par catégorie ────────────────────────────────────────────────────

class _CategoryFilter extends StatelessWidget {
  final List<_SbomqsCheck> checks;
  final Set<String> activeFilters;
  final void Function(String) onToggle;

  const _CategoryFilter({
    required this.checks,
    required this.activeFilters,
    required this.onToggle,
  });

  @override
  Widget build(BuildContext context) {
    final categories = checks.map((c) => c.category).toSet().toList()..sort();
    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
      child: Wrap(
        spacing: 6,
        runSpacing: 4,
        children: [
          for (final cat in categories)
            FilterChip(
              label: Text(cat.isEmpty ? 'Autre' : cat,
                  style: const TextStyle(fontSize: 12)),
              selected: activeFilters.contains(cat),
              onSelected: (_) => onToggle(cat),
              visualDensity: VisualDensity.compact,
            ),
          if (activeFilters.isNotEmpty)
            ActionChip(
              label: const Text('Tout voir', style: TextStyle(fontSize: 12)),
              onPressed: () {
                for (final c in List.of(activeFilters)) {
                  onToggle(c);
                }
              },
              visualDensity: VisualDensity.compact,
            ),
        ],
      ),
    );
  }
}

// ─── Tableau sbomqs ──────────────────────────────────────────────────────────

class _SbomqsTable extends StatelessWidget {
  final List<_SbomqsCheck> checks;
  final Set<String> activeFilters;

  const _SbomqsTable(
      {required this.checks, required this.activeFilters});

  @override
  Widget build(BuildContext context) {
    final filtered = activeFilters.isEmpty
        ? checks
        : checks.where((c) => activeFilters.contains(c.category)).toList();

    return ListView.separated(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: filtered.length,
      separatorBuilder: (_, _) => const Divider(height: 1, indent: 16),
      itemBuilder: (context, i) {
        final check = filtered[i];
        return ListTile(
          dense: true,
          leading: Icon(
            check.passed ? Icons.check_circle_outline : Icons.cancel_outlined,
            color: check.passed ? Colors.green[600] : Colors.red[400],
            size: 20,
          ),
          title: Text(check.name,
              style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500)),
          subtitle: check.description.isNotEmpty
              ? Text(check.description,
                  style: const TextStyle(fontSize: 11),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis)
              : null,
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (check.category.isNotEmpty)
                Chip(
                  label: Text(check.category,
                      style: const TextStyle(fontSize: 10)),
                  padding: EdgeInsets.zero,
                  visualDensity: VisualDensity.compact,
                ),
              const SizedBox(width: 8),
              Text(
                '${check.score.toStringAsFixed(0)}/${check.maxScore.toStringAsFixed(0)}',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  color:
                      check.passed ? Colors.green[700] : Colors.red[400],
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

// ─── Section sbom-scorecard ──────────────────────────────────────────────────

class _ScorecardSection extends StatefulWidget {
  final _ScorecardResult? result;
  final String? rawOutput;
  final String? error;

  const _ScorecardSection(
      {required this.result, required this.rawOutput, required this.error});

  @override
  State<_ScorecardSection> createState() => _ScorecardSectionState();
}

class _ScorecardSectionState extends State<_ScorecardSection> {
  bool _showRaw = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final result = widget.result;

    return Card(
      clipBehavior: Clip.antiAlias,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // En-tête
          Container(
            color: theme.colorScheme.secondaryContainer,
            padding:
                const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            child: Row(
              children: [
                Icon(Icons.score_outlined,
                    size: 20,
                    color: theme.colorScheme.onSecondaryContainer),
                const SizedBox(width: 8),
                Text(
                  'sbom-scorecard',
                  style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                      color: theme.colorScheme.onSecondaryContainer),
                ),
                const Spacer(),
                if (result != null)
                  _ScoreBadge(
                    score: result.total.toDouble(),
                    maxScore: 100,
                    large: true,
                  ),
                if (widget.rawOutput != null) ...[
                  const SizedBox(width: 8),
                  IconButton(
                    icon: Icon(_showRaw ? Icons.bar_chart : Icons.code,
                        size: 18),
                    tooltip: _showRaw ? 'Vue graphique' : 'Sortie brute',
                    color: theme.colorScheme.onSecondaryContainer,
                    onPressed: () =>
                        setState(() => _showRaw = !_showRaw),
                  ),
                  IconButton(
                    icon: const Icon(Icons.copy, size: 18),
                    tooltip: 'Copier',
                    color: theme.colorScheme.onSecondaryContainer,
                    onPressed: () => Clipboard.setData(
                        ClipboardData(text: widget.rawOutput!)),
                  ),
                ],
              ],
            ),
          ),

          // Erreur
          if (widget.error != null)
            Padding(
              padding: const EdgeInsets.all(16),
              child: _ErrorBanner(message: widget.error!),
            )
          // Sortie brute
          else if (_showRaw && widget.rawOutput != null)
            _RawOutput(text: widget.rawOutput!)
          // Graphique à barres
          else if (result != null && result.categories.isNotEmpty)
            Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  for (final cat in result.categories)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: _ScoreBar(
                          label: cat.label, score: cat.score, maxScore: 100),
                    ),
                  const Divider(),
                  _ScoreBar(
                    label: 'Total',
                    score: result.total,
                    maxScore: 100,
                    bold: true,
                  ),
                ],
              ),
            )
          else if (widget.rawOutput != null)
            _RawOutput(text: widget.rawOutput!),
        ],
      ),
    );
  }
}

// ─── Barre de score ──────────────────────────────────────────────────────────

class _ScoreBar extends StatelessWidget {
  final String label;
  final int score;
  final int maxScore;
  final bool bold;

  const _ScoreBar({
    required this.label,
    required this.score,
    required this.maxScore,
    this.bold = false,
  });

  Color _color() {
    final pct = maxScore > 0 ? score / maxScore : 0.0;
    if (pct >= 0.8) return Colors.green[600]!;
    if (pct >= 0.6) return Colors.orange[600]!;
    return Colors.red[400]!;
  }

  @override
  Widget build(BuildContext context) {
    final pct = maxScore > 0 ? score / maxScore : 0.0;
    return Row(
      children: [
        SizedBox(
          width: 140,
          child: Text(
            label,
            style: TextStyle(
              fontSize: 13,
              fontWeight: bold ? FontWeight.bold : FontWeight.normal,
            ),
          ),
        ),
        Expanded(
          child: ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: pct.clamp(0.0, 1.0),
              minHeight: 10,
              backgroundColor: Colors.grey[200],
              valueColor: AlwaysStoppedAnimation<Color>(_color()),
            ),
          ),
        ),
        const SizedBox(width: 10),
        SizedBox(
          width: 50,
          child: Text(
            '$score / $maxScore',
            textAlign: TextAlign.right,
            style: TextStyle(
              fontSize: 12,
              fontWeight: bold ? FontWeight.bold : FontWeight.normal,
              color: _color(),
            ),
          ),
        ),
      ],
    );
  }
}

// ─── Badge de score ──────────────────────────────────────────────────────────

class _ScoreBadge extends StatelessWidget {
  final double score;
  final double maxScore;
  final bool large;

  const _ScoreBadge(
      {required this.score, required this.maxScore, this.large = false});

  Color _color() {
    final pct = maxScore > 0 ? score / maxScore : 0.0;
    if (pct >= 0.8) return Colors.green[700]!;
    if (pct >= 0.6) return Colors.orange[700]!;
    return Colors.red[600]!;
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding:
          EdgeInsets.symmetric(horizontal: large ? 10 : 6, vertical: large ? 4 : 2),
      decoration: BoxDecoration(
        color: _color(),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(
        maxScore == 10
            ? '${score.toStringAsFixed(1)} / 10'
            : '${score.toStringAsFixed(0)} / 100',
        style: TextStyle(
          color: Colors.white,
          fontWeight: FontWeight.bold,
          fontSize: large ? 14 : 12,
        ),
      ),
    );
  }
}

// ─── Affichage brut ──────────────────────────────────────────────────────────

class _RawOutput extends StatelessWidget {
  final String text;
  const _RawOutput({required this.text});

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: const BoxConstraints(maxHeight: 300),
      color: const Color(0xFF1E1E1E),
      padding: const EdgeInsets.all(12),
      child: SingleChildScrollView(
        child: SelectableText(
          text,
          style: const TextStyle(
              fontFamily: 'monospace', fontSize: 12, color: Colors.white70),
        ),
      ),
    );
  }
}

// ─── Bannière d'erreur ───────────────────────────────────────────────────────

class _ErrorBanner extends StatelessWidget {
  final String message;
  const _ErrorBanner({required this.message});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.red[50],
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.red[200]!),
      ),
      child: Row(
        children: [
          Icon(Icons.error_outline, color: Colors.red[600], size: 20),
          const SizedBox(width: 8),
          Expanded(
            child: SelectableText(
              message,
              style: TextStyle(color: Colors.red[800], fontSize: 13),
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Split-button fichier ────────────────────────────────────────────────────

class _SplitPickButton extends StatelessWidget {
  final void Function({bool filtered}) onPick;
  const _SplitPickButton({required this.onPick});

  @override
  Widget build(BuildContext context) {
    final controller = MenuController();
    return MenuAnchor(
      controller: controller,
      menuChildren: [
        MenuItemButton(
          child: const Text('Type filtré (.json, .jsonld)'),
          onPressed: () => onPick(filtered: true),
        ),
        MenuItemButton(
          child: const Text('Tous les fichiers'),
          onPressed: () => onPick(filtered: false),
        ),
      ],
      child: IconButton(
        icon: const Icon(Icons.folder_open_outlined, size: 20),
        tooltip: 'Choisir',
        onPressed: () =>
            controller.isOpen ? controller.close() : controller.open(),
      ),
    );
  }
}
