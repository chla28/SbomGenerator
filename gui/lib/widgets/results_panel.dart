import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

import '../models/sbom_result.dart';

class ResultsPanel extends StatefulWidget {
  final List<String> logLines;
  final List<OutputFile> outputFiles;
  final List<String> warnings;
  final String? fatalError;
  final bool isRunning;
  final bool isPdfRunning;
  final int? exitCode;
  final int progressCurrent;
  final int progressTotal;
  final int progressPercent;
  final String progressLabel;

  const ResultsPanel({
    super.key,
    required this.logLines,
    required this.outputFiles,
    required this.warnings,
    this.fatalError,
    required this.isRunning,
    this.isPdfRunning = false,
    this.exitCode,
    this.progressCurrent = 0,
    this.progressTotal = 0,
    this.progressPercent = 0,
    this.progressLabel = '',
  });

  @override
  State<ResultsPanel> createState() => _ResultsPanelState();
}

class _ResultsPanelState extends State<ResultsPanel>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  final ScrollController _logScroll = ScrollController();

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 2, vsync: this);
  }

  @override
  void dispose() {
    _tabs.dispose();
    _logScroll.dispose();
    super.dispose();
  }

  @override
  void didUpdateWidget(ResultsPanel old) {
    super.didUpdateWidget(old);
    // Auto-scroll log
    if (widget.logLines.length != old.logLines.length) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (_logScroll.hasClients) {
          _logScroll.animateTo(
            _logScroll.position.maxScrollExtent,
            duration: const Duration(milliseconds: 150),
            curve: Curves.easeOut,
          );
        }
      });
    }
    // Basculer vers Progression dès le démarrage
    if (widget.isRunning && !old.isRunning) _tabs.animateTo(0);
    // Basculer vers Résultats une fois SBOM + PDF terminés
    final wasBusy = old.isRunning || old.isPdfRunning;
    final isBusy = widget.isRunning || widget.isPdfRunning;
    if (!isBusy && wasBusy && widget.exitCode == 0) {
      _tabs.animateTo(1);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isBusy = widget.isRunning || widget.isPdfRunning;
    final hasActivity = isBusy ||
        widget.logLines.isNotEmpty ||
        widget.outputFiles.isNotEmpty;

    return Column(
      children: [
        // Barre de progression SBOM
        if (widget.isRunning && widget.progressTotal > 0)
          _ProgressBar(
            current: widget.progressCurrent,
            total: widget.progressTotal,
            percent: widget.progressPercent,
            label: widget.progressLabel,
          ),

        // Bannière PDF en cours
        if (widget.isPdfRunning)
          Container(
            color: Colors.blue[50],
            padding:
                const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Row(
              children: [
                const SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(
                      strokeWidth: 2, color: Colors.blue),
                ),
                const SizedBox(width: 10),
                Text(
                  'Conversion PDF (asciidoctor-pdf) en cours…',
                  style: TextStyle(
                      fontSize: 13, color: Colors.blue[800]),
                ),
              ],
            ),
          ),

        // Bannière de résultat
        if (!isBusy && widget.exitCode != null)
          _StatusBanner(
            exitCode: widget.exitCode!,
            outputFiles: widget.outputFiles,
            warnings: widget.warnings,
            fatalError: widget.fatalError,
          ),

        // TabBar
        ColoredBox(
          color: theme.colorScheme.surfaceContainerLow,
          child: TabBar(
            controller: _tabs,
            tabs: [
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    if (widget.isRunning)
                      const SizedBox(
                        width: 14,
                        height: 14,
                        child:
                            CircularProgressIndicator(strokeWidth: 2),
                      )
                    else
                      const Icon(Icons.terminal, size: 16),
                    const SizedBox(width: 6),
                    const Text('Progression'),
                  ],
                ),
              ),
              Tab(
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.assignment_outlined, size: 16),
                    const SizedBox(width: 6),
                    Text(
                      widget.outputFiles.isEmpty
                          ? 'Résultats'
                          : 'Résultats (${widget.outputFiles.length})',
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),

        Expanded(
          child: TabBarView(
            controller: _tabs,
            children: [
              // Tab 0 : Progression
              hasActivity
                  ? _LogView(
                      lines: widget.logLines,
                      scrollController: _logScroll,
                    )
                  : const _EmptyHint(),

              // Tab 1 : Résultats
              _ResultsView(
                outputFiles: widget.outputFiles,
                warnings: widget.warnings,
                fatalError: widget.fatalError,
                exitCode: widget.exitCode,
              ),
            ],
          ),
        ),
      ],
    );
  }
}

// ─── Progress bar ─────────────────────────────────────────────────────────────

class _ProgressBar extends StatelessWidget {
  final int current;
  final int total;
  final int percent;
  final String label;

  const _ProgressBar({
    required this.current,
    required this.total,
    required this.percent,
    required this.label,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      color: theme.colorScheme.surfaceContainerLowest,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                '$current / $total paquets',
                style: const TextStyle(
                    fontSize: 12, fontWeight: FontWeight.bold),
              ),
              const SizedBox(width: 12),
              Text(
                '$percent%',
                style: TextStyle(
                    fontSize: 12,
                    color: theme.colorScheme.primary,
                    fontWeight: FontWeight.bold),
              ),
              const Spacer(),
              if (label.isNotEmpty)
                Flexible(
                  child: Text(
                    label,
                    style: const TextStyle(
                        fontSize: 11, fontFamily: 'monospace'),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
            ],
          ),
          const SizedBox(height: 6),
          LinearProgressIndicator(
            value: total > 0 ? current / total : null,
            minHeight: 6,
            borderRadius: BorderRadius.circular(3),
          ),
        ],
      ),
    );
  }
}

// ─── Status banner ────────────────────────────────────────────────────────────

class _StatusBanner extends StatelessWidget {
  final int exitCode;
  final List<OutputFile> outputFiles;
  final List<String> warnings;
  final String? fatalError;

  const _StatusBanner({
    required this.exitCode,
    required this.outputFiles,
    required this.warnings,
    this.fatalError,
  });

  @override
  Widget build(BuildContext context) {
    final ok = exitCode == 0;
    return Container(
      color: ok ? Colors.green[50] : Colors.red[50],
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Row(
        children: [
          Icon(
            ok ? Icons.check_circle : Icons.error_outline,
            color: ok ? Colors.green[700] : Colors.red[700],
            size: 20,
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              ok
                  ? '${outputFiles.length} fichier(s) SBOM généré(s)'
                      '${warnings.isNotEmpty ? " — ${warnings.length} avertissement(s)" : ""}'
                  : fatalError ?? 'Échec de la génération (exit $exitCode)',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                color: ok ? Colors.green[800] : Colors.red[800],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Log view ─────────────────────────────────────────────────────────────────

class _LogView extends StatelessWidget {
  final List<String> lines;
  final ScrollController scrollController;

  const _LogView({required this.lines, required this.scrollController});

  static Color? _lineColor(String line) {
    if (line.startsWith('Error:')) return Colors.red[300];
    if (line.startsWith('Warning:') ||
        line.startsWith('⚠') ||
        line.startsWith('   •')) {
      return Colors.orange[300];
    }
    if (line.contains('SBOM written')) return Colors.green[300];
    if (line.contains('PDF written')) return Colors.green[300];
    if (line.startsWith('Conversion PDF')) return Colors.lightBlue[300];
    if (line.startsWith('Generating') ||
        line.startsWith('Resolving') ||
        line.startsWith('Found') ||
        line.startsWith('Analysés')) {
      return Colors.blue[300];
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      color: const Color(0xFF1E1E1E),
      padding: const EdgeInsets.all(12),
      child: SelectionArea(
        child: ListView.builder(
          controller: scrollController,
          itemCount: lines.length,
          itemBuilder: (_, i) {
            final line = lines[i];
            return Text(
              line,
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 12,
                color: _lineColor(line) ?? const Color(0xFFD4D4D4),
                height: 1.5,
              ),
            );
          },
        ),
      ),
    );
  }
}

// ─── Results view ─────────────────────────────────────────────────────────────

class _ResultsView extends StatelessWidget {
  final List<OutputFile> outputFiles;
  final List<String> warnings;
  final String? fatalError;
  final int? exitCode;

  const _ResultsView({
    required this.outputFiles,
    required this.warnings,
    this.fatalError,
    this.exitCode,
  });

  @override
  Widget build(BuildContext context) {
    if (outputFiles.isEmpty && warnings.isEmpty && fatalError == null) {
      return const _EmptyHint();
    }

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Fichiers générés
        if (outputFiles.isNotEmpty) ...[
          _SectionTitle(
            icon: Icons.insert_drive_file_outlined,
            label: 'Fichiers générés',
          ),
          const SizedBox(height: 8),
          for (final f in outputFiles) _OutputFileCard(file: f),
          const SizedBox(height: 20),
        ],

        // Avertissements
        if (warnings.isNotEmpty) ...[
          _SectionTitle(
            icon: Icons.warning_amber_outlined,
            label: 'Avertissements (${warnings.length})',
            color: Colors.orange[700],
          ),
          const SizedBox(height: 8),
          _WarningsList(warnings: warnings),
          const SizedBox(height: 20),
        ],

        // Erreur fatale
        if (fatalError != null) ...[
          _SectionTitle(
            icon: Icons.error_outline,
            label: 'Erreur',
            color: Colors.red[700],
          ),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.red[50],
              borderRadius: BorderRadius.circular(6),
              border: Border.all(color: Colors.red[200]!),
            ),
            child: SelectableText(
              fatalError!,
              style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: Colors.red[800]),
            ),
          ),
        ],
      ],
    );
  }
}

class _OutputFileCard extends StatelessWidget {
  final OutputFile file;
  const _OutputFileCard({required this.file});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final exists = File(file.path).existsSync();
    final ext = file.path.split('.').last;

    final iconColor = switch (ext) {
      'json' || 'jsonld' => theme.colorScheme.primary,
      'md' => Colors.purple[600],
      'adoc' => Colors.teal[600],
      'pdf' => Colors.red[700],
      _ => theme.colorScheme.secondary,
    };

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: Icon(
          ext == 'pdf' ? Icons.picture_as_pdf_outlined : Icons.description_outlined,
          color: iconColor,
        ),
        title: Text(
          file.path.split('/').last,
          style: const TextStyle(
              fontFamily: 'monospace', fontWeight: FontWeight.w600),
        ),
        subtitle: Text(
          file.path,
          style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
          overflow: TextOverflow.ellipsis,
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              file.size,
              style: TextStyle(
                  fontSize: 12,
                  color: theme.colorScheme.onSurface.withValues(alpha: 0.6)),
            ),
            const SizedBox(width: 8),
            IconButton(
              icon: const Icon(Icons.copy_outlined, size: 18),
              tooltip: 'Copier le chemin',
              onPressed: () {
                Clipboard.setData(ClipboardData(text: file.path));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Chemin copié'),
                    duration: Duration(seconds: 2),
                  ),
                );
              },
            ),
            if (exists)
              IconButton(
                icon: const Icon(Icons.open_in_new, size: 18),
                tooltip: 'Ouvrir le fichier',
                onPressed: () =>
                    launchUrl(Uri.file(file.path)),
              ),
          ],
        ),
      ),
    );
  }
}

class _WarningsList extends StatefulWidget {
  final List<String> warnings;
  const _WarningsList({required this.warnings});

  @override
  State<_WarningsList> createState() => _WarningsListState();
}

class _WarningsListState extends State<_WarningsList> {
  bool _expanded = false;
  static const _previewCount = 5;

  @override
  Widget build(BuildContext context) {
    final shown = _expanded
        ? widget.warnings
        : widget.warnings.take(_previewCount).toList();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: Colors.orange[50],
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: Colors.orange[200]!),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              for (final w in shown)
                Padding(
                  padding: const EdgeInsets.only(bottom: 2),
                  child: Text(
                    w,
                    style: const TextStyle(
                        fontSize: 12, fontFamily: 'monospace'),
                  ),
                ),
            ],
          ),
        ),
        if (widget.warnings.length > _previewCount) ...[
          const SizedBox(height: 4),
          TextButton(
            onPressed: () => setState(() => _expanded = !_expanded),
            child: Text(_expanded
                ? 'Réduire'
                : 'Voir ${widget.warnings.length - _previewCount} de plus…'),
          ),
        ],
      ],
    );
  }
}

class _SectionTitle extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color? color;

  const _SectionTitle({
    required this.icon,
    required this.label,
    this.color,
  });

  @override
  Widget build(BuildContext context) {
    final c = color ?? Theme.of(context).colorScheme.primary;
    return Row(
      children: [
        Icon(icon, size: 16, color: c),
        const SizedBox(width: 6),
        Text(
          label,
          style: TextStyle(
              fontSize: 13, fontWeight: FontWeight.bold, color: c),
        ),
      ],
    );
  }
}

class _EmptyHint extends StatelessWidget {
  const _EmptyHint();

  @override
  Widget build(BuildContext context) => const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.inventory_2_outlined, size: 56, color: Colors.grey),
            SizedBox(height: 12),
            Text(
              'Configurez les options et lancez la génération',
              style: TextStyle(color: Colors.grey, fontSize: 15),
            ),
          ],
        ),
      );
}
