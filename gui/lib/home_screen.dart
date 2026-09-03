import 'dart:io';

import 'package:flutter/material.dart';

import 'models/app_themes.dart';
import 'models/sbom_config.dart';
import 'models/sbom_result.dart';
import 'services/sbom_runner.dart';
import 'services/settings_service.dart';
import 'widgets/config_panel.dart';
import 'widgets/results_panel.dart';

class HomeScreen extends StatefulWidget {
  final SbomConfig? initialConfig;
  final ThemeMode themeMode;
  final VoidCallback onThemeToggle;
  final int themeIndex;
  final ValueChanged<int> onThemeIndexChanged;

  const HomeScreen({
    super.key,
    this.initialConfig,
    required this.themeMode,
    required this.onThemeToggle,
    required this.themeIndex,
    required this.onThemeIndexChanged,
  });

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  late SbomConfig _config;
  final _runner = SbomRunner();

  List<String> _logLines = [];
  List<OutputFile> _outputFiles = [];
  List<String> _warnings = [];
  String? _fatalError;
  bool _isRunning = false;
  bool _isPdfRunning = false;
  int? _exitCode;
  String? _sbomqsOutput;

  // Progression parsée
  int _progressCurrent = 0;
  int _progressTotal = 0;
  int _progressPercent = 0;
  String _progressLabel = '';

  @override
  void initState() {
    super.initState();
    _config = widget.initialConfig ?? SbomConfig();
  }

  void _saveSettings() => SettingsService.saveConfig(_config);

  void _startScan() {
    _saveSettings();
    final cmdLine = _config.toCommandLine(SettingsService.cliBinary);
    setState(() {
      _isRunning = true;
      _isPdfRunning = false;
      _logLines = ['\$ $cmdLine'];
      _outputFiles = [];
      _warnings = [];
      _fatalError = null;
      _exitCode = null;
      _sbomqsOutput = null;
      _progressCurrent = 0;
      _progressTotal = 0;
      _progressPercent = 0;
      _progressLabel = '';
    });

    _runner
        .run(args: _config.toArgs())
        .listen(
      (event) {
        if (!mounted) return;
        switch (event) {
          case SbomProgressEvent(:final current, :final total,
                :final percent, :final label):
            setState(() {
              _progressCurrent = current;
              _progressTotal = total;
              _progressPercent = percent;
              _progressLabel = label;
            });

          case SbomLogEvent(:final line, :final isError, :final isWarning):
            setState(() {
              _logLines.add(line);
              if (isError && _fatalError == null) {
                _fatalError = line.replaceFirst('Error: ', '');
              }
              if (isWarning) _warnings.add(line);
            });

          case SbomOutputFileEvent(:final file):
            setState(() => _outputFiles.add(file));

          case SbomDoneEvent(:final exitCode):
            setState(() {
              _isRunning = false;
              _exitCode = exitCode;
              if (exitCode != 0 && _fatalError == null) {
                _fatalError = 'Génération échouée (exit $exitCode)';
              }
            });
            if (exitCode == 0) {
              if (_config.generatePdf) {
                String? adocPath;
                for (final f in _outputFiles) {
                  if (f.path.endsWith('.adoc')) {
                    adocPath = f.path;
                    break;
                  }
                }
                if (adocPath != null) _generatePdf(adocPath);
              }
              if (_config.enableSbomqs) {
                _runSbomqs();
              }
            }
        }
      },
      onError: (Object e) {
        if (mounted) {
          setState(() {
            _isRunning = false;
            _fatalError = e.toString();
            _exitCode = 1;
          });
        }
      },
    );
  }

  Future<void> _generatePdf(String adocPath) async {
    final pdfPath = _config.pdfOutputPath.isNotEmpty
        ? _config.pdfOutputPath
        : adocPath.endsWith('.adoc')
            ? '${adocPath.substring(0, adocPath.length - 5)}.pdf'
            : '$adocPath.pdf';

    setState(() {
      _isPdfRunning = true;
      _logLines.add('');
      _logLines.add('Conversion PDF (asciidoctor-pdf)…');
      _logLines.add('  ← $adocPath');
      _logLines.add('  → $pdfPath');
    });

    try {
      final result =
          await Process.run('asciidoctor-pdf', [adocPath, '-o', pdfPath]);

      if (!mounted) return;

      if (result.exitCode == 0) {
        final size = await File(pdfPath).length();
        if (!mounted) return;
        final sizeStr = '${(size / 1024).toStringAsFixed(1)} KB';
        setState(() {
          _isPdfRunning = false;
          _outputFiles.add(OutputFile(path: pdfPath, size: sizeStr));
          _logLines.add('PDF written → $pdfPath  ($sizeStr)');
        });
      } else {
        final stderr = (result.stderr as String).trim();
        setState(() {
          _isPdfRunning = false;
          _logLines.add('Erreur asciidoctor-pdf (exit ${result.exitCode})');
          if (stderr.isNotEmpty) _logLines.add('  $stderr');
        });
      }
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _isPdfRunning = false;
        _logLines.add('');
        _logLines.add('Erreur : asciidoctor-pdf introuvable.');
        _logLines.add('  Installez avec : gem install asciidoctor-pdf');
      });
    }
  }

  Future<void> _runSbomqs() async {
    // Cible le premier SBOM JSON généré
    final target = _outputFiles
        .where((f) =>
            f.path.endsWith('.cdx.json') ||
            f.path.endsWith('.spdx.json') ||
            f.path.endsWith('.jsonld'))
        .map((f) => f.path)
        .firstOrNull;
    if (target == null) return;

    try {
      final result = await Process.run('sbomqs', ['score', target]);
      if (!mounted) return;
      if (result.exitCode == 0 || result.exitCode == 1) {
        final out = (result.stdout as String).trim();
        if (out.isNotEmpty) setState(() => _sbomqsOutput = out);
      }
    } catch (_) {
      // sbomqs non installé — on ignore silencieusement
    }
  }

  void _stopScan() {
    _runner.kill();
    setState(() {
      _isRunning = false;
      _logLines.add('[Génération interrompue par l\'utilisateur]');
    });
  }

  bool get _isBusy => _isRunning || _isPdfRunning;

  @override
  Widget build(BuildContext context) {
    final isDark = widget.themeMode == ThemeMode.dark;
    return Scaffold(
      appBar: AppBar(
        title: const Row(
          children: [
            Icon(Icons.assignment_outlined, size: 22),
            SizedBox(width: 10),
            Text('SBOM Generator',
                style: TextStyle(fontWeight: FontWeight.bold)),
          ],
        ),
        actions: [
          if (_isBusy)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Center(
                child: Tooltip(
                  message: _isPdfRunning
                      ? 'Conversion PDF en cours…'
                      : 'Génération SBOM en cours…',
                  child: const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                        strokeWidth: 2, color: Colors.white),
                  ),
                ),
              ),
            ),
          IconButton(
            icon: const Icon(Icons.palette_outlined),
            tooltip: 'Couleur du thème',
            onPressed: () => _showThemePicker(context),
          ),
          IconButton(
            icon: Icon(isDark ? Icons.light_mode : Icons.dark_mode),
            tooltip: isDark ? 'Mode clair' : 'Mode sombre',
            onPressed: widget.onThemeToggle,
          ),
          IconButton(
            icon: const Icon(Icons.info_outline),
            tooltip: 'À propos',
            onPressed: () => _showAbout(context),
          ),
        ],
      ),
      body: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ConfigPanel(
            config: _config,
            isRunning: _isBusy,
            onRun: _startScan,
            onStop: _stopScan,
            onChanged: _saveSettings,
          ),
          const VerticalDivider(width: 1),
          Expanded(
            child: ResultsPanel(
              logLines: _logLines,
              outputFiles: _outputFiles,
              warnings: _warnings,
              fatalError: _fatalError,
              isRunning: _isRunning,
              isPdfRunning: _isPdfRunning,
              exitCode: _exitCode,
              progressCurrent: _progressCurrent,
              progressTotal: _progressTotal,
              progressPercent: _progressPercent,
              progressLabel: _progressLabel,
              sbomqsOutput: _sbomqsOutput,
            ),
          ),
        ],
      ),
    );
  }

  void _showThemePicker(BuildContext context) {
    showDialog<void>(
      context: context,
      builder: (_) => _ThemePickerDialog(
        currentIndex: widget.themeIndex,
        onSelected: (i) {
          widget.onThemeIndexChanged(i);
          Navigator.of(context).pop();
        },
      ),
    );
  }

  void _showAbout(BuildContext context) {
    showAboutDialog(
      context: context,
      applicationName: 'SBOM Generator',
      applicationVersion: '1.2.0',
      applicationIcon: const Icon(Icons.assignment_outlined, size: 48),
      children: const [
        Text(
          'Interface graphique pour l\'outil sbom_generator.\n\n'
          'Génère des SBOM (Software Bill of Materials) depuis des listes '
          'de paquets RPM, .whl, .tar.gz, .deb, .zip, .jar ou requirements.txt '
          '— fichier liste, paquet unique, ou dossier scanné récursivement.\n\n'
          'Formats supportés : CycloneDX 1.6/1.7, SPDX 2.3, SPDX 3.0 JSON-LD, '
          'JSON personnalisé, Markdown, AsciiDoc.',
        ),
      ],
    );
  }
}

// ─── Sélecteur de thème de couleur ───────────────────────────────────────────

class _ThemePickerDialog extends StatelessWidget {
  final int currentIndex;
  final ValueChanged<int> onSelected;

  const _ThemePickerDialog({
    required this.currentIndex,
    required this.onSelected,
  });

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Row(
        children: [
          Icon(Icons.palette_outlined, size: 20),
          SizedBox(width: 8),
          Text('Couleur du thème'),
        ],
      ),
      contentPadding: const EdgeInsets.fromLTRB(24, 12, 24, 8),
      content: SizedBox(
        width: 320,
        child: Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            for (int i = 0; i < kAppThemes.length; i++)
              _ThemeSwatch(
                theme: kAppThemes[i],
                selected: i == currentIndex,
                onTap: () => onSelected(i),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Annuler'),
        ),
      ],
    );
  }
}

class _ThemeSwatch extends StatelessWidget {
  final AppTheme theme;
  final bool selected;
  final VoidCallback onTap;

  const _ThemeSwatch({
    required this.theme,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: theme.label,
      child: InkWell(
        borderRadius: BorderRadius.circular(32),
        onTap: onTap,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            AnimatedContainer(
              duration: const Duration(milliseconds: 150),
              width: 48,
              height: 48,
              decoration: BoxDecoration(
                color: theme.color,
                shape: BoxShape.circle,
                border: Border.all(
                  color: selected
                      ? Theme.of(context).colorScheme.onSurface
                      : Colors.transparent,
                  width: 3,
                ),
                boxShadow: selected
                    ? [
                        BoxShadow(
                          color: theme.color.withValues(alpha: 0.5),
                          blurRadius: 8,
                          spreadRadius: 2,
                        ),
                      ]
                    : null,
              ),
              child: selected
                  ? const Icon(Icons.check, color: Colors.white, size: 22)
                  : null,
            ),
            const SizedBox(height: 4),
            Text(
              theme.label,
              style: TextStyle(
                fontSize: 11,
                fontWeight:
                    selected ? FontWeight.bold : FontWeight.normal,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
