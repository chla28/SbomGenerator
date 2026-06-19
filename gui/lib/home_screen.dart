import 'dart:io';

import 'package:flutter/material.dart';

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

  const HomeScreen({
    super.key,
    this.initialConfig,
    required this.themeMode,
    required this.onThemeToggle,
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
    setState(() {
      _isRunning = true;
      _isPdfRunning = false;
      _logLines = [];
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

  void _showAbout(BuildContext context) {
    showAboutDialog(
      context: context,
      applicationName: 'SBOM Generator',
      applicationVersion: '1.0.0',
      applicationIcon: const Icon(Icons.assignment_outlined, size: 48),
      children: const [
        Text(
          'Interface graphique pour l\'outil sbom_generator.\n\n'
          'Génère des SBOM (Software Bill of Materials) depuis des listes '
          'de paquets RPM, .whl, .tar.gz, .deb, .zip ou requirements.txt.\n\n'
          'Formats supportés : CycloneDX 1.6, SPDX 2.3, SPDX 3.0 JSON-LD, '
          'JSON personnalisé, Markdown, AsciiDoc.',
        ),
      ],
    );
  }
}
