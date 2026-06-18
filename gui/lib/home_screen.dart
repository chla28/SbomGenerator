import 'package:flutter/material.dart';

import 'models/sbom_config.dart';
import 'models/sbom_result.dart';
import 'services/sbom_runner.dart';
import 'services/settings_service.dart';
import 'widgets/config_panel.dart';
import 'widgets/results_panel.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _config = SbomConfig();
  final _runner = SbomRunner();

  String _projectRoot = '';
  List<String> _logLines = [];
  List<OutputFile> _outputFiles = [];
  List<String> _warnings = [];
  String? _fatalError;
  bool _isRunning = false;
  int? _exitCode;

  // Progression parsée
  int _progressCurrent = 0;
  int _progressTotal = 0;
  int _progressPercent = 0;
  String _progressLabel = '';

  @override
  void initState() {
    super.initState();
    SettingsService.getProjectRoot().then((root) {
      if (mounted) setState(() => _projectRoot = root);
    });
  }

  void _startScan() {
    if (!SettingsService.isValidRoot(_projectRoot)) {
      setState(() {
        _fatalError =
            'Le répertoire "$_projectRoot" ne contient pas bin/sbom_generator.dart.\n'
            'Vérifiez la racine du projet dans la configuration.';
        _logLines = [];
        _outputFiles = [];
        _warnings = [];
        _exitCode = 1;
      });
      return;
    }

    setState(() {
      _isRunning = true;
      _logLines = [];
      _outputFiles = [];
      _warnings = [];
      _fatalError = null;
      _exitCode = null;
      _progressCurrent = 0;
      _progressTotal = 0;
      _progressPercent = 0;
      _progressLabel = '';
    });

    _runner
        .run(projectRoot: _projectRoot, args: _config.toArgs())
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

  void _stopScan() {
    _runner.kill();
    setState(() {
      _isRunning = false;
      _logLines.add('[Génération interrompue par l\'utilisateur]');
    });
  }

  void _onProjectRootChanged(String root) {
    setState(() => _projectRoot = root);
    SettingsService.setProjectRoot(root);
  }

  @override
  Widget build(BuildContext context) {
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
          if (_isRunning)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 16),
              child: Center(
                child: SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                      strokeWidth: 2, color: Colors.white),
                ),
              ),
            ),
          if (_projectRoot.isNotEmpty &&
              !SettingsService.isValidRoot(_projectRoot))
            IconButton(
              icon: const Icon(Icons.warning_amber, color: Colors.amber),
              tooltip: 'Racine du projet invalide',
              onPressed: () {},
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
            projectRoot: _projectRoot,
            isRunning: _isRunning,
            onRun: _startScan,
            onStop: _stopScan,
            onProjectRootChanged: _onProjectRootChanged,
          ),
          const VerticalDivider(width: 1),
          Expanded(
            child: ResultsPanel(
              logLines: _logLines,
              outputFiles: _outputFiles,
              warnings: _warnings,
              fatalError: _fatalError,
              isRunning: _isRunning,
              exitCode: _exitCode,
              progressCurrent: _progressCurrent,
              progressTotal: _progressTotal,
              progressPercent: _progressPercent,
              progressLabel: _progressLabel,
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
          'JSON personnalisé, Markdown.',
        ),
      ],
    );
  }
}
