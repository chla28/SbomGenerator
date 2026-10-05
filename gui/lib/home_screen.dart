import 'dart:io';

import 'package:flutter/material.dart';

import 'l10n/l10n.dart';
import 'models/app_themes.dart';
import 'models/sbom_config.dart';
import 'models/sbom_result.dart';
import 'services/sbom_runner.dart';
import 'services/settings_service.dart';
import 'widgets/config_panel.dart';
import 'widgets/help_viewer.dart';
import 'widgets/pdf_report.dart' show kGuiVersion;
import 'widgets/results_panel.dart';

class HomeScreen extends StatefulWidget {
  final SbomConfig? initialConfig;
  final ThemeMode themeMode;
  final VoidCallback onThemeToggle;
  final int themeIndex;
  final ValueChanged<int> onThemeIndexChanged;

  /// Langue de l'interface choisie (réglage mémorisé).
  final AppLanguage language;
  final ValueChanged<AppLanguage> onLanguageChanged;

  const HomeScreen({
    super.key,
    this.initialConfig,
    required this.themeMode,
    required this.onThemeToggle,
    required this.themeIndex,
    required this.onThemeIndexChanged,
    this.language = AppLanguage.system,
    required this.onLanguageChanged,
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
    final l = context.l10n;
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
              case SbomProgressEvent(
                :final current,
                :final total,
                :final percent,
                :final label,
              ):
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
                    _fatalError = l.homeGenerationFailed(exitCode);
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
    final l = context.l10n;
    final pdfPath = _config.pdfOutputPath.isNotEmpty
        ? _config.pdfOutputPath
        : adocPath.endsWith('.adoc')
        ? '${adocPath.substring(0, adocPath.length - 5)}.pdf'
        : '$adocPath.pdf';

    setState(() {
      _isPdfRunning = true;
      _logLines.add('');
      _logLines.add(l.homePdfHeader);
      _logLines.add('  ← $adocPath');
      _logLines.add('  → $pdfPath');
    });

    try {
      final result = await Process.run('asciidoctor-pdf', [
        adocPath,
        '-o',
        pdfPath,
      ]);

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
          _logLines.add(l.homePdfError(result.exitCode));
          if (stderr.isNotEmpty) _logLines.add('  $stderr');
        });
      }
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _isPdfRunning = false;
        _logLines.add('');
        _logLines.add(l.homePdfMissing);
        _logLines.add(l.homePdfInstall);
      });
    }
  }

  Future<void> _runSbomqs() async {
    // Cible le premier SBOM JSON généré
    final target = _outputFiles
        .where(
          (f) =>
              f.path.endsWith('.cdx.json') ||
              f.path.endsWith('.spdx.json') ||
              f.path.endsWith('.jsonld'),
        )
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
      _logLines.add(context.l10n.homeInterrupted);
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
            Text(
              'SBOM Generator',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
          ],
        ),
        actions: [
          if (_isBusy)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Center(
                child: Tooltip(
                  message: _isPdfRunning
                      ? context.l10n.homePdfRunning
                      : context.l10n.homeSbomRunning,
                  child: const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: Colors.white,
                    ),
                  ),
                ),
              ),
            ),
          IconButton(
            icon: const Icon(Icons.help_outline),
            tooltip: context.l10n.homeHelpTooltip,
            onPressed: () => _showHelp(context),
          ),
          PopupMenuButton<AppLanguage>(
            key: const Key('language-menu'),
            icon: const Icon(Icons.translate),
            tooltip: context.l10n.languageMenuTooltip,
            initialValue: widget.language,
            onSelected: widget.onLanguageChanged,
            itemBuilder: (context) => [
              for (final l in AppLanguage.values)
                CheckedPopupMenuItem(
                  value: l,
                  checked: l == widget.language,
                  child: Text(switch (l) {
                    AppLanguage.system => context.l10n.languageSystem,
                    AppLanguage.fr => context.l10n.languageFrench,
                    AppLanguage.en => context.l10n.languageEnglish,
                  }),
                ),
            ],
          ),
          IconButton(
            icon: const Icon(Icons.palette_outlined),
            tooltip: context.l10n.homeThemeColor,
            onPressed: () => _showThemePicker(context),
          ),
          IconButton(
            icon: Icon(isDark ? Icons.light_mode : Icons.dark_mode),
            tooltip: isDark
                ? context.l10n.homeLightMode
                : context.l10n.homeDarkMode,
            onPressed: widget.onThemeToggle,
          ),
          IconButton(
            icon: const Icon(Icons.info_outline),
            tooltip: context.l10n.homeAbout,
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

  void _showHelp(BuildContext context) {
    Navigator.of(
      context,
    ).push(MaterialPageRoute(builder: (_) => const HelpViewerScreen()));
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
      applicationVersion: kGuiVersion,
      applicationIcon: const Icon(Icons.assignment_outlined, size: 48),
      children: [Text(context.l10n.homeAboutText)],
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
      title: Row(
        children: [
          const Icon(Icons.palette_outlined, size: 20),
          const SizedBox(width: 8),
          Text(context.l10n.homeThemeColor),
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
          child: Text(context.l10n.homeCancel),
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
      message: themeLabel(context.l10n, theme),
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
              themeLabel(context.l10n, theme),
              style: TextStyle(
                fontSize: 11,
                fontWeight: selected ? FontWeight.bold : FontWeight.normal,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Nom d'une couleur de thème dans la langue courante (les libellés de
/// [kAppThemes] sont en français, langue de référence).
String themeLabel(AppLocalizations l, AppTheme t) => switch (t.label) {
  'Bleu' => l.themeBlue,
  'Violet' => l.themePurple,
  'Vert' => l.themeGreen,
  'Rouge' => l.themeRed,
  'Rose' => l.themePink,
  'Ardoise' => l.themeSlate,
  'Marron' => l.themeBrown,
  _ => t.label,
};
