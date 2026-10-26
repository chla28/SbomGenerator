import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'i18n.dart';
import 'l10n/l10n.dart';
import 'models/app_themes.dart';
import 'models/sbom_config.dart';
import 'models/sbom_result.dart';
import 'services/sbom_runner.dart';
import 'services/session_store.dart';
import 'services/settings_service.dart';
import 'widgets/config_panel.dart';
import 'widgets/help_viewer.dart';
import 'widgets/pdf_report.dart' show kGuiVersion;
import 'widgets/results_panel.dart';

class HomeScreen extends StatefulWidget {
  final SbomConfig? initialConfig;

  /// SBOM prérempli dans l'onglet Grype (argument `--sbom`).
  final String? initialSbom;
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
    this.initialSbom,
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
  final _configKey = GlobalKey<ConfigPanelState>();
  final _resultsKey = GlobalKey<ResultsPanelState>();
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
                    _fatalError = tr('Génération échouée (exit {code})', {'code': exitCode});
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
      _logLines.add(tr('Conversion PDF (asciidoctor-pdf)…'));
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
          _logLines.add(tr('Erreur asciidoctor-pdf (exit {code})', {'code': result.exitCode}));
          if (stderr.isNotEmpty) _logLines.add('  $stderr');
        });
      }
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _isPdfRunning = false;
        _logLines.add('');
        _logLines.add(tr('Erreur : asciidoctor-pdf introuvable.'));
        _logLines.add(tr('  Installez avec : gem install asciidoctor-pdf'));
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
      _logLines.add(tr('[Génération interrompue par l\'utilisateur]'));
    });
  }

  bool get _isBusy => _isRunning || _isPdfRunning;

  @override
  Widget build(BuildContext context) {
    final isDark = widget.themeMode == ThemeMode.dark;
    return CallbackShortcuts(
      bindings: _shortcutBindings(context),
      child: Focus(autofocus: true, child: _scaffold(context, isDark)),
    );
  }

  /// Raccourcis clavier globaux (voir [_showShortcuts]).
  Map<ShortcutActivator, VoidCallback> _shortcutBindings(
    BuildContext context,
  ) => {
    const SingleActivator(LogicalKeyboardKey.enter, control: true): () =>
        _configKey.currentState?.triggerRun(),
    const SingleActivator(LogicalKeyboardKey.escape): () {
      if (_isRunning) _stopScan();
    },
    const SingleActivator(LogicalKeyboardKey.f1): () => _showHelp(context),
    const SingleActivator(LogicalKeyboardKey.slash, control: true): () =>
        _showShortcuts(context),
    const SingleActivator(LogicalKeyboardKey.pageDown, control: true): () =>
        _resultsKey.currentState?.moveTab(1),
    const SingleActivator(LogicalKeyboardKey.pageUp, control: true): () =>
        _resultsKey.currentState?.moveTab(-1),
    for (final (i, key) in [
      LogicalKeyboardKey.digit1,
      LogicalKeyboardKey.digit2,
      LogicalKeyboardKey.digit3,
      LogicalKeyboardKey.digit4,
      LogicalKeyboardKey.digit5,
      LogicalKeyboardKey.digit6,
      LogicalKeyboardKey.digit7,
      LogicalKeyboardKey.digit8,
      LogicalKeyboardKey.digit9,
    ].indexed)
      SingleActivator(key, control: true): () =>
          _resultsKey.currentState?.selectTab(i),
  };

  Widget _scaffold(BuildContext context, bool isDark) {
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
                      ? tr('Conversion PDF en cours…')
                      : tr('Génération SBOM en cours…'),
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
            icon: const Icon(Icons.keyboard_outlined),
            tooltip: tr('Raccourcis clavier'),
            onPressed: () => _showShortcuts(context),
          ),
          IconButton(
            icon: const Icon(Icons.help_outline),
            tooltip: tr('Aide — Manuel utilisateur'),
            onPressed: () => _showHelp(context),
          ),
          PopupMenuButton<AppLanguage>(
            key: const Key('language-menu'),
            icon: const Icon(Icons.translate),
            tooltip: tr('Langue de l\'interface'),
            initialValue: widget.language,
            onSelected: widget.onLanguageChanged,
            itemBuilder: (context) => [
              for (final l in AppLanguage.values)
                CheckedPopupMenuItem(
                  value: l,
                  checked: l == widget.language,
                  child: Text(switch (l) {
                    AppLanguage.system => tr('Système'),
                    AppLanguage.fr => tr('Français'),
                    AppLanguage.en => tr('English'),
                  }),
                ),
            ],
          ),
          IconButton(
            icon: const Icon(Icons.palette_outlined),
            tooltip: tr('Couleur du thème'),
            onPressed: () => _showThemePicker(context),
          ),
          IconButton(
            icon: Icon(isDark ? Icons.light_mode : Icons.dark_mode),
            tooltip: isDark
                ? tr('Mode clair')
                : tr('Mode sombre'),
            onPressed: widget.onThemeToggle,
          ),
          IconButton(
            icon: const Icon(Icons.info_outline),
            tooltip: tr('À propos'),
            onPressed: () => _showAbout(context),
          ),
        ],
      ),
      body: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ConfigPanel(
            key: _configKey,
            config: _config,
            isRunning: _isBusy,
            onRun: _startScan,
            onStop: _stopScan,
            onChanged: _saveSettings,
          ),
          const VerticalDivider(width: 1),
          Expanded(
            child: ResultsPanel(
              key: _resultsKey,
              initialGrypeSbom: widget.initialSbom,
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
              historyStore: SessionStore(SessionStore.defaultDir()),
            ),
          ),
        ],
      ),
    );
  }

  void _showShortcuts(BuildContext context) {
    final rows = <(String, String)>[
      ('Ctrl+Entrée', tr('Lancer la génération')),
      ('Échap', tr('Arrêter l\'exécution en cours')),
      ('Ctrl+1 … Ctrl+9', tr('Aller à l\'onglet 1 à 9')),
      ('Ctrl+PgSuiv / Ctrl+PgPréc', tr('Onglet suivant / précédent')),
      ('F1', tr('Ouvrir l\'aide')),
      ('Ctrl+/', tr('Afficher cette liste')),
    ];
    showDialog<void>(
      context: context,
      builder: (_) => AlertDialog(
        title: Text(tr('Raccourcis clavier')),
        content: SizedBox(
          width: 460,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              for (final (keys, what) in rows)
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 3),
                  child: Row(
                    children: [
                      SizedBox(
                        width: 190,
                        child: Text(
                          keys,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                      Expanded(child: Text(what)),
                    ],
                  ),
                ),
              const SizedBox(height: 8),
              Text(
                tr('Parcourir : Tab / flèches ; ouvrir une ligne : Entrée ou Espace'),
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(tr('Fermer')),
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
      children: [Text(tr('Interface graphique pour l\'outil sbom_generator.\n\nGénère des SBOM (Software Bill of Materials) depuis des listes de paquets RPM, .whl, .tar.gz, .deb, .zip, .jar, ou de manifestes (requirements.txt, go.sum, package-lock.json, pom.xml, pubspec.lock…) — fichier liste, paquet unique, ou dossier scanné récursivement.\n\nFormats supportés : CycloneDX 1.6/1.7, SPDX 2.3, SPDX 3.0 JSON-LD, JSON personnalisé, Markdown, AsciiDoc.'))],
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
          Text(tr('Couleur du thème')),
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
          child: Text(tr('Annuler')),
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
      message: themeLabel( theme),
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
              themeLabel( theme),
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
String themeLabel(AppTheme t) => switch (t.label) {
  'Bleu' => tr('Bleu'),
  'Violet' => tr('Violet'),
  'Vert' => tr('Vert'),
  'Rouge' => tr('Rouge'),
  'Rose' => tr('Rose'),
  'Ardoise' => tr('Ardoise'),
  'Marron' => tr('Marron'),
  _ => t.label,
};
