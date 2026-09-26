import 'package:flutter/material.dart';

import 'home_screen.dart';
import 'l10n/l10n.dart';
import 'models/app_themes.dart';
import 'models/sbom_config.dart';
import 'services/settings_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final savedConfig = await SettingsService.loadConfig();
  final themeMode = await SettingsService.loadTheme();
  final themeIndex = await SettingsService.loadThemeColorIndex();
  final language = AppLanguage.parse(await SettingsService.loadLanguage());
  runApp(SbomGeneratorApp(
    initialConfig: savedConfig,
    initialTheme: themeMode,
    initialThemeIndex: themeIndex,
    initialLanguage: language,
  ));
}

class SbomGeneratorApp extends StatefulWidget {
  final SbomConfig? initialConfig;
  final ThemeMode initialTheme;
  final int initialThemeIndex;
  final AppLanguage initialLanguage;

  const SbomGeneratorApp({
    super.key,
    this.initialConfig,
    this.initialTheme = ThemeMode.system,
    this.initialThemeIndex = 0,
    this.initialLanguage = AppLanguage.system,
  });

  @override
  State<SbomGeneratorApp> createState() => _SbomGeneratorAppState();
}

class _SbomGeneratorAppState extends State<SbomGeneratorApp> {
  late ThemeMode _themeMode;
  late int _themeIndex;
  late AppLanguage _language;

  @override
  void initState() {
    super.initState();
    _themeMode = widget.initialTheme;
    _themeIndex = widget.initialThemeIndex.clamp(0, kAppThemes.length - 1);
    _language = widget.initialLanguage;
  }

  void _onLanguageChanged(AppLanguage language) {
    setState(() => _language = language);
    SettingsService.saveLanguage(language.name);
  }

  void _toggleTheme() {
    final next =
        _themeMode == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark;
    setState(() => _themeMode = next);
    SettingsService.saveTheme(next);
  }

  void _onThemeIndexChanged(int index) {
    setState(() => _themeIndex = index);
    SettingsService.saveThemeColorIndex(index);
  }

  @override
  Widget build(BuildContext context) {
    final seedColor = kAppThemes[_themeIndex].color;
    const inputTheme = InputDecorationTheme(
      contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
    );
    return MaterialApp(
      title: 'SBOM Generator',
      debugShowCheckedModeBanner: false,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      locale: _language.locale,
      localeListResolutionCallback: (locales, _) => resolveAppLocale(locales),
      themeMode: _themeMode,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: seedColor),
        inputDecorationTheme: inputTheme,
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: seedColor,
          brightness: Brightness.dark,
        ),
        inputDecorationTheme: inputTheme,
      ),
      home: HomeScreen(
        initialConfig: widget.initialConfig,
        themeMode: _themeMode,
        onThemeToggle: _toggleTheme,
        themeIndex: _themeIndex,
        onThemeIndexChanged: _onThemeIndexChanged,
        language: _language,
        onLanguageChanged: _onLanguageChanged,
      ),
    );
  }
}
