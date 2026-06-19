import 'package:flutter/material.dart';

import 'home_screen.dart';
import 'models/sbom_config.dart';
import 'services/settings_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final savedConfig = await SettingsService.loadConfig();
  final themeMode = await SettingsService.loadTheme();
  runApp(SbomGeneratorApp(
    initialConfig: savedConfig,
    initialTheme: themeMode,
  ));
}

class SbomGeneratorApp extends StatefulWidget {
  final SbomConfig? initialConfig;
  final ThemeMode initialTheme;

  const SbomGeneratorApp({
    super.key,
    this.initialConfig,
    this.initialTheme = ThemeMode.system,
  });

  @override
  State<SbomGeneratorApp> createState() => _SbomGeneratorAppState();
}

class _SbomGeneratorAppState extends State<SbomGeneratorApp> {
  late ThemeMode _themeMode;

  @override
  void initState() {
    super.initState();
    _themeMode = widget.initialTheme;
  }

  void _toggleTheme() {
    final next =
        _themeMode == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark;
    setState(() => _themeMode = next);
    SettingsService.saveTheme(next);
  }

  @override
  Widget build(BuildContext context) {
    const seedColor = Color(0xFF1A237E);
    return MaterialApp(
      title: 'SBOM Generator',
      debugShowCheckedModeBanner: false,
      themeMode: _themeMode,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: seedColor),
        inputDecorationTheme: const InputDecorationTheme(
          contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        ),
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: seedColor,
          brightness: Brightness.dark,
        ),
        inputDecorationTheme: const InputDecorationTheme(
          contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        ),
      ),
      home: HomeScreen(
        initialConfig: widget.initialConfig,
        themeMode: _themeMode,
        onThemeToggle: _toggleTheme,
      ),
    );
  }
}
