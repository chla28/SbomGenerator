import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:shared_preferences/shared_preferences.dart';

import '../models/sbom_config.dart';

class SettingsService {
  static const _configKey = 'sbom_config_v1';
  static const _themeKey = 'theme_mode';
  static const _themeColorKey = 'theme_color_index';

  static String get cliBinary {
    final exeDir = p.dirname(Platform.resolvedExecutable);
    final candidates = [
      p.normalize(p.join(exeDir, '..', '..', 'bin', 'sbom-generator')),
      p.join(exeDir, 'sbom-generator'),
    ];
    for (final c in candidates) {
      if (File(c).existsSync()) return c;
    }
    return 'sbom-generator';
  }

  static Future<void> saveConfig(SbomConfig config) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_configKey, jsonEncode(config.toJson()));
  }

  static Future<SbomConfig?> loadConfig() async {
    final prefs = await SharedPreferences.getInstance();
    final str = prefs.getString(_configKey);
    if (str == null) return null;
    try {
      return SbomConfig.fromJson(jsonDecode(str) as Map<String, dynamic>);
    } catch (_) {
      return null;
    }
  }

  static Future<void> saveTheme(ThemeMode mode) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_themeKey, mode.name);
  }

  static Future<ThemeMode> loadTheme() async {
    final prefs = await SharedPreferences.getInstance();
    final name = prefs.getString(_themeKey);
    return switch (name) {
      'dark' => ThemeMode.dark,
      'light' => ThemeMode.light,
      _ => ThemeMode.system,
    };
  }

  static Future<void> saveThemeColorIndex(int index) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_themeColorKey, index);
  }

  static Future<int> loadThemeColorIndex() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getInt(_themeColorKey) ?? 0;
  }
}
