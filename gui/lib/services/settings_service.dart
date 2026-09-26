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
  static const _scanEnrichKey = 'scan_enrich_online_v1';
  static const _reportSeverityKey = 'dashboard_report_severity_v1';

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

  // ── Enrichissement CVE (exploitabilité / exploitation active) ─────────────

  /// Autoriser les requêtes réseau (CISA KEV / EPSS / poc-in-github) lors d'un
  /// scan de vulnérabilités. Défaut : activé.
  static Future<bool> loadScanEnrichOnline() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getBool(_scanEnrichKey) ?? true;
  }

  static Future<void> saveScanEnrichOnline(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_scanEnrichKey, value);
  }

  /// Seuil de sévérité du rapport PDF du tableau de bord (nom de la valeur
  /// d'énumération, ex. `high`) ; `null` si jamais choisi.
  static Future<String?> loadReportSeverity() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_reportSeverityKey);
  }

  static Future<void> saveReportSeverity(String value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_reportSeverityKey, value);
  }

  // ── Profils de configuration ──────────────────────────────────────────────

  static const _profileNamesKey = 'profile_names_v1';
  static String _profileKey(String name) =>
      'profile_v1_${Uri.encodeComponent(name)}';

  static Future<List<String>> listProfiles() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_profileNamesKey);
    if (raw == null) return [];
    return (jsonDecode(raw) as List).cast<String>();
  }

  static Future<void> saveProfile(String name, SbomConfig config) async {
    final prefs = await SharedPreferences.getInstance();
    final names = await listProfiles();
    if (!names.contains(name)) {
      names.add(name);
      await prefs.setString(_profileNamesKey, jsonEncode(names));
    }
    await prefs.setString(_profileKey(name), jsonEncode(config.toJson()));
  }

  static Future<SbomConfig?> loadProfile(String name) async {
    final prefs = await SharedPreferences.getInstance();
    final str = prefs.getString(_profileKey(name));
    if (str == null) return null;
    try {
      return SbomConfig.fromJson(jsonDecode(str) as Map<String, dynamic>);
    } catch (_) {
      return null;
    }
  }

  static Future<void> deleteProfile(String name) async {
    final prefs = await SharedPreferences.getInstance();
    final names = await listProfiles();
    names.remove(name);
    await prefs.setString(_profileNamesKey, jsonEncode(names));
    await prefs.remove(_profileKey(name));
  }
}
