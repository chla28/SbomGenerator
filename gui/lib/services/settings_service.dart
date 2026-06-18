import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:shared_preferences/shared_preferences.dart';

class SettingsService {
  static const _kProjectRoot = 'sbom_project_root';

  static Future<String> getProjectRoot() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString(_kProjectRoot);
    if (saved != null && saved.isNotEmpty) return saved;
    return _detectProjectRoot();
  }

  static Future<void> setProjectRoot(String value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_kProjectRoot, value);
  }

  static String _detectProjectRoot() {
    final candidates = [
      Directory.current.path,
      Directory.current.parent.path,
      p.dirname(Platform.resolvedExecutable),
      p.join(p.dirname(Platform.resolvedExecutable), '..', '..', '..', '..'),
    ];
    for (final dir in candidates) {
      if (_isValid(dir)) return p.normalize(dir);
    }
    return Directory.current.path;
  }

  static bool isValidRoot(String path) => _isValid(path);

  static bool _isValid(String path) =>
      File(p.join(path, 'bin', 'sbom_generator.dart')).existsSync();
}
