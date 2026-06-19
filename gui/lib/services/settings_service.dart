import 'dart:io';
import 'package:path/path.dart' as p;

/// Localise le binaire sbom-generator compilé.
/// Cherche d'abord à côté du GUI (installation bundle), puis dans le PATH.
class SettingsService {
  static String get cliBinary {
    final exeDir = p.dirname(Platform.resolvedExecutable);
    final candidates = [
      // Bundle installé : PREFIX/lib/sbom_generator/sbom_generator_gui
      //                   PREFIX/bin/sbom-generator
      p.normalize(p.join(exeDir, '..', '..', 'bin', 'sbom-generator')),
      p.join(exeDir, 'sbom-generator'),
    ];
    for (final c in candidates) {
      if (File(c).existsSync()) return c;
    }
    return 'sbom-generator'; // fallback PATH
  }
}
