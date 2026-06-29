import 'dart:io';
import 'models.dart';

/// Résultat d'une violation de politique de licence.
class LicenseViolation {
  final String packageName;
  final String version;
  final String license;
  final String deniedPattern;

  const LicenseViolation({
    required this.packageName,
    required this.version,
    required this.license,
    required this.deniedPattern,
  });
}

/// Vérifie les politiques applicables après génération du SBOM.
class PolicyChecker {
  /// Retourne la liste des violations pour les licences interdites.
  /// [denyPatterns] peut contenir des identifiants SPDX exacts ou des sous-chaînes.
  List<LicenseViolation> checkDenyLicenses(
      List<Package> packages, List<String> denyPatterns) {
    if (denyPatterns.isEmpty) return [];

    final violations = <LicenseViolation>[];
    for (final pkg in packages) {
      final lic = pkg.license.trim();
      if (lic.isEmpty) continue;
      for (final pattern in denyPatterns) {
        if (_licenseMatches(lic, pattern)) {
          violations.add(LicenseViolation(
            packageName: pkg.name,
            version: pkg.version,
            license: lic,
            deniedPattern: pattern,
          ));
          break; // Une seule violation par paquet suffit
        }
      }
    }
    return violations;
  }

  /// Retourne le score sbomqs (0–10) du fichier [sbomPath], ou null si sbomqs
  /// est absent ou échoue.
  Future<double?> runSbomqs(String sbomPath, {bool verbose = false}) async {
    final check = await Process.run('sbomqs', ['--version']);
    if (check.exitCode != 0) {
      stderr.writeln('policy: sbomqs introuvable — vérification qualité ignorée.');
      return null;
    }

    if (verbose) print('sbomqs : évaluation de $sbomPath…');
    final result = await Process.run('sbomqs', ['score', sbomPath]);
    if (result.exitCode != 0) {
      stderr.writeln('sbomqs: échec (code ${result.exitCode})');
      return null;
    }

    // sbomqs écrit une ligne du type "7.3  <fichier>"
    final output = result.stdout as String;
    for (final line in output.split('\n')) {
      final parts = line.trim().split(RegExp(r'\s+'));
      if (parts.isNotEmpty) {
        final score = double.tryParse(parts.first);
        if (score != null) return score;
      }
    }
    return null;
  }

  bool _licenseMatches(String license, String pattern) {
    final lcLicense = license.toLowerCase();
    final lcPattern = pattern.toLowerCase();
    // Correspondance exacte ou expression SPDX composée (AND/OR/WITH)
    if (lcLicense == lcPattern) return true;
    // Sous-chaîne : "GPL-3.0" matche "GPL-3.0-only", "GPL-3.0-or-later"…
    return lcLicense.contains(lcPattern);
  }
}
