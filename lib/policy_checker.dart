import 'dart:io';
import 'tool_runner.dart';
import 'models.dart';
import 'i18n.dart';

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
    // ProcessException si le binaire est absent du PATH.
    final check = await runTool('sbomqs', ['version'])
        .catchError((Object _) => ProcessResult(0, 127, '', ''));
    if (check.exitCode != 0) {
      stderr.writeln(tr(
          'policy: sbomqs introuvable — vérification qualité ignorée.',
          'policy: sbomqs not found — quality check skipped.'));
      return null;
    }

    if (verbose) {
      print(tr(
          'sbomqs : évaluation de $sbomPath…', 'sbomqs: assessing $sbomPath…'));
    }
    // --basic force une sortie sur une seule ligne (score en premier champ) ;
    // sans ce flag, sbomqs >= 2.0 imprime un tableau détaillé illisible ici.
    final result = await runTool('sbomqs', ['score', '--basic', sbomPath]);
    if (result.exitCode != 0) {
      stderr.writeln(tr('sbomqs: échec (code ${result.exitCode})',
          'sbomqs: failed (code ${result.exitCode})'));
      return null;
    }

    // sbomqs --basic écrit une ligne du type "7.3  D  Interlynk  1.6  json  <fichier>"
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

  /// Un motif correspond si la licence lui est égale ou si l'un des
  /// identifiants SPDX de l'expression (découpée sur `AND`/`OR`/`WITH` et les
  /// parenthèses) lui est égal ou en est une variante de version : `GPL-3.0`
  /// couvre `GPL-3.0-only` et `GPL-3.0-or-later`, mais **pas** `LGPL-3.0` ni
  /// `AGPL-3.0`. Un motif entre `*…*` (ex. `*GPL*`) garde l'ancienne
  /// correspondance par sous-chaîne.
  bool _licenseMatches(String license, String pattern) {
    final lcLicense = license.toLowerCase();
    var lcPattern = pattern.trim().toLowerCase();
    if (lcPattern.length > 2 &&
        lcPattern.startsWith('*') &&
        lcPattern.endsWith('*')) {
      return lcLicense.contains(lcPattern.substring(1, lcPattern.length - 1));
    }
    if (lcLicense == lcPattern) return true;
    final tokens = lcLicense
        .split(RegExp(r'[\s()]+|\b(?:and|or|with)\b'))
        .where((t) => t.isNotEmpty && t != 'and' && t != 'or' && t != 'with');
    for (final t in tokens) {
      if (t == lcPattern) return true;
      // « GPL-3.0 » couvre « GPL-3.0-only » / « GPL-3.0-or-later » / « GPL-3.0+ ».
      if (t.startsWith(lcPattern) &&
          (t[lcPattern.length] == '-' || t[lcPattern.length] == '+')) {
        return true;
      }
    }
    return false;
  }
}
