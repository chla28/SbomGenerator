// ─── Habillage visuel partagé des exports AsciiDoc → PDF ────────────────────
//
// Utilisé par dashboard_panel.dart (rapport de synthèse) et vuln_shared.dart
// (rapport par scanner) pour que les PDF générés via asciidoctor-pdf
// ressemblent à l'écran : thème de couleurs calqué sur l'appli, badges de
// sévérité (mêmes teintes que severityFg/severityBg), et une barre de
// répartition par sévérité reproduisant _SeverityBar (dashboard_panel.dart).
import 'dart:convert';
import 'dart:io';

// ─── Version de la GUI ───────────────────────────────────────────────────────
//
// Unique endroit à mettre à jour côté GUI lors d'un bump de version (avec
// gui/pubspec.yaml) — home_screen.dart (À propos) et les exports PDF s'y
// réfèrent tous les deux, au lieu de dupliquer le littéral.
const String kGuiVersion = '1.2.1';

// ─── Thème asciidoctor-pdf ──────────────────────────────────────────────────
//
// asciidoctor-pdf ne sait charger un thème que depuis un fichier réel sur
// disque (pas de data URI) : writePdfTheme() l'écrit dans le dossier temp
// système avant chaque conversion, et runAsciidoctorPdf() le référence via
// l'attribut CLI `pdf-theme` (pas besoin de `pdf-themesdir`, chemin absolu).
const String _kPdfThemeYaml = '''
extends: default
page:
  margin: [2cm, 1.8cm, 2cm, 1.8cm]
base:
  font_color: 263238
  font_size: 10.5
  line_height: 1.35
heading:
  font_color: 0D47A1
  font_style: bold
  h1:
    font_size: 20
    border_bottom_width: 0.75
    border_bottom_color: 1565C0
  h2:
    font_size: 15
    font_color: 1565C0
    margin_top: 18
    border_bottom_width: 0.5
    border_bottom_color: CFD8DC
  h3:
    font_size: 12
    font_color: 00695C
toc:
  font_color: 37474F
  dot_leader:
    font_color: CFD8DC
table:
  border_color: CFD8DC
  border_width: 0.5
  head:
    background_color: 1565C0
    font_color: FFFFFF
    font_style: bold
  body:
    background_color: FFFFFF
  even_row:
    background_color: F5F7FA
role:
  sev-critical:
    background_color: B71C1C
    font_color: FFFFFF
    font_style: bold
  sev-high:
    background_color: BF360C
    font_color: FFFFFF
    font_style: bold
  sev-medium:
    background_color: E65100
    font_color: FFFFFF
    font_style: bold
  sev-low:
    background_color: 2E7D32
    font_color: FFFFFF
    font_style: bold
  sev-other:
    background_color: 607D8B
    font_color: FFFFFF
    font_style: bold
''';

/// Écrit le thème PDF dans le dossier temp système et renvoie son chemin
/// absolu. Réécrit à chaque appel (contenu statique, coût négligeable) —
/// évite tout problème de cache si le thème change d'une version à l'autre.
Future<String> writePdfTheme() async {
  final file = File(
      '${Directory.systemTemp.path}/sbom_generator_gui_pdf_theme.yml');
  await file.writeAsString(_kPdfThemeYaml);
  return file.path;
}

/// Lance asciidoctor-pdf avec le thème partagé. À utiliser à la place d'un
/// `Process.run('asciidoctor-pdf', [...])` direct dans tout export PDF de la
/// GUI, pour un rendu cohérent entre les onglets.
Future<ProcessResult> runAsciidoctorPdf(String adocPath, String pdfPath) async {
  final themePath = await writePdfTheme();
  return Process.run(
      'asciidoctor-pdf', [adocPath, '-o', pdfPath, '-a', 'pdf-theme=$themePath']);
}

// ─── Badges de sévérité ──────────────────────────────────────────────────────
//
// Mêmes seuils que severityFg/severityBg (vuln_shared.dart) et _SeverityBar
// (dashboard_panel.dart), traduits en rôles du thème ci-dessus.
String _severityRole(String severity) => switch (severity.toLowerCase()) {
      'critical' => 'sev-critical',
      'high' => 'sev-high',
      'medium' => 'sev-medium',
      'low' => 'sev-low',
      _ => 'sev-other',
    };

/// Rend une sévérité en badge coloré AsciiDoc (`[.sev-xxx]#LABEL#`), à
/// utiliser directement comme contenu d'une cellule de tableau.
String pdfSeverityBadge(String severity) {
  final label = severity.isEmpty ? '?' : severity.toUpperCase();
  return '[.${_severityRole(severity)}]#$label#';
}

// ─── Barre de répartition par sévérité ───────────────────────────────────────
//
// Reproduit _SeverityBar (dashboard_panel.dart) : segments proportionnels
// Critical/High/Medium/Low/Autre dans le même ordre et les mêmes couleurs.
// asciidoctor-pdf n'offre pas de cellule de tableau à fond plein fiable
// (l'attribut `cellbgcolor` n'est pas honoré par le thème par défaut) — la
// barre est donc construite comme une image SVG, intégrée en data URI pour
// n'avoir aucun fichier temporaire à gérer.
String? buildSeverityBarSvg(
  Map<String, int> countsBySeverity, {
  int width = 640,
  int height = 22,
}) {
  int c(String key) => countsBySeverity.entries
      .where((e) => e.key.toLowerCase() == key)
      .fold(0, (sum, e) => sum + e.value);
  final total = countsBySeverity.values.fold(0, (sum, v) => sum + v);
  if (total == 0) return null;

  final critical = c('critical');
  final high = c('high');
  final medium = c('medium');
  final low = c('low');
  final other = total - critical - high - medium - low;

  final segments = <(int, String)>[
    (critical, 'B71C1C'),
    (high, 'BF360C'),
    (medium, 'E65100'),
    (low, '2E7D32'),
    (other > 0 ? other : 0, '9E9E9E'),
  ].where((s) => s.$1 > 0).toList();

  final radius = height / 2;
  final buf = StringBuffer()
    ..writeln('<svg xmlns="http://www.w3.org/2000/svg" '
        'width="$width" height="$height">')
    ..writeln('<clipPath id="r"><rect x="0" y="0" '
        'width="$width" height="$height" rx="$radius" ry="$radius"/></clipPath>')
    ..writeln('<g clip-path="url(#r)">');
  var x = 0.0;
  for (final (count, color) in segments) {
    final w = width * count / total;
    buf.writeln('<rect x="${x.toStringAsFixed(1)}" y="0" '
        'width="${w.toStringAsFixed(1)}" height="$height" fill="#$color"/>');
    x += w;
  }
  buf.writeln('</g></svg>');
  return buf.toString();
}

/// Encode un SVG en macro image AsciiDoc (data URI, sans fichier temporaire).
String svgImageMacro(String svg, {String alt = 'Répartition par sévérité'}) {
  final b64 = base64Encode(utf8.encode(svg));
  return 'image::data:image/svg+xml;base64,$b64[$alt,pdfwidth=100%]';
}

// ─── Version des scanners ─────────────────────────────────────────────────
//
// Exécute `<outil> --version` (ou équivalent) au moment de l'export, pour
// que le rapport reflète la version réellement installée — plutôt que de la
// capturer au moment du scan, qui peut dater de plusieurs jours. `null` si
// l'outil est absent du PATH ou si la sortie ne correspond pas au format
// attendu : les appelants doivent alors omettre la ligne plutôt que
// d'afficher "null".
Future<String?> _detectToolVersion(
  String executable,
  List<String> args,
  RegExp versionPattern,
) async {
  try {
    final result = await Process.run(executable, args);
    final output = '${result.stdout}\n${result.stderr}';
    return versionPattern.firstMatch(output)?.group(1);
  } catch (_) {
    return null;
  }
}

/// Ex. `grype version` → une ligne `Version:             0.118.0`.
Future<String?> grypeVersion() => _detectToolVersion(
    'grype', ['version'], RegExp(r'^Version:\s*(\S+)', multiLine: true));

/// Ex. `trivy --version` → une première ligne `Version: 0.74.0` (les
/// versions de bases de données qui suivent sont indentées, donc non
/// capturées par `^Version:` ancré en tout début de ligne).
Future<String?> trivyVersion() => _detectToolVersion(
    'trivy', ['--version'], RegExp(r'^Version:\s*(\S+)', multiLine: true));

/// Ex. `osv-scanner --version` → une première ligne
/// `osv-scanner version: 2.4.0`.
Future<String?> osvScannerVersion() => _detectToolVersion(
    'osv-scanner',
    ['--version'],
    RegExp(r'^osv-scanner version:\s*(\S+)', multiLine: true));

/// Formate une ligne `| Libellé | Version |` pour la table de résumé d'un
/// export, avec "indisponible" si la détection a échoué (outil absent du
/// PATH, sortie inattendue…).
String pdfToolVersionRow(String label, String? version) =>
    '| $label | ${version ?? '_indisponible_'}';
