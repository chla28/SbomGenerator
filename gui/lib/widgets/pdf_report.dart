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
const String kGuiVersion = '1.5.9';

// ─── Thème asciidoctor-pdf ──────────────────────────────────────────────────
//
// asciidoctor-pdf ne sait charger un thème que depuis un fichier réel sur
// disque (pas de data URI) : writePdfTheme() l'écrit dans le dossier temp
// système avant chaque conversion, et runAsciidoctorPdf() le référence via
// l'attribut CLI `pdf-theme` (pas besoin de `pdf-themesdir`, chemin absolu).
//
// IMPORTANT : ce thème est une copie synchronisée de `_kPdfThemeYaml` de
// `lib/scan_report_generator.dart` (paquet CLI) — garder les deux identiques.
// `extends: default-sans` : thème sans-serif fourni par asciidoctor-pdf
// (aucun fichier de police supplémentaire à embarquer).
const String _kPdfThemeYaml = '''
extends: default-sans
page:
  size: A4
  margin: [1.7cm, 1.7cm, 2.4cm, 1.7cm]
base:
  font_size: 9.8
  font_color: 222E39
  line_height: 1.42
link:
  font_color: 1A4C8B
heading:
  font_color: 1B3A5C
  font_style: bold
  line_height: 1.15
  margin_top: 14
  margin_bottom: 5
  h1:
    font_size: 20
    font_color: 15314F
  h2:
    font_size: 14
    font_color: 1B3A5C
    margin_top: 18
    border_bottom_width: 0.75
    border_bottom_color: D3DCE3
  h3:
    font_size: 11.5
    font_color: 2C4A63
    margin_top: 12
  h4:
    font_size: 10
    font_color: 46586A
title_page:
  text_align: left
  title:
    top: 34%
    font_size: 28
    font_color: 15314F
    line_height: 1.05
  subtitle:
    font_size: 13
    font_style: normal
    font_color: 566878
  authors:
    margin_top: 24
    font_size: 10.5
    font_color: 46586A
  revision:
    margin_top: 6
    font_size: 9.5
    font_color: 6B7A88
toc:
  font_color: 30455A
  dot_leader:
    font_color: C7D0D9
table:
  border_color: D3DCE3
  border_width: 0.5
  grid_width: 0.5
  cell_padding: [4, 6, 4, 6]
  head:
    background_color: 2C4A63
    font_color: FFFFFF
    font_style: bold
  body:
    stripe_background_color: F3F6F9
  foot:
    background_color: EEF2F5
admonition:
  border_color: D3DCE3
  border_width: 0.5
  background_color: F7F9FB
  padding: [8, 10, 8, 10]
  label:
    font_color: 46586A
code:
  background_color: F3F5F7
  border_color: E4E9ED
  border_width: 0.5
  font_size: 8.5
footer:
  font_size: 8
  font_color: 7A8894
  border_width: 0.5
  border_color: D3DCE3
  height: 26
  padding: [7, 2, 0, 2]
  vertical_align: top
  recto:
    left:
      content: '{document-title}'
    right:
      content: 'Page {page-number} / {page-count}'
  verso:
    left:
      content: '{document-title}'
    right:
      content: 'Page {page-number} / {page-count}'
role:
  h1-num:
    font_size: 19
    font_color: 15314F
    font_style: bold
  h1-num-alert:
    font_size: 19
    font_color: B3261E
    font_style: bold
  verdict-urgent:
    font_color: B3261E
    font_style: bold
  verdict-watch:
    font_color: 8A5000
    font_style: bold
  verdict-ok:
    font_color: 1B5E20
    font_style: bold
  muted:
    font_color: 6B7A88
  sev-critical:
    background_color: B3261E
    font_color: FFFFFF
    font_style: bold
  sev-high:
    background_color: C4531A
    font_color: FFFFFF
    font_style: bold
  sev-medium:
    background_color: B9770E
    font_color: FFFFFF
    font_style: bold
  sev-low:
    background_color: 2E7D32
    font_color: FFFFFF
    font_style: bold
  sev-other:
    background_color: 5B6B7A
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

/// Libellé français d'une sévérité (les scanners rapportent l'anglais, parfois
/// en casses différentes). Utilisé pour un rendu homogène dans les rapports.
String frenchSeverityLabel(String severity) => switch (severity.toLowerCase()) {
      'critical' => 'CRITIQUE',
      'high' => 'ÉLEVÉE',
      'medium' => 'MOYENNE',
      'low' => 'FAIBLE',
      'negligible' => 'NÉGLIGEABLE',
      '' => '?',
      _ => severity.toUpperCase(),
    };

/// Rend une sévérité en badge coloré AsciiDoc (`[.sev-xxx]#LIBELLÉ#`), libellé
/// francisé, à utiliser directement comme contenu d'une cellule de tableau.
String pdfSeverityBadge(String severity) =>
    '[.${_severityRole(severity)}]#${frenchSeverityLabel(severity)}#';

/// Date longue en français, ex. « 8 septembre 2026 » — pour l'en-tête des
/// rapports (évite une dépendance `intl`).
String pdfFrenchDate(DateTime d) {
  const months = [
    'janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août',
    'septembre', 'octobre', 'novembre', 'décembre'
  ];
  return '${d.day} ${months[d.month - 1]} ${d.year}';
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
    (critical, 'B3261E'),
    (high, 'C4531A'),
    (medium, 'B9770E'),
    (low, '2E7D32'),
    (other > 0 ? other : 0, '5B6B7A'),
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
