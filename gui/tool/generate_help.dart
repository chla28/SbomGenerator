// Génère les assets de l'aide en ligne de la GUI à partir de doc/user.adoc
// (français → assets/help/manual) et doc/user.en.adoc (anglais →
// assets/help/manual_en).
//
// À relancer manuellement (`dart run tool/generate_help.dart` depuis `gui/`)
// après toute modification de doc/user.adoc — voir la note dans
// doc/developer.adoc, section « Aide en ligne ». Nécessite `asciidoctor`
// installé (même dépendance que l'export PDF), utilisé uniquement au moment
// de la génération : l'appli elle-même n'exécute jamais asciidoctor, elle
// ne fait que lire les fichiers HTML déjà produits ici.
//
// Sortie : assets/help/manual/<n>.html (un fichier par chapitre, découpé à
// chaque titre `== ` de niveau 1) + assets/help/manual/toc.json (titres de
// chapitres dans l'ordre, et index ancre → chapitre pour la navigation des
// renvois internes `<<sec-xxx>>`).
import 'dart:convert';
import 'dart:io';

import 'package:html/parser.dart' as html_parser;

Future<void> main() async {
  final guiDir = File(Platform.script.toFilePath()).parent.parent;
  for (final (adoc, out) in const [
    ('user.adoc', 'manual'),
    ('user.en.adoc', 'manual_en'),
  ]) {
    await _generate(
      guiDir,
      '${guiDir.path}/doc/$adoc',
      '${guiDir.path}/assets/help/$out',
    );
  }
}

Future<void> _generate(
  Directory guiDir,
  String adocPath,
  String outPath,
) async {
  final outDir = Directory(outPath);

  if (!File(adocPath).existsSync()) {
    stderr.writeln('Introuvable : $adocPath');
    exit(1);
  }

  final tmpHtml = File(
    '${Directory.systemTemp.path}/sbom_generator_gui_help_src_${outDir.uri.pathSegments.where((e) => e.isNotEmpty).last}.html',
  );
  final result = await Process.run('asciidoctor', [
    '-o', tmpHtml.path,
    '-a', 'icons!', // labels texte ("Note", "Astuce"…) plutôt qu'une police
    // d'icônes externe que flutter_html ne peut pas charger.
    '-a', 'toc!', // le sommaire est reconstruit côté Flutter (liste des
    // chapitres, navigable sans JS ni ancre de défilement HTML).
    adocPath,
  ]);
  if (result.exitCode != 0) {
    stderr.writeln('asciidoctor a échoué :\n${result.stderr}');
    exit(1);
  }

  final document = html_parser.parse(await tmpHtml.readAsString());
  final content = document.querySelector('#content');
  if (content == null) {
    stderr.writeln(
      'Structure HTML inattendue (div#content introuvable) — le script '
      'suppose la sortie par défaut d\'asciidoctor (backend html5).',
    );
    exit(1);
  }

  // asciidoctor enveloppe déjà chaque section de premier niveau dans un
  // <div class="sect1"> propre, enfant direct de #content — un chapitre
  // par div, pas besoin de redécouper nous-mêmes au fil des <h2>.
  final chapters = content.children
      .where((e) => e.classes.contains('sect1'))
      .toList();
  if (chapters.isEmpty) {
    stderr.writeln('Aucune section (div.sect1) trouvée dans le manuel.');
    exit(1);
  }
  final titles = [
    for (final ch in chapters)
      (ch.querySelector('h2')?.text ?? '')
          .replaceFirst(RegExp(r'^\d+\.\s*'), '')
          .trim(),
  ];

  if (outDir.existsSync()) outDir.deleteSync(recursive: true);
  outDir.createSync(recursive: true);

  // anchorId -> index de chapitre, pour que les renvois internes
  // (<<sec-xxx>>, rendus en <a href="#sec-xxx">) puissent, au clic, faire
  // basculer le lecteur sur le bon chapitre.
  final anchorIndex = <String, int>{};
  final chapterFiles = <String>[];

  for (var i = 0; i < chapters.length; i++) {
    final chapter = chapters[i];
    // On garde le contenu de la section (les enfants du <div class="sect1">
    // — h2, .sectionbody…) plutôt que le div englobant lui-même, dont la
    // classe "sect1" n'a pas de style particulier côté flutter_html.
    final html = chapter.innerHtml;
    await File('${outDir.path}/$i.html').writeAsString(html);
    chapterFiles.add('$i.html');

    final id = chapter.attributes['id'];
    if (id != null && id.isNotEmpty) anchorIndex[id] = i;
    for (final inner in chapter.querySelectorAll('[id]')) {
      final innerId = inner.attributes['id'];
      if (innerId != null && innerId.isNotEmpty) anchorIndex[innerId] = i;
    }
  }

  final manifest = {
    'chapters': [
      for (var i = 0; i < chapters.length; i++)
        {'title': titles[i], 'file': chapterFiles[i]},
    ],
    'anchors': anchorIndex,
  };
  await File(
    '${outDir.path}/toc.json',
  ).writeAsString(const JsonEncoder.withIndent('  ').convert(manifest));

  stdout.writeln(
    'Aide générée : ${chapters.length} chapitres → ${outDir.path}',
  );
}
