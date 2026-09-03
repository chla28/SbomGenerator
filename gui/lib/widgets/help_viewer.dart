import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_html/flutter_html.dart';
import 'package:html/parser.dart' as html_parser;
import 'package:url_launcher/url_launcher.dart';

/// Visionneuse du manuel utilisateur (doc/user.adoc) directement dans la
/// GUI, sans quitter l'appli. Le contenu est pré-généré en HTML (un fichier
/// par chapitre + un sommaire) par `tool/generate_help.dart` — voir la note
/// dans doc/developer.adoc, section « Aide en ligne ».
class HelpViewerScreen extends StatefulWidget {
  /// Chapitre à afficher à l'ouverture (index dans toc.json), 0 par défaut.
  final int initialChapter;

  const HelpViewerScreen({super.key, this.initialChapter = 0});

  @override
  State<HelpViewerScreen> createState() => _HelpViewerScreenState();
}

class _HelpViewerScreenState extends State<HelpViewerScreen> {
  static const _base = 'assets/help/manual';

  List<_Chapter> _chapters = const [];
  Map<String, int> _anchors = const {};
  // Contenu HTML et texte brut (pour la recherche) de tous les chapitres,
  // chargés une fois pour toutes au démarrage — 21 fichiers, ~240 Ko au
  // total, un coût négligeable qui évite tout aller-retour disque pendant
  // la frappe dans le champ de recherche.
  List<String> _chapterHtml = const [];
  List<String> _chapterText = const [];

  int _selected = 0;
  String? _error;
  bool _loading = true;
  final _scrollController = ScrollController();
  final _searchController = TextEditingController();
  String _query = '';

  @override
  void initState() {
    super.initState();
    _selected = widget.initialChapter;
    _searchController.addListener(() {
      setState(() => _query = _searchController.text.trim());
    });
    _loadAll();
  }

  @override
  void dispose() {
    _scrollController.dispose();
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _loadAll() async {
    try {
      final rawToc = await rootBundle.loadString('$_base/toc.json');
      final json = jsonDecode(rawToc) as Map<String, dynamic>;
      final chapters = (json['chapters'] as List)
          .map((c) => _Chapter(
                title: c['title'] as String,
                file: c['file'] as String,
              ))
          .toList();
      final anchors = (json['anchors'] as Map<String, dynamic>)
          .map((k, v) => MapEntry(k, v as int));

      final htmls = await Future.wait(
          chapters.map((c) => rootBundle.loadString('$_base/${c.file}')));
      final texts = htmls.map(_stripHtml).toList();

      if (!mounted) return;
      setState(() {
        _chapters = chapters;
        _anchors = anchors;
        _chapterHtml = htmls;
        _chapterText = texts;
        _loading = false;
      });
      if (_selected < 0 || _selected >= chapters.length) _selected = 0;
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = 'Aide indisponible : impossible de charger le manuel ($e).';
      });
    }
  }

  /// Texte brut d'un fragment HTML (pour la recherche), via un vrai parseur
  /// HTML plutôt qu'une regex — gère correctement les entités (&#8217;…).
  static String _stripHtml(String html) =>
      html_parser.parse(html).documentElement?.text ?? '';

  void _selectChapter(int index) {
    if (index < 0 || index >= _chapters.length) return;
    setState(() => _selected = index);
    if (_scrollController.hasClients) _scrollController.jumpTo(0);
  }

  void _onAnchorTap(String? url, Map<String, String> attrs, dynamic element) {
    if (url == null) return;
    if (url.startsWith('#')) {
      final target = _anchors[url.substring(1)];
      if (target != null) _selectChapter(target);
      return;
    }
    launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
  }

  /// Indices des chapitres correspondant à la recherche courante (titre ou
  /// contenu), dans l'ordre du sommaire — tous si la recherche est vide.
  List<int> get _visibleIndices {
    if (_query.isEmpty) return List.generate(_chapters.length, (i) => i);
    final q = _query.toLowerCase();
    return [
      for (var i = 0; i < _chapters.length; i++)
        if (_chapters[i].title.toLowerCase().contains(q) ||
            _chapterText[i].toLowerCase().contains(q))
          i,
    ];
  }

  /// Extrait de contexte autour de la première occurrence de [_query] dans
  /// le texte du chapitre [i] — null si la correspondance ne vient que du
  /// titre (pas la peine de répéter le titre en extrait).
  String? _snippetFor(int i) {
    if (_query.isEmpty) return null;
    final text = _chapterText[i];
    final q = _query.toLowerCase();
    final idx = text.toLowerCase().indexOf(q);
    if (idx == -1) return null;
    const radius = 60;
    final start = (idx - radius).clamp(0, text.length);
    final end = (idx + q.length + radius).clamp(0, text.length);
    final prefix = start > 0 ? '…' : '';
    final suffix = end < text.length ? '…' : '';
    return '$prefix${text.substring(start, end).trim()}$suffix';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final visible = _visibleIndices;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Aide — Manuel utilisateur'),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _error != null
              ? Center(
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: Text(_error!, textAlign: TextAlign.center),
                  ),
                )
              : Row(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    SizedBox(
                      width: 320,
                      child: Column(
                        children: [
                          Padding(
                            padding: const EdgeInsets.all(8),
                            child: TextField(
                              controller: _searchController,
                              decoration: InputDecoration(
                                hintText: 'Rechercher dans le manuel…',
                                prefixIcon: const Icon(Icons.search, size: 20),
                                suffixIcon: _query.isEmpty
                                    ? null
                                    : IconButton(
                                        icon: const Icon(Icons.clear, size: 18),
                                        tooltip: 'Effacer',
                                        onPressed: _searchController.clear,
                                      ),
                                isDense: true,
                                border: OutlineInputBorder(
                                  borderRadius: BorderRadius.circular(8),
                                ),
                              ),
                            ),
                          ),
                          Expanded(
                            child: visible.isEmpty
                                ? Padding(
                                    padding: const EdgeInsets.all(16),
                                    child: Text(
                                      'Aucun chapitre ne contient « $_query ».',
                                      style: theme.textTheme.bodySmall,
                                    ),
                                  )
                                : ListView.builder(
                                    itemCount: visible.length,
                                    itemBuilder: (context, pos) {
                                      final i = visible[pos];
                                      final selected = i == _selected;
                                      final snippet = _snippetFor(i);
                                      return ListTile(
                                        dense: true,
                                        selected: selected,
                                        selectedTileColor: theme
                                            .colorScheme.primary
                                            .withValues(alpha: 0.1),
                                        title: Text(
                                          '${i + 1}. ${_chapters[i].title}',
                                          style: TextStyle(
                                            fontWeight: selected
                                                ? FontWeight.bold
                                                : FontWeight.normal,
                                            color: selected
                                                ? theme.colorScheme.primary
                                                : null,
                                          ),
                                        ),
                                        subtitle: snippet == null
                                            ? null
                                            : Text(
                                                snippet,
                                                maxLines: 2,
                                                overflow: TextOverflow.ellipsis,
                                                style: theme.textTheme.bodySmall,
                                              ),
                                        onTap: () => _selectChapter(i),
                                      );
                                    },
                                  ),
                          ),
                        ],
                      ),
                    ),
                    const VerticalDivider(width: 1),
                    Expanded(
                      child: SingleChildScrollView(
                        controller: _scrollController,
                        padding: const EdgeInsets.symmetric(
                            horizontal: 32, vertical: 24),
                        child: Html(
                          data: _chapterHtml[_selected],
                          onAnchorTap: _onAnchorTap,
                          style: _helpStyle(theme),
                        ),
                      ),
                    ),
                  ],
                ),
    );
  }
}

class _Chapter {
  final String title;
  final String file;
  const _Chapter({required this.title, required this.file});
}

/// Style du contenu HTML calqué sur le thème Material courant, pour rester
/// cohérent en mode clair comme sombre (voir aussi pdf_report.dart pour le
/// thème équivalent des exports PDF).
Map<String, Style> _helpStyle(ThemeData theme) {
  final onSurface = theme.colorScheme.onSurface;
  final codeBg = theme.colorScheme.surfaceContainerHighest;
  return {
    'body': Style(
      color: onSurface,
      fontSize: FontSize(14),
      lineHeight: LineHeight(1.5),
      margin: Margins.zero,
    ),
    'h2': Style(
      color: theme.colorScheme.primary,
      fontSize: FontSize(22),
      fontWeight: FontWeight.bold,
      margin: Margins.only(top: 0, bottom: 12),
    ),
    'h3': Style(
      color: theme.colorScheme.primary,
      fontSize: FontSize(17),
      fontWeight: FontWeight.bold,
      margin: Margins.only(top: 20, bottom: 8),
    ),
    'h4': Style(
      fontSize: FontSize(15),
      fontWeight: FontWeight.bold,
      margin: Margins.only(top: 16, bottom: 6),
    ),
    'a': Style(color: theme.colorScheme.primary),
    'code': Style(
      backgroundColor: codeBg,
      fontFamily: 'monospace',
      padding: HtmlPaddings.symmetric(horizontal: 4),
    ),
    'pre': Style(
      backgroundColor: codeBg,
      padding: HtmlPaddings.all(12),
      margin: Margins.symmetric(vertical: 8),
    ),
    'table': Style(
      border: Border.all(color: theme.dividerColor),
      margin: Margins.symmetric(vertical: 12),
    ),
    'th': Style(
      backgroundColor: theme.colorScheme.surfaceContainerHighest,
      padding: HtmlPaddings.all(6),
      fontWeight: FontWeight.bold,
    ),
    'td': Style(
      padding: HtmlPaddings.all(6),
      border: Border.all(color: theme.dividerColor, width: 0.5),
    ),
    '.admonitionblock': Style(
      backgroundColor:
          theme.colorScheme.secondaryContainer.withValues(alpha: 0.4),
      padding: HtmlPaddings.all(12),
      margin: Margins.symmetric(vertical: 12),
    ),
    '.title': Style(
      fontWeight: FontWeight.bold,
      color: theme.colorScheme.secondary,
    ),
  };
}
