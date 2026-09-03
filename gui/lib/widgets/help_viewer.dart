import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_html/flutter_html.dart';
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
  int _selected = 0;
  String? _html;
  String? _error;
  final _scrollController = ScrollController();

  @override
  void initState() {
    super.initState();
    _selected = widget.initialChapter;
    _loadToc();
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _loadToc() async {
    try {
      final raw = await rootBundle.loadString('$_base/toc.json');
      final json = jsonDecode(raw) as Map<String, dynamic>;
      final chapters = (json['chapters'] as List)
          .map((c) => _Chapter(
                title: c['title'] as String,
                file: c['file'] as String,
              ))
          .toList();
      final anchors = (json['anchors'] as Map<String, dynamic>)
          .map((k, v) => MapEntry(k, v as int));
      if (!mounted) return;
      setState(() {
        _chapters = chapters;
        _anchors = anchors;
      });
      await _loadChapter(_selected);
    } catch (e) {
      if (!mounted) return;
      setState(() => _error =
          'Aide indisponible : impossible de charger le sommaire ($e).');
    }
  }

  Future<void> _loadChapter(int index) async {
    if (index < 0 || index >= _chapters.length) return;
    try {
      final html = await rootBundle.loadString(
          '$_base/${_chapters[index].file}');
      if (!mounted) return;
      setState(() {
        _selected = index;
        _html = html;
        _error = null;
      });
      if (_scrollController.hasClients) _scrollController.jumpTo(0);
    } catch (e) {
      if (!mounted) return;
      setState(() =>
          _error = 'Impossible de charger ce chapitre (${_chapters[index].title}) : $e');
    }
  }

  void _onAnchorTap(String? url, Map<String, String> attrs, dynamic element) {
    if (url == null) return;
    if (url.startsWith('#')) {
      final target = _anchors[url.substring(1)];
      if (target != null) _loadChapter(target);
      return;
    }
    launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('Aide — Manuel utilisateur'),
      ),
      body: _error != null && _chapters.isEmpty
          ? Center(child: Padding(
              padding: const EdgeInsets.all(24),
              child: Text(_error!, textAlign: TextAlign.center),
            ))
          : Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                SizedBox(
                  width: 280,
                  child: _chapters.isEmpty
                      ? const Center(
                          child: Padding(
                            padding: EdgeInsets.all(24),
                            child: CircularProgressIndicator(),
                          ),
                        )
                      : ListView.builder(
                          itemCount: _chapters.length,
                          itemBuilder: (context, i) {
                            final selected = i == _selected;
                            return ListTile(
                              dense: true,
                              selected: selected,
                              selectedTileColor:
                                  theme.colorScheme.primary.withValues(alpha: 0.1),
                              title: Text(
                                '${i + 1}. ${_chapters[i].title}',
                                style: TextStyle(
                                  fontWeight:
                                      selected ? FontWeight.bold : FontWeight.normal,
                                  color: selected ? theme.colorScheme.primary : null,
                                ),
                              ),
                              onTap: () => _loadChapter(i),
                            );
                          },
                        ),
                ),
                const VerticalDivider(width: 1),
                Expanded(
                  child: _error != null
                      ? Center(child: Padding(
                          padding: const EdgeInsets.all(24),
                          child: Text(_error!, textAlign: TextAlign.center),
                        ))
                      : _html == null
                          ? const Center(child: CircularProgressIndicator())
                          : SingleChildScrollView(
                              controller: _scrollController,
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 32, vertical: 24),
                              child: Html(
                                data: _html!,
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
      backgroundColor: theme.colorScheme.secondaryContainer.withValues(alpha: 0.4),
      padding: HtmlPaddings.all(12),
      margin: Margins.symmetric(vertical: 12),
    ),
    '.title': Style(
      fontWeight: FontWeight.bold,
      color: theme.colorScheme.secondary,
    ),
  };
}
