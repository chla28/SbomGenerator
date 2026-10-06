import 'package:html/dom.dart';
import 'package:html/parser.dart' as html_parser;

/// Identifiant HTML de la n-ième occurrence surlignée.
String hitId(int n) => 'hit-$n';

/// Surligne toutes les occurrences de [query] (insensible à la casse) dans le
/// texte du fragment [html] : chacune est enveloppée dans `<mark id="hit-N">`,
/// l'occurrence [current] portant en plus la classe `cur`. Le contenu des
/// balises `script`, `style` n'est pas touché. Retourne le HTML modifié et le
/// nombre d'occurrences.
({String html, int count}) highlightHtml(
  String html,
  String query, {
  int current = 0,
}) {
  final q = query.trim();
  if (q.isEmpty) return (html: html, count: 0);
  final lowerQ = q.toLowerCase();
  final doc = html_parser.parseFragment(html);
  var n = 0;

  void walk(Node node) {
    // Copie : on remplace des enfants pendant le parcours.
    for (final child in List<Node>.of(node.nodes)) {
      if (child is Element &&
          (child.localName == 'script' || child.localName == 'style')) {
        continue;
      }
      if (child is Text) {
        final text = child.text;
        final lower = text.toLowerCase();
        // `toLowerCase` peut changer la longueur de certains caractères
        // (ex. « İ ») : dans ce cas on ne surligne pas ce nœud.
        if (lower.length != text.length || !lower.contains(lowerQ)) continue;
        final parts = <Node>[];
        var pos = 0;
        while (true) {
          final i = lower.indexOf(lowerQ, pos);
          if (i < 0) break;
          if (i > pos) parts.add(Text(text.substring(pos, i)));
          final mark = Element.tag('mark')
            ..attributes['id'] = hitId(n)
            ..append(Text(text.substring(i, i + q.length)));
          if (n == current) mark.classes.add('cur');
          parts.add(mark);
          n++;
          pos = i + q.length;
        }
        if (pos < text.length) parts.add(Text(text.substring(pos)));
        final parent = child.parent!;
        final at = parent.nodes.indexOf(child);
        parent.nodes.removeAt(at);
        parent.nodes.insertAll(at, parts);
      } else {
        walk(child);
      }
    }
  }

  walk(doc);
  return (html: doc.outerHtml, count: n);
}
