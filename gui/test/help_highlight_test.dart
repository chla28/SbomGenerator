import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/help_highlight.dart';

void main() {
  test('surligne chaque occurrence, insensible à la casse, numérotée', () {
    final r = highlightHtml('<p>Grype et GRYPE, puis grype.</p>', 'grype');
    expect(r.count, 3);
    expect(RegExp('<mark').allMatches(r.html), hasLength(3));
    expect(r.html, contains('id="hit-0"'));
    expect(r.html, contains('id="hit-2"'));
    expect(r.html, contains('>GRYPE</mark>'), reason: 'casse d\'origine');
  });

  test('l\'occurrence courante porte la classe « cur » (une seule)', () {
    final r = highlightHtml('<p>a b a b a</p>', 'a', current: 1);
    expect(RegExp('class="cur"').allMatches(r.html), hasLength(1));
    expect(r.html, contains('<mark id="hit-1" class="cur">a</mark>'));
  });

  test('ne touche pas aux balises ni aux attributs ; entités conservées', () {
    final r = highlightHtml(
      '<p class="grype">x &amp; <a href="grype">grype</a></p>',
      'grype',
    );
    expect(r.count, 1);
    expect(r.html, contains('class="grype"'));
    expect(r.html, contains('href="grype"'));
    expect(r.html, contains('&amp;'));
  });

  test('script et style ignorés ; requête vide : inchangé', () {
    final h = '<style>.grype{}</style><p>rien</p>';
    expect(highlightHtml(h, 'grype').count, 0);
    final e = highlightHtml('<p>x</p>', '  ');
    expect((e.html, e.count), ('<p>x</p>', 0));
  });

  test('texte imbriqué (gras, code) : toutes les occurrences', () {
    final r = highlightHtml(
      '<p>un <b>mot</b> et <code>mot</code> et mot</p>',
      'mot',
    );
    expect(r.count, 3);
  });
}
