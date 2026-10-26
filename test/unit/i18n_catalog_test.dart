import 'dart:io';

import 'package:sbom_generator/l10n/en.dart';
import 'package:test/test.dart';

/// Extrait les textes passés à `tr(...)` : littéraux adjacents concaténés,
/// comme le fait Dart.
Map<String, String> extractTr(String source, String file) {
  final found = <String, String>{};
  final re = RegExp(r'(?<![\w.$])tr\(');
  for (final m in re.allMatches(source)) {
    var i = m.end;
    final buf = StringBuffer();
    var literals = 0;
    while (true) {
      while (i < source.length && ' \t\r\n'.contains(source[i])) {
        i++;
      }
      if (source.startsWith('//', i)) {
        while (i < source.length && source[i] != '\n') {
          i++;
        }
        continue;
      }
      if (i >= source.length || (source[i] != "'" && source[i] != '"')) break;
      final triple = source.startsWith(source[i] * 3, i);
      final quote = source[i];
      i += triple ? 3 : 1;
      if (triple && source[i] == '\n') i++;
      bool closed() =>
          triple ? source.startsWith(quote * 3, i) : source[i] == quote;
      while (i < source.length && !closed()) {
        if (source[i] == r'\') {
          final next = source[i + 1];
          buf.write(switch (next) {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            _ => next,
          });
          i += 2;
        } else {
          buf.write(source[i++]);
        }
      }
      i += triple ? 3 : 1;
      literals++;
    }
    if (literals > 0) found[buf.toString()] = file;
  }
  return found;
}

Map<String, String> sourceTexts() {
  final all = <String, String>{};
  for (final dir in ['lib', 'bin']) {
    for (final f in Directory(dir).listSync(recursive: true)) {
      if (f is! File || !f.path.endsWith('.dart')) continue;
      if (f.path.contains('/l10n/') || f.path.endsWith('lib/i18n.dart')) {
        continue;
      }
      all.addAll(extractTr(f.readAsStringSync(), f.path));
    }
  }
  return all;
}

Set<String> placeholders(String s) =>
    RegExp(r'\{(\w+)\}').allMatches(s).map((m) => m[1]!).toSet();

void main() {
  final texts = sourceTexts();

  test('chaque texte passé à tr() a sa traduction anglaise', () {
    final missing = texts.entries
        .where((e) => !catalogEn.containsKey(e.key))
        .map((e) => '${e.value}: ${e.key}')
        .toList();
    expect(missing, isEmpty, reason: missing.take(20).join('\n'));
  });

  test("le catalogue ne garde pas d'entrée orpheline", () {
    final orphans = catalogEn.keys.where((k) => !texts.containsKey(k)).toList();
    expect(orphans, isEmpty, reason: orphans.take(20).join('\n'));
  });

  test('les paramètres {nom} sont identiques en français et en anglais', () {
    final bad = catalogEn.entries
        .where((e) =>
            !placeholders(e.key).containsAll(placeholders(e.value)) ||
            !placeholders(e.value).containsAll(placeholders(e.key)))
        .map((e) => e.key)
        .toList();
    expect(bad, isEmpty, reason: bad.take(20).join('\n'));
  });
}
