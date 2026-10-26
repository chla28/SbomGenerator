import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/i18n.dart';
import 'package:sbom_generator_gui/l10n/en.dart';
import 'package:sbom_generator_gui/l10n/l10n.dart';
import 'package:sbom_generator_gui/main.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Extrait les textes passés à `tr(...)` : littéraux adjacents concaténés,
/// comme le fait Dart.
Map<String, String> _extractTr(String source, String file) {
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

Map<String, String> _sourceTexts() {
  final all = <String, String>{};
  for (final f in Directory('lib').listSync(recursive: true)) {
    if (f is! File || !f.path.endsWith('.dart')) continue;
    if (f.path.contains('/l10n/') || f.path.endsWith('lib/i18n.dart')) continue;
    all.addAll(_extractTr(f.readAsStringSync(), f.path));
  }
  return all;
}

Set<String> _placeholders(String message) =>
    RegExp(r'\{(\w+)\}').allMatches(message).map((m) => m.group(1)!).toSet();

void main() {
  tearDown(() => appLocale = fallbackLocale);

  group('catalogue anglais', () {
    final texts = _sourceTexts();

    test('chaque texte passé à tr() a sa traduction anglaise', () {
      final missing = texts.entries
          .where((e) => !catalogEn.containsKey(e.key))
          .map((e) => '${e.value}: ${e.key}')
          .toList();
      expect(missing, isEmpty, reason: missing.take(20).join('\n'));
    });

    test("le catalogue ne garde pas d'entrée orpheline", () {
      final orphans = catalogEn.keys
          .where((k) => !texts.containsKey(k))
          .toList();
      expect(orphans, isEmpty, reason: orphans.take(20).join('\n'));
    });

    test('mêmes {paramètres} en français et en anglais', () {
      for (final e in catalogEn.entries) {
        expect(_placeholders(e.value), _placeholders(e.key), reason: e.key);
      }
    });
  });

  test('langue : résolution et repli sur le français', () {
    expect(resolveAppLocale([const Locale('en', 'US')]), const Locale('en'));
    expect(
      resolveAppLocale([const Locale('de'), const Locale('fr', 'CA')]),
      const Locale('fr'),
    );
    expect(resolveAppLocale([const Locale('de')]), fallbackLocale);
    expect(resolveAppLocale(null), fallbackLocale);
    expect(AppLanguage.parse('en'), AppLanguage.en);
    expect(AppLanguage.parse(null), AppLanguage.system);
    expect(AppLanguage.parse('xx'), AppLanguage.system);
    expect(AppLanguage.system.locale, isNull);
  });

  test('tr() suit la langue de l\'application', () {
    appLocale = const Locale('en');
    expect(tr('Système'), 'System');
    appLocale = const Locale('fr');
    expect(tr('Système'), 'Système');
  });

  testWidgets('menu de langue : bascule de l\'application et mémorisation', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    tester.view.physicalSize = const Size(1600, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    // Débordements RenderFlex préexistants du panneau de configuration avec
    // la police de test (même filtre que config_panel_input_test.dart).
    final originalOnError = FlutterError.onError;
    FlutterError.onError = (details) {
      if (details.toString().contains('A RenderFlex overflowed')) return;
      originalOnError?.call(details);
    };
    addTearDown(() => FlutterError.onError = originalOnError);

    await tester.pumpWidget(
      const SbomGeneratorApp(initialLanguage: AppLanguage.en),
    );
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.byTooltip('Interface language'), findsOneWidget);

    await tester.tap(find.byKey(const Key('language-menu')));
    await tester.pump();
    await tester.pump(const Duration(seconds: 1));
    await tester.tap(find.text('Français').last);
    await tester.pump();
    await tester.pump(const Duration(seconds: 1));
    expect(find.byTooltip('Langue de l\'interface'), findsOneWidget);
    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString('ui_language_v1'), 'fr');
  });
}
