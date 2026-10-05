import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/l10n/l10n.dart';
import 'package:sbom_generator_gui/main.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Clés de message (hors métadonnées `@…`) d'un fichier ARB.
Map<String, dynamic> _arb(String lang) =>
    jsonDecode(File('lib/l10n/app_$lang.arb').readAsStringSync())
        as Map<String, dynamic>;

Set<String> _placeholders(String message) =>
    RegExp(r'\{(\w+)').allMatches(message).map((m) => m.group(1)!).toSet();

void main() {
  group('fichiers ARB', () {
    final fr = _arb('fr');
    final languages = Directory('lib/l10n')
        .listSync()
        .map((e) => e.path.split('/').last)
        .where((n) => n.startsWith('app_') && n.endsWith('.arb'))
        .map((n) => n.substring(4, n.length - 4))
        .toList();
    final keys = {
      for (final k in fr.keys)
        if (!k.startsWith('@')) k,
    };

    test('le français (référence) documente chaque clé', () {
      for (final k in keys) {
        final meta = fr['@$k'];
        expect(
          meta is Map && (meta['description'] as String?)?.isNotEmpty == true,
          isTrue,
          reason: 'app_fr.arb : @$k.description manquante',
        );
      }
    });

    for (final lang in languages.where((l) => l != 'fr')) {
      test('$lang : mêmes clés et mêmes paramètres que le français', () {
        final other = _arb(lang);
        final otherKeys = {
          for (final k in other.keys)
            if (!k.startsWith('@')) k,
        };
        expect(
          otherKeys.difference(keys),
          isEmpty,
          reason: 'clés inconnues de app_fr.arb',
        );
        expect(
          keys.difference(otherKeys),
          isEmpty,
          reason: 'clés non traduites dans app_$lang.arb',
        );
        for (final k in keys) {
          expect(
            _placeholders(other[k] as String),
            _placeholders(fr[k] as String),
            reason: 'paramètres différents pour « $k »',
          );
        }
      });
    }
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

  testWidgets('context.l10n : langue de l\'application, repli hors délégués', (
    tester,
  ) async {
    late String inApp;
    late String bare;
    await tester.pumpWidget(
      MaterialApp(
        locale: const Locale('en'),
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: Builder(
          builder: (context) {
            inApp = context.l10n.languageSystem;
            return const SizedBox();
          },
        ),
      ),
    );
    expect(inApp, 'System');

    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) {
            bare = context.l10n.languageSystem;
            return const SizedBox();
          },
        ),
      ),
    );
    expect(bare, 'Système');
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
