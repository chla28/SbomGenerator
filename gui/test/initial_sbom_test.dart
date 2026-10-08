import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/home_screen.dart';
import 'package:sbom_generator_gui/l10n/l10n.dart';
import 'package:sbom_generator_gui/main.dart' show parseSbomArg;
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  test('parseSbomArg lit --sbom <chemin> et --sbom=<chemin>', () {
    expect(parseSbomArg(const []), isNull);
    expect(parseSbomArg(const ['--sbom']), isNull);
    expect(parseSbomArg(const ['--sbom', '/a/b.cdx.json']), '/a/b.cdx.json');
    expect(parseSbomArg(const ['x', '--sbom=/c.json']), '/c.json');
  });

  testWidgets('--sbom ouvre l\'onglet Grype avec le fichier prérempli', (
    tester,
  ) async {
    final old = FlutterError.onError;
    FlutterError.onError = (d) {
      if (d.toString().contains('overflowed')) return;
      old?.call(d);
    };
    addTearDown(() => FlutterError.onError = old);
    tester.view.physicalSize = const Size(1600, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(
      MaterialApp(
        locale: const Locale('fr'),
        localizationsDelegates: const [
          AppLocalizations.delegate,
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
        ],
        supportedLocales: AppLocalizations.supportedLocales,
        home: HomeScreen(
          initialSbom: '/tmp/demo.cdx.json',
          themeMode: ThemeMode.light,
          onThemeToggle: () {},
          themeIndex: 0,
          onThemeIndexChanged: (_) {},
          onLanguageChanged: (_) {},
        ),
      ),
    );
    await tester.pump(const Duration(milliseconds: 400));
    final tabs = tester.widget<TabBar>(find.byType(TabBar)).controller!;
    expect(tabs.index, 4);
    expect(find.text('/tmp/demo.cdx.json'), findsWidgets);
  });
}
