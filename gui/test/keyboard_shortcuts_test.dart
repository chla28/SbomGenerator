import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/home_screen.dart';
import 'package:sbom_generator_gui/l10n/l10n.dart';
import 'package:shared_preferences/shared_preferences.dart';

Widget _app() => MaterialApp(
  locale: const Locale('fr'),
  localizationsDelegates: const [
    AppLocalizations.delegate,
    GlobalMaterialLocalizations.delegate,
    GlobalWidgetsLocalizations.delegate,
    GlobalCupertinoLocalizations.delegate,
  ],
  supportedLocales: AppLocalizations.supportedLocales,
  home: HomeScreen(
    themeMode: ThemeMode.light,
    onThemeToggle: () {},
    themeIndex: 0,
    onThemeIndexChanged: (_) {},
    onLanguageChanged: (_) {},
  ),
);

Future<void> _ctrl(WidgetTester tester, LogicalKeyboardKey key) async {
  await tester.sendKeyDownEvent(LogicalKeyboardKey.controlLeft);
  await tester.sendKeyEvent(key);
  await tester.sendKeyUpEvent(LogicalKeyboardKey.controlLeft);
  await tester.pump(const Duration(milliseconds: 400));
}

/// La police de test (Ahem) est plus large que la vraie : les débordements de
/// mise en page du panneau de configuration n'ont pas d'intérêt ici.
void _ignoreOverflow() {
  final old = FlutterError.onError;
  FlutterError.onError = (d) {
    if (d.toString().contains('overflowed')) return;
    old?.call(d);
  };
  addTearDown(() => FlutterError.onError = old);
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets('Ctrl+chiffre et Ctrl+PgSuiv changent d\'onglet', (tester) async {
    _ignoreOverflow();
    tester.view.physicalSize = const Size(1600, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(_app());
    await tester.pump();

    TabController tabs() =>
        DefaultTabController.maybeOf(tester.element(find.byType(TabBar))) ??
        tester.widget<TabBar>(find.byType(TabBar)).controller!;

    expect(tabs().index, 0);
    await _ctrl(tester, LogicalKeyboardKey.digit3);
    expect(tabs().index, 2, reason: 'Ctrl+3 = 3e onglet (tableau de bord)');
    await _ctrl(tester, LogicalKeyboardKey.pageDown);
    expect(tabs().index, 3);
    await _ctrl(tester, LogicalKeyboardKey.pageUp);
    await _ctrl(tester, LogicalKeyboardKey.pageUp);
    expect(tabs().index, 1);
    await _ctrl(tester, LogicalKeyboardKey.digit1);
    await _ctrl(tester, LogicalKeyboardKey.pageUp);
    expect(tabs().index, 14, reason: 'retour en fin de liste');
  });

  testWidgets('Ctrl+/ affiche la liste des raccourcis', (tester) async {
    _ignoreOverflow();
    tester.view.physicalSize = const Size(1600, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(_app());
    await tester.pump();

    await _ctrl(tester, LogicalKeyboardKey.slash);
    await tester.pumpAndSettle();
    expect(find.text('Raccourcis clavier'), findsWidgets);
    expect(find.text('Ctrl+Entrée'), findsOneWidget);
    await tester.tap(find.text('Fermer'));
    await tester.pumpAndSettle();
    expect(find.text('Ctrl+Entrée'), findsNothing);

    // Le bouton de la barre d'application fait de même.
    await tester.tap(find.byTooltip('Raccourcis clavier'));
    await tester.pumpAndSettle();
    expect(find.text('Ctrl+Entrée'), findsOneWidget);
  });

  testWidgets('Échap sans exécution en cours : sans effet', (tester) async {
    _ignoreOverflow();
    tester.view.physicalSize = const Size(1600, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(_app());
    await tester.pump();
    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await tester.pump();
    expect(find.byType(HomeScreen), findsOneWidget);
  });
}
