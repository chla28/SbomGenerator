/// Copies d'écran hors affichage (README) : lancé seulement si SCREENSHOT_DIR
/// est défini, avec les polices système réelles.
///
///   PATH=/chemin/du/cli:$PATH SCREENSHOT_DIR=../doc/screenshots \
///     flutter test test/screenshot_test.dart
///
/// Les captures françaises sont écrites dans SCREENSHOT_DIR, les anglaises
/// dans SCREENSHOT_DIR/en. Les écrans « Conformité CRA » et « Qualité » lancent
/// le vrai CLI `sbom-generator` (et `sbomqs` s'il est installé) : le binaire
/// doit être dans le PATH.
library;

import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/l10n/l10n.dart';
import 'package:sbom_generator_gui/models/sbom_config.dart';
import 'package:sbom_generator_gui/models/sbom_result.dart';
import 'package:sbom_generator_gui/services/settings_service.dart';
import 'package:sbom_generator_gui/services/vuln_enrichment.dart';
import 'package:sbom_generator_gui/widgets/config_panel.dart';
import 'package:sbom_generator_gui/widgets/cra_panel.dart';
import 'package:sbom_generator_gui/widgets/dashboard_panel.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/osv_panel.dart';
import 'package:sbom_generator_gui/widgets/quality_panel.dart';
import 'package:sbom_generator_gui/widgets/results_panel.dart';
import 'package:sbom_generator_gui/widgets/trivy_panel.dart';
import 'package:sbom_generator_gui/widgets/vuln_shared.dart';
import 'package:shared_preferences/shared_preferences.dart';

final _dir = Platform.environment['SCREENSHOT_DIR'];

Future<void> _font(String family, List<String> files) async {
  final loader = FontLoader(family);
  for (final f in files) {
    if (File(f).existsSync()) {
      loader.addFont(
        Future.value(ByteData.sublistView(File(f).readAsBytesSync())),
      );
    }
  }
  await loader.load();
}

Locale _locale = const Locale('fr');
late String _sbomPath;

Future<void> _shot(WidgetTester tester, String name) async {
  final boundary = tester.renderObject<RenderRepaintBoundary>(
    find.byKey(const Key('shot')),
  );
  final image = await tester.runAsync(() => boundary.toImage(pixelRatio: 1));
  final bytes = await tester.runAsync(
    () => image!.toByteData(format: ui.ImageByteFormat.png),
  );
  final dir = _locale.languageCode == 'fr' ? _dir : '$_dir/en';
  Directory(dir!).createSync(recursive: true);
  File('$dir/$name.png').writeAsBytesSync(bytes!.buffer.asUint8List());
}

// ── Données de démonstration ────────────────────────────────────────────────

const _g = [
  GrypeVuln(
    id: 'CVE-2021-44228',
    severity: 'Critical',
    packageName: 'log4j-core',
    installedVersion: '2.14.1',
    fixedVersion: '2.17.1',
    packageType: 'java-archive',
  ),
  GrypeVuln(
    id: 'CVE-2022-22965',
    severity: 'Critical',
    packageName: 'spring-beans',
    installedVersion: '5.3.17',
    fixedVersion: '5.3.18',
    packageType: 'java-archive',
  ),
  GrypeVuln(
    id: 'CVE-2023-44487',
    severity: 'High',
    packageName: 'netty-codec-http2',
    installedVersion: '4.1.93',
    fixedVersion: '4.1.100',
    packageType: 'java-archive',
  ),
  GrypeVuln(
    id: 'CVE-2022-42889',
    severity: 'Critical',
    packageName: 'commons-text',
    installedVersion: '1.9',
    fixedVersion: '1.10.0',
    packageType: 'java-archive',
  ),
  GrypeVuln(
    id: 'CVE-2023-38545',
    severity: 'High',
    packageName: 'curl',
    installedVersion: '7.76.1-23.el9',
    fixedVersion: '7.76.1-26.el9',
    packageType: 'rpm',
  ),
  GrypeVuln(
    id: 'CVE-2024-6387',
    severity: 'High',
    packageName: 'openssh',
    installedVersion: '8.7p1-38.el9',
    fixedVersion: '8.7p1-38.el9_4.1',
    packageType: 'rpm',
  ),
  GrypeVuln(
    id: 'CVE-2022-37434',
    severity: 'Medium',
    packageName: 'zlib',
    installedVersion: '1.2.11-40.el9',
    fixedVersion: '1.2.11-41.el9',
    packageType: 'rpm',
  ),
  GrypeVuln(
    id: 'CVE-2023-4911',
    severity: 'High',
    packageName: 'glibc',
    installedVersion: '2.34-60.el9',
    fixedVersion: '2.34-83.el9_3.7',
    packageType: 'rpm',
  ),
  GrypeVuln(
    id: 'CVE-2021-3711',
    severity: 'Medium',
    packageName: 'expat',
    installedVersion: '2.2.10-12.el9',
    fixedVersion: '',
    packageType: 'rpm',
  ),
  GrypeVuln(
    id: 'CVE-2020-8908',
    severity: 'Low',
    packageName: 'guava',
    installedVersion: '30.1-jre',
    fixedVersion: '32.0.0-jre',
    packageType: 'java-archive',
  ),
];

const _o = [
  OsvVuln(
    id: 'CVE-2021-44228',
    severity: 'Critical',
    packageName: 'log4j-core',
    installedVersion: '2.14.1',
    fixedVersion: '2.17.1',
    ecosystem: 'Maven',
  ),
  OsvVuln(
    id: 'CVE-2022-22965',
    severity: 'Critical',
    packageName: 'spring-beans',
    installedVersion: '5.3.17',
    fixedVersion: '5.3.18',
    ecosystem: 'Maven',
  ),
  OsvVuln(
    id: 'CVE-2023-44487',
    severity: 'High',
    packageName: 'netty-codec-http2',
    installedVersion: '4.1.93',
    fixedVersion: '4.1.100',
    ecosystem: 'Maven',
  ),
  OsvVuln(
    id: 'CVE-2020-8908',
    severity: 'Low',
    packageName: 'guava',
    installedVersion: '30.1-jre',
    fixedVersion: '32.0.0-jre',
    ecosystem: 'Maven',
  ),
];

const _t = [
  TrivyVuln(
    id: 'CVE-2021-44228',
    severity: 'CRITICAL',
    packageName: 'log4j-core',
    installedVersion: '2.14.1',
    fixedVersion: '2.17.1',
    title: 'log4j: Remote code execution via JNDI lookups',
  ),
  TrivyVuln(
    id: 'CVE-2022-42889',
    severity: 'CRITICAL',
    packageName: 'commons-text',
    installedVersion: '1.9',
    fixedVersion: '1.10.0',
    title: 'commons-text: variable interpolation RCE',
  ),
  TrivyVuln(
    id: 'CVE-2023-38545',
    severity: 'HIGH',
    packageName: 'curl',
    installedVersion: '7.76.1-23.el9',
    fixedVersion: '7.76.1-26.el9',
    title: 'curl: SOCKS5 heap buffer overflow',
  ),
  TrivyVuln(
    id: 'CVE-2024-6387',
    severity: 'HIGH',
    packageName: 'openssh',
    installedVersion: '8.7p1-38.el9',
    fixedVersion: '8.7p1-38.el9_4.1',
    title: 'openssh: race condition in sshd signal handler',
  ),
  TrivyVuln(
    id: 'CVE-2022-37434',
    severity: 'MEDIUM',
    packageName: 'zlib',
    installedVersion: '1.2.11-40.el9',
    fixedVersion: '1.2.11-41.el9',
    title: 'zlib: heap buffer over-read in inflate',
  ),
];

final _exploit = <String, ExploitInfo>{
  'CVE-2021-44228': ExploitInfo(
    inKev: true,
    kevDateAdded: DateTime(2021, 12, 10),
    kevDueDate: DateTime(2021, 12, 24),
    kevRansomware: true,
    epssScore: 0.97,
    epssPercentile: 1.0,
    pocKnown: true,
    pocCount: 31,
    cvssBaseScore: 10.0,
    cvssExploitabilityScore: 3.9,
  ),
  'CVE-2022-22965': ExploitInfo(
    inKev: true,
    kevDateAdded: DateTime(2022, 4, 4),
    kevDueDate: DateTime(2022, 4, 25),
    epssScore: 0.97,
    epssPercentile: 0.999,
    pocKnown: true,
    pocCount: 12,
    cvssBaseScore: 9.8,
    cvssExploitabilityScore: 3.9,
  ),
  'CVE-2023-44487': ExploitInfo(
    inKev: true,
    kevDateAdded: DateTime(2023, 10, 10),
    epssScore: 0.94,
    epssPercentile: 0.998,
    pocKnown: true,
    pocCount: 8,
    cvssBaseScore: 7.5,
    cvssExploitabilityScore: 3.9,
  ),
  'CVE-2022-42889': ExploitInfo(
    epssScore: 0.93,
    epssPercentile: 0.997,
    pocKnown: true,
    pocCount: 5,
    cvssBaseScore: 9.8,
    cvssExploitabilityScore: 3.9,
  ),
  'CVE-2024-6387': ExploitInfo(
    epssScore: 0.31,
    epssPercentile: 0.97,
    pocKnown: true,
    pocCount: 4,
    cvssBaseScore: 8.1,
    cvssExploitabilityScore: 2.2,
  ),
  'CVE-2023-38545': ExploitInfo(
    epssScore: 0.07,
    epssPercentile: 0.91,
    cvssBaseScore: 9.8,
    cvssExploitabilityScore: 3.9,
  ),
  'CVE-2023-4911': ExploitInfo(
    inKev: true,
    kevDateAdded: DateTime(2023, 11, 21),
    epssScore: 0.58,
    epssPercentile: 0.985,
    pocKnown: true,
    pocCount: 6,
    cvssBaseScore: 7.8,
    cvssExploitabilityScore: 1.8,
  ),
};

/// Fournit les fichiers au second build : certains panneaux ne pré-remplissent
/// leur champ qu'au `didUpdateWidget`.
class _LateFiles extends StatefulWidget {
  final Widget Function(List<OutputFile>) build;
  final List<OutputFile> files;
  const _LateFiles(this.build, this.files);

  @override
  State<_LateFiles> createState() => _LateFilesState();
}

class _LateFilesState extends State<_LateFiles> {
  bool _ready = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback(
      (_) => setState(() => _ready = true),
    );
  }

  @override
  Widget build(BuildContext context) =>
      widget.build(_ready ? widget.files : <OutputFile>[]);
}

void main() {
  final flutterRoot =
      Platform.environment['FLUTTER_ROOT'] ??
      File(Platform.resolvedExecutable).parent.parent.parent.parent.path;

  setUpAll(() async {
    if (_dir == null) return;
    await _font('Roboto', [
      '/usr/share/fonts/adwaita-sans-fonts/AdwaitaSans-Regular.ttf',
    ]);
    await _font('monospace', [
      '/usr/share/fonts/adwaita-mono-fonts/AdwaitaMono-Regular.ttf',
    ]);
    // Police de repli du framework de test (Ahem : rectangles pleins) pour les
    // textes sans famille explicite.
    await _font('Ahem', [
      '/usr/share/fonts/adwaita-sans-fonts/AdwaitaSans-Regular.ttf',
    ]);
    await _font('MaterialIcons', [
      '$flutterRoot/bin/cache/artifacts/material_fonts/MaterialIcons-Regular.otf',
    ]);
    // SBOM réel (dépendances de la GUI) pour les onglets CRA et Qualité.
    final tmp = Directory('${Directory.systemTemp.path}/audit')
      ..createSync(recursive: true);
    final r = await Process.run('sbom-generator', [
      '--lang',
      'fr',
      '-i',
      'pubspec.lock',
      '-f',
      'cyclonedx',
      '-n',
      'SBOM Generator GUI',
      '-o',
      '${tmp.path}/sbom',
    ]);
    if (r.exitCode != 0) {
      fail('sbom-generator introuvable dans le PATH ou en échec : ${r.stderr}');
    }
    // Un seul format : le CLI écrit le fichier sans suffixe.
    _sbomPath = '${tmp.path}/sbom.cdx.json';
    File('${tmp.path}/sbom').renameSync(_sbomPath);
  });

  Future<void> run(
    WidgetTester tester,
    String name,
    Widget Function() body, {
    Brightness brightness = Brightness.light,
    Size size = const Size(1500, 950),
    Future<void> Function(WidgetTester)? act,
  }) async {
    SharedPreferences.setMockInitialValues({});
    // Avertissement de développement connu (ListTile dans un ColoredBox),
    // sans effet sur le rendu — voir « Pièges » du guide développeur.
    final previous = FlutterError.onError;
    FlutterError.onError = (details) {
      if (details.exceptionAsString().contains('ListTile background color')) {
        return;
      }
      previous?.call(details);
    };
    addTearDown(() => FlutterError.onError = previous);
    tester.view.physicalSize = size;
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
    appLocale = _locale;
    SettingsService.cliLang = _locale.languageCode;
    await tester.pumpWidget(
      RepaintBoundary(
        key: const Key('shot'),
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          locale: _locale,
          theme: ThemeData(
            useMaterial3: true,
            colorScheme: ColorScheme.fromSeed(
              seedColor: const Color(0xFF1A237E),
              brightness: brightness,
            ),
            fontFamily: 'Roboto',
          ),
          home: Scaffold(body: body()),
        ),
      ),
    );
    await tester.pumpAndSettle();
    if (act != null) await act(tester);
    await tester.pumpAndSettle();
    await _shot(tester, name);
    await tester.pumpWidget(const SizedBox());
    await tester.pump(const Duration(seconds: 3));
  }

  /// Appuie sur un bouton dans la zone réelle (hors horloge simulée) : les
  /// sous-processus lancés par le callback ne progressent pas autrement.
  Future<void> pressReal(WidgetTester tester, Finder button) async {
    final onPressed = tester.widget<FilledButton>(button).onPressed!;
    await tester.runAsync(() async {
      onPressed();
    });
    await tester.pump();
  }

  /// Attend (E/S réelles hors horloge simulée) que [finder] apparaisse.
  Future<void> waitFor(WidgetTester tester, Finder finder) async {
    for (var i = 0; i < 400 && finder.evaluate().isEmpty; i++) {
      await tester.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 50)),
      );
      await tester.pump();
    }
    expect(finder, findsWidgets);
  }

  for (final lang in ['fr', 'en']) {
    testWidgets('captures $lang', (tester) async {
      _locale = Locale(lang);
      final l = lookupAppLocalizations(_locale);

      // 1. Génération : configuration + progression.
      Widget generation() {
        final config = SbomConfig()
          ..inputFile = '/srv/audit/rhel9-ha.lst'
          ..outputBase = '/srv/audit/sbom'
          ..formats = {'cyclonedx', 'spdx', 'html'}
          ..documentName = 'RHEL 9.4 — HA'
          ..enableSbomqs = true;
        return Row(
          children: [
            ConfigPanel(
              config: config,
              isRunning: false,
              onRun: () {},
              onStop: () {},
            ),
            Expanded(
              child: ResultsPanel(
                logLines: const [
                  r'$ sbom-generator --input /srv/audit/rhel9-ha.lst --output /srv/audit/sbom --format cyclonedx spdx html',
                  'Resolved bash-5.1.8-6.el9.x86_64',
                  'Resolved glibc-2.34-83.el9.x86_64',
                  'Resolved openssl-libs-3.0.7-27.el9.x86_64',
                  'Resolved systemd-252-32.el9.x86_64',
                  'SBOM written → /srv/audit/sbom.cdx.json  (186.4 KB)',
                  'SBOM written → /srv/audit/sbom.spdx.json  (203.9 KB)',
                  'SBOM written → /srv/audit/sbom.html  (412.0 KB)',
                ],
                outputFiles: const [
                  OutputFile(
                    path: '/srv/audit/sbom.cdx.json',
                    size: '186.4 KB',
                  ),
                  OutputFile(
                    path: '/srv/audit/sbom.spdx.json',
                    size: '203.9 KB',
                  ),
                  OutputFile(path: '/srv/audit/sbom.html', size: '412.0 KB'),
                ],
                warnings: const [],
                isRunning: false,
                exitCode: 0,
                progressCurrent: 247,
                progressTotal: 247,
                progressPercent: 100,
              ),
            ),
          ],
        );
      }

      await run(tester, 'generation', generation);
      await run(
        tester,
        'resultats',
        generation,
        act: (t) async {
          await t.tap(find.text(l.tabResultsCount(3)));
        },
      );

      // 2. Tableau de bord multi-scanners (thème sombre).
      await run(
        tester,
        'tableau-de-bord',
        () => SingleChildScrollView(
          child: DashboardPanel(
            grypeVulns: _g,
            osvVulns: _o,
            trivyVulns: _t,
            exploitById: _exploit,
            scanTargets: const ['registry.example/keycloak:26.0'],
          ),
        ),
        size: const Size(1500, 720),
      );

      // 3. Scan Grype : tableau + détail d'une CVE.
      await run(
        tester,
        'scan-grype',
        () => VulnTableView<GrypeVuln>(
          vulns: _g,
          parseFailedMessage: '',
          severityOrder: const [
            'Critical',
            'High',
            'Medium',
            'Low',
            'Negligible',
          ],
          toolName: 'Grype',
          csvDialogTitle: '',
          csvFileName: 'grype_vulns.csv',
          csvHeader: l.vulnCsvHeaderGrype,
          csvRow: (v) => [v.id],
          extraColumnHeader: l.grypeColType,
          extraOf: (v) => v.packageType,
          exploitById: _exploit,
        ),
        size: const Size(1500, 860),
        act: (t) async {
          await t.tap(find.text('CVE-2021-44228').first);
        },
      );

      // 4. Conformité CRA (vrai CLI, SBOM réel, sans scan réseau).
      await run(
        tester,
        'cra',
        () => CraPanel(
          outputFiles: [OutputFile(path: _sbomPath, size: '120 KB')],
        ),
        size: const Size(1300, 1100),
        act: (t) async {
          await pressReal(t, find.widgetWithText(FilledButton, l.craEvaluate));
          await waitFor(t, find.text(l.craTileFields));
        },
      );

      // 5. Qualité SBOM (vrai sbomqs s'il est installé).
      await run(
        tester,
        'qualite',
        () => _LateFiles((files) => QualityPanel(outputFiles: files), [
          OutputFile(path: _sbomPath, size: '120 KB'),
        ]),
        size: const Size(1300, 1000),
        act: (t) async {
          await pressReal(
            t,
            find.widgetWithText(FilledButton, l.qualityAnalyze),
          );
          await waitFor(t, find.text(l.qualityIndustryProfiles));
        },
      );
    }, skip: _dir == null);
  }
}
