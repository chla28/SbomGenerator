import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/cve_date_filter.dart';
import 'package:sbom_generator_gui/models/layer_scan.dart';
import 'package:sbom_generator_gui/services/grype_runner.dart';
import 'package:sbom_generator_gui/services/osv_runner.dart';
import 'package:sbom_generator_gui/services/trivy_runner.dart';
import 'package:sbom_generator_gui/widgets/vuln_shared.dart';

void main() {
  test('shellQuote / shellCommand', () {
    expect(shellQuote('nginx:latest'), 'nginx:latest');
    expect(shellQuote('/tmp/a b.tar'), "'/tmp/a b.tar'");
    expect(shellQuote("l'image"), r"'l'\''image'");
    expect(shellQuote(''), "''");
    expect(
      shellCommand('grype', ['x.cdx.json', '--output', 'json']),
      'grype x.cdx.json --output json',
    );
  });

  test('arguments des runners (identiques à l\'exécution)', () {
    expect(
      GrypeRunner.buildArgs(
        target: 'sbom.cdx.json',
        failOn: 'high',
        distroVersion: '9',
        templateFile: 't.tmpl',
        templateOutput: 'out.txt',
      ),
      [
        'sbom.cdx.json',
        '--output',
        'json',
        '--output',
        'template=out.txt',
        '--template',
        't.tmpl',
        '--platform',
        'linux',
        '--add-cpes-if-none',
        '--by-cve',
        '--distro',
        'rhel:9',
        '--fail-on',
        'high',
      ],
    );
    expect(OsvRunner.buildArgs(target: 's.json'), [
      '--format',
      'json',
      '--sbom',
      's.json',
    ]);
    expect(OsvRunner.buildArgs(target: 'nginx:latest', useImage: true), [
      'scan',
      'image',
      '--format',
      'json',
      'nginx:latest',
    ]);
    expect(
      TrivyRunner.buildArgs(
        target: 'nginx:latest',
        useImage: true,
        platform: 'linux/arm64',
        severities: ['HIGH', 'CRITICAL'],
        ignoreUnfixed: true,
      ),
      [
        'image',
        '--format',
        'json',
        '--quiet',
        '--severity',
        'HIGH,CRITICAL',
        '--ignore-unfixed',
        '--platform',
        'linux/arm64',
        'nginx:latest',
      ],
    );
  });

  test('équivalent sbom-generator scan', () {
    expect(
      sbomGeneratorScanArgs(
        scanner: 'trivy',
        target: 'app.tar',
        useImage: true,
        layers: const LayerScanSettings(
          enabled: true,
          mode: LayerScanMode.each,
          layerMode: 'rootfs',
        ),
        dateFilter: CveDateFilter(
          after: DateTime.utc(2024, 1, 2),
          field: CveDateField.modified,
          includeUndated: true,
        ),
        enrichOnline: false,
      ),
      [
        'scan',
        '--image',
        'app.tar',
        '--scanner',
        'trivy',
        '--per-layer',
        '--layer-scan',
        'each',
        '--layer-mode',
        'rootfs',
        '--cve-after',
        '2024-01-02',
        '--cve-date-field',
        'modified',
        '--include-undated',
        '--no-enrich',
      ],
    );
    // Par couche ignoré pour une source SBOM.
    expect(
      sbomGeneratorScanArgs(
        scanner: 'grype',
        target: 's.json',
        useImage: false,
        layers: const LayerScanSettings(enabled: true),
      ),
      ['scan', '--sbom', 's.json', '--scanner', 'grype'],
    );
  });

  test('équivalent sbom-generator scan --package', () {
    expect(
      sbomGeneratorScanArgs(
        scanner: 'grype',
        target: 'app.rpm',
        useImage: false,
        usePackage: true,
        packageDepth: '2',
        enrichOnline: false,
      ),
      [
        'scan',
        '--package',
        'app.rpm',
        '--depth',
        '2',
        '--scanner',
        'grype',
        '--no-enrich',
      ],
    );
    // Profondeur 0 : pas de --depth.
    expect(
      sbomGeneratorScanArgs(
        scanner: 'osv',
        target: 'a.tgz',
        useImage: false,
        usePackage: true,
      ),
      ['scan', '--package', 'a.tgz', '--scanner', 'osv'],
    );
  });

  test('séquence de l\'analyse par couche', () {
    String seq(LayerScanMode mode) => layeredCliSequence(
      cliBinary: 'sbom-generator',
      prepareArgs: ['--image', 'a.tar'],
      layers: LayerScanSettings(enabled: true, mode: mode),
      imageScan: 'grype a.tar',
      layerScan: (f) => 'grype $f',
    );
    expect(
      seq(LayerScanMode.attribute),
      'sbom-generator --image a.tar\ngrype a.tar',
    );
    expect(
      seq(LayerScanMode.each),
      'sbom-generator --image a.tar\n'
      'for f in $cliLayerDir/image.layer-*.cdx.json; do\n'
      '  grype "\$f"\ndone',
    );
  });

  testWidgets('bouton « CLI Commande » : popup et copie', (tester) async {
    String? copied;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = (call.arguments as Map)['text'] as String;
        }
        return null;
      },
    );
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: CliCommandButton(
            sections: () => const [
              CliCommandSection(
                'Commande exécutée par l\'onglet',
                'grype sbom.cdx.json --output json',
              ),
              CliCommandSection(
                'Équivalent sbom-generator scan',
                'sbom-generator scan --sbom sbom.cdx.json',
                note: 'Non transposable : --fail-on.',
              ),
            ],
          ),
        ),
      ),
    );
    await tester.tap(find.text('CLI Commande'));
    await tester.pumpAndSettle();
    expect(find.text('Ligne de commande'), findsOneWidget);
    expect(find.text('grype sbom.cdx.json --output json'), findsOneWidget);
    expect(find.text('Non transposable : --fail-on.'), findsOneWidget);

    await tester.tap(find.byTooltip('Copier').first);
    await tester.pumpAndSettle();
    expect(copied, 'grype sbom.cdx.json --output json');

    await tester.tap(find.text('Fermer'));
    await tester.pumpAndSettle();
    expect(find.text('Ligne de commande'), findsNothing);
  });
}
