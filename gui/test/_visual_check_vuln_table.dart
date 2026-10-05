// Vérification visuelle jetable du VulnTableView unifié — pas un test de
// régression, à supprimer après inspection des captures.
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/osv_panel.dart';
import 'package:sbom_generator_gui/widgets/trivy_panel.dart';
import 'package:sbom_generator_gui/widgets/vuln_shared.dart';

void main() {
  final grype = [
    const GrypeVuln(
      id: 'CVE-2024-0001',
      severity: 'Critical',
      packageName: 'openssl',
      installedVersion: '3.0.1',
      fixedVersion: '3.0.9',
      packageType: 'rpm',
    ),
    const GrypeVuln(
      id: 'CVE-2024-0002',
      severity: 'High',
      packageName: 'curl',
      installedVersion: '7.85.0',
      fixedVersion: '7.88.1',
      packageType: 'rpm',
    ),
    const GrypeVuln(
      id: 'CVE-2024-0003',
      severity: 'Medium',
      packageName: 'glibc',
      installedVersion: '2.34',
      fixedVersion: '',
      packageType: 'rpm',
    ),
    const GrypeVuln(
      id: 'CVE-2024-0004',
      severity: 'Low',
      packageName: 'bash',
      installedVersion: '5.1.8',
      fixedVersion: '5.1.16',
      packageType: 'rpm',
    ),
    const GrypeVuln(
      id: 'CVE-2024-0005',
      severity: 'Negligible',
      packageName: 'zlib',
      installedVersion: '1.2.11',
      fixedVersion: '1.2.13',
      packageType: 'rpm',
    ),
  ];
  final trivy = [
    const TrivyVuln(
      id: 'CVE-2024-0001',
      severity: 'CRITICAL',
      packageName: 'openssl',
      installedVersion: '3.0.1',
      fixedVersion: '3.0.9',
      title: 'OpenSSL: buffer overflow in X.509 certificate verification',
    ),
    const TrivyVuln(
      id: 'CVE-2024-0002',
      severity: 'HIGH',
      packageName: 'curl',
      installedVersion: '7.85.0',
      fixedVersion: '7.88.1',
      title: 'curl: use-after-free in HTTP/2 handling',
    ),
    const TrivyVuln(
      id: 'CVE-2024-0003',
      severity: 'MEDIUM',
      packageName: 'glibc',
      installedVersion: '2.34',
      fixedVersion: '',
      title: 'glibc: integer overflow in printf',
    ),
    const TrivyVuln(
      id: 'CVE-2024-0004',
      severity: 'LOW',
      packageName: 'bash',
      installedVersion: '5.1.8',
      fixedVersion: '5.1.16',
      title: '',
    ),
  ];
  final osv = [
    const OsvVuln(
      id: 'CVE-2024-0001',
      severity: 'Critical',
      packageName: 'openssl',
      installedVersion: '3.0.1',
      fixedVersion: '3.0.9',
      ecosystem: 'RPM',
    ),
    const OsvVuln(
      id: 'CVE-2024-0002',
      severity: 'High',
      packageName: 'curl',
      installedVersion: '7.85.0',
      fixedVersion: '7.88.1',
      ecosystem: 'RPM',
    ),
    const OsvVuln(
      id: 'CVE-2024-0003',
      severity: 'Medium',
      packageName: 'glibc',
      installedVersion: '2.34',
      fixedVersion: '',
      ecosystem: 'RPM',
    ),
  ];

  testWidgets('capture grype table', (tester) async {
    tester.view.physicalSize = const Size(1200, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: RepaintBoundary(
            child: VulnTableView<GrypeVuln>(
              vulns: grype,
              parseFailedMessage: 'x',
              severityOrder: const [
                'Critical',
                'High',
                'Medium',
                'Low',
                'Negligible',
              ],
              toolName: 'Grype',
              csvDialogTitle: 'x',
              csvFileName: 'x.csv',
              csvHeader: 'x',
              csvRow: (v) => [
                v.severity,
                v.id,
                v.packageName,
                v.installedVersion,
                v.fixedVersion,
                v.packageType,
              ],
              extraColumnHeader: 'TYPE',
              extraOf: (v) => v.packageType,
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    final boundary = tester.renderObject<RenderRepaintBoundary>(
      find.byType(RepaintBoundary).first,
    );
    final image = await boundary.toImage(pixelRatio: 1.0);
    final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
    final dir = Directory('/tmp/vuln_table_shots')..createSync(recursive: true);
    File('${dir.path}/grype.png').writeAsBytesSync(bytes!.buffer.asUint8List());
  });

  testWidgets('capture trivy table', (tester) async {
    tester.view.physicalSize = const Size(1200, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: RepaintBoundary(
            child: VulnTableView<TrivyVuln>(
              vulns: trivy,
              parseFailedMessage: 'x',
              severityOrder: const [
                'CRITICAL',
                'HIGH',
                'MEDIUM',
                'LOW',
                'UNKNOWN',
              ],
              toolName: 'Trivy',
              csvDialogTitle: 'x',
              csvFileName: 'x.csv',
              csvHeader: 'x',
              csvRow: (v) => [
                v.severity,
                v.id,
                v.packageName,
                v.installedVersion,
                v.fixedVersion,
                v.title,
              ],
              descriptionOf: (v) => v.title,
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    final boundary = tester.renderObject<RenderRepaintBoundary>(
      find.byType(RepaintBoundary).first,
    );
    final image = await boundary.toImage(pixelRatio: 1.0);
    final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
    final dir = Directory('/tmp/vuln_table_shots')..createSync(recursive: true);
    File('${dir.path}/trivy.png').writeAsBytesSync(bytes!.buffer.asUint8List());
  });

  testWidgets('capture osv table', (tester) async {
    tester.view.physicalSize = const Size(1200, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: RepaintBoundary(
            child: VulnTableView<OsvVuln>(
              vulns: osv,
              parseFailedMessage: 'x',
              severityOrder: const [
                'Critical',
                'High',
                'Medium',
                'Low',
                'Unknown',
              ],
              toolName: 'OSV-Scanner',
              csvDialogTitle: 'x',
              csvFileName: 'x.csv',
              csvHeader: 'x',
              csvRow: (v) => [
                v.severity,
                v.id,
                v.packageName,
                v.installedVersion,
                v.fixedVersion,
                v.ecosystem,
              ],
              extraColumnHeader: 'ÉCOSYSTÈME',
              extraOf: (v) => v.ecosystem,
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    final boundary = tester.renderObject<RenderRepaintBoundary>(
      find.byType(RepaintBoundary).first,
    );
    final image = await boundary.toImage(pixelRatio: 1.0);
    final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
    final dir = Directory('/tmp/vuln_table_shots')..createSync(recursive: true);
    File('${dir.path}/osv.png').writeAsBytesSync(bytes!.buffer.asUint8List());
  });
}
