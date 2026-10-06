import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sbom_generator_gui/widgets/dashboard_panel.dart';
import 'package:sbom_generator_gui/widgets/grype_panel.dart';
import 'package:sbom_generator_gui/widgets/on_pale.dart';
import 'package:sbom_generator_gui/widgets/osv_panel.dart';

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  testWidgets(
    'thème sombre : la ligne « vue par un seul scanner » (fond pastel) reste lisible',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 1400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      await tester.pumpWidget(
        MaterialApp(
          theme: ThemeData(brightness: Brightness.dark),
          home: Scaffold(
            body: DashboardPanel(
              grypeVulns: const [
                GrypeVuln(
                  id: 'CVE-SOLO',
                  severity: 'High',
                  packageName: 'p',
                  installedVersion: '1',
                  fixedVersion: '2',
                  packageType: 'rpm',
                ),
                GrypeVuln(
                  id: 'CVE-BOTH',
                  severity: 'High',
                  packageName: 'p',
                  installedVersion: '1',
                  fixedVersion: '2',
                  packageType: 'rpm',
                ),
              ],
              osvVulns: const [
                OsvVuln(
                  id: 'CVE-BOTH',
                  severity: 'HIGH',
                  packageName: 'p',
                  installedVersion: '1',
                  fixedVersion: '2',
                  ecosystem: 'RPM',
                ),
              ],
              trivyVulns: null,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      Color? textColor(String id) {
        final e = tester.element(find.text(id));
        return DefaultTextStyle.of(e).style.color;
      }

      // Ligne isolée (fond pastel) : texte sombre forcé.
      expect(textColor('CVE-SOLO'), kOnPale);
      // Ligne normale : texte du thème (clair en mode sombre).
      expect(textColor('CVE-BOTH'), isNot(kOnPale));
    },
  );
}
