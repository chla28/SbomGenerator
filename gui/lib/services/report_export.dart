import 'dart:io';

import '../models/scan_session.dart';
import 'settings_service.dart';

/// Arguments de `sbom-generator report` — le rapport du tableau de bord est
/// produit par le CLI (un seul générateur pour le CLI et la GUI).
List<String> reportArgs({
  required String input,
  required String output,
  required String severity,
  String format = 'pdf',
  String? compareWith,
  bool applyVex = true,
}) => [
  'report',
  '--input',
  input,
  '--output',
  output,
  '--format',
  format,
  '--severity',
  severity,
  if (compareWith != null) ...['--compare-with', compareWith],
  if (!applyVex) '--no-vex',
];

/// Issue d'un export de rapport.
class ReportExportResult {
  final int exitCode;
  final String stderr;

  /// AsciiDoc (toujours écrit) et PDF (si `asciidoctor-pdf` a réussi).
  final String adocPath;
  final String pdfPath;
  final bool pdfWritten;

  const ReportExportResult({
    required this.exitCode,
    required this.stderr,
    required this.adocPath,
    required this.pdfPath,
    required this.pdfWritten,
  });

  bool get adocWritten => File(adocPath).existsSync();
}

/// Écrit [session] (et [baseline] pour la tendance) dans un dossier
/// temporaire, lance `sbom-generator report` et nettoie. [pdfPath] est le PDF
/// demandé ; l'AsciiDoc est écrit à côté (même nom, `.adoc`). Lève une
/// [ProcessException] si le CLI est introuvable.
Future<ReportExportResult> exportReport({
  required ScanSession session,
  ScanSession? baseline,
  required String severity,
  required String pdfPath,
  bool applyVex = true,
}) async {
  final tmp = await Directory.systemTemp.createTemp('sbom_report_');
  try {
    final input = File('${tmp.path}/session.json');
    await input.writeAsString(session.encode());
    String? compare;
    if (baseline != null) {
      final f = File('${tmp.path}/baseline.json');
      await f.writeAsString(baseline.encode());
      compare = f.path;
    }
    final r = await Process.run(
      SettingsService.cliBinary,
      reportArgs(
        input: input.path,
        output: pdfPath,
        severity: severity,
        compareWith: compare,
        applyVex: applyVex,
      ),
      environment: SettingsService.cliEnvironment,
    );
    final adoc = pdfPath.toLowerCase().endsWith('.pdf')
        ? '${pdfPath.substring(0, pdfPath.length - 4)}.adoc'
        : '$pdfPath.adoc';
    return ReportExportResult(
      exitCode: r.exitCode,
      stderr: '${r.stderr}'.trim(),
      adocPath: adoc,
      pdfPath: pdfPath,
      pdfWritten: File(pdfPath).existsSync(),
    );
  } finally {
    await tmp.delete(recursive: true);
  }
}
