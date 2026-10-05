import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../models/sbom_result.dart';
import '../services/settings_service.dart';
import 'help_icon.dart';
import '../l10n/l10n.dart';

/// Onglet « Conformité CRA » — pilote la sous-commande `sbom-generator cra`
/// (rapport de conformité Cyber Resilience Act, périmètre vérifiable
/// automatiquement). Le résultat JSON est affiché ; l'export PDF relance la
/// commande en `--format pdf`.
class CraPanel extends StatefulWidget {
  final List<OutputFile> outputFiles;
  const CraPanel({super.key, required this.outputFiles});

  @override
  State<CraPanel> createState() => _CraPanelState();
}

class _CraPanelState extends State<CraPanel> {
  final _sbom = TextEditingController();
  final _manufacturer = TextEditingController();
  final _product = TextEditingController();
  final _productVersion = TextEditingController();
  final _supportUntil = TextEditingController();
  final _vulnContact = TextEditingController();
  final _cvdUrl = TextEditingController();
  String? _configPath;
  bool _scan = true;
  String _scanner = 'grype';

  bool _running = false;
  String? _error;
  Map<String, dynamic>? _result;

  @override
  void initState() {
    super.initState();
    _autoFile();
  }

  @override
  void didUpdateWidget(CraPanel old) {
    super.didUpdateWidget(old);
    if (widget.outputFiles != old.outputFiles) _autoFile();
  }

  @override
  void dispose() {
    for (final c in [
      _sbom,
      _manufacturer,
      _product,
      _productVersion,
      _supportUntil,
      _vulnContact,
      _cvdUrl,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  void _autoFile() {
    if (widget.outputFiles.isEmpty || _sbom.text.isNotEmpty) return;
    final f =
        widget.outputFiles
            .where(
              (f) =>
                  f.path.endsWith('.cdx.json') || f.path.endsWith('.spdx.json'),
            )
            .firstOrNull ??
        widget.outputFiles.where((f) => f.path.endsWith('.json')).firstOrNull;
    if (f != null) _sbom.text = f.path;
  }

  List<String> _metaArgs() => [
    for (final (flag, ctrl) in [
      ('--manufacturer', _manufacturer),
      ('--product', _product),
      ('--product-version', _productVersion),
      ('--support-until', _supportUntil),
      ('--vuln-contact', _vulnContact),
      ('--cvd-policy-url', _cvdUrl),
    ])
      if (ctrl.text.trim().isNotEmpty) ...[flag, ctrl.text.trim()],
    if (_configPath != null) ...['--config', _configPath!],
  ];

  Future<void> _run() async {
    final l = context.l10n;
    final sbom = _sbom.text.trim();
    if (sbom.isEmpty || !File(sbom).existsSync()) {
      setState(() => _error = l.craInvalidSbom);
      return;
    }
    setState(() {
      _running = true;
      _error = null;
      _result = null;
    });
    try {
      final r = await Process.run(SettingsService.cliBinary, [
        'cra',
        '--sbom',
        sbom,
        '--format',
        'json',
        _scan ? '--scan' : '--no-scan',
        if (_scan) ...['--scanner', _scanner],
        ..._metaArgs(),
      ], environment: SettingsService.cliEnvironment);
      if (!mounted) return;
      // stdout = JSON même si exit 2 (non conforme).
      final out = (r.stdout as String).trim();
      if (out.startsWith('{')) {
        setState(() => _result = jsonDecode(out) as Map<String, dynamic>);
      } else {
        setState(
          () => _error = (r.stderr as String).trim().isEmpty
              ? l.craUnexpectedOutput(r.exitCode)
              : (r.stderr as String).trim(),
        );
      }
    } catch (e) {
      if (mounted) setState(() => _error = l.craLaunchFailed('$e'));
    } finally {
      if (mounted) setState(() => _running = false);
    }
  }

  Future<void> _exportPdf() async {
    final l = context.l10n;
    final sbom = _sbom.text.trim();
    final path = await FilePicker.saveFile(
      dialogTitle: l.craExportTitle,
      fileName: l.craExportFileName,
      type: FileType.custom,
      allowedExtensions: ['pdf'],
    );
    if (path == null || !mounted) return;
    setState(() => _running = true);
    try {
      final r = await Process.run(SettingsService.cliBinary, [
        'cra',
        '--sbom',
        sbom,
        '--format',
        'pdf',
        '-o',
        path,
        _scan ? '--scan' : '--no-scan',
        if (_scan) ...['--scanner', _scanner],
        ..._metaArgs(),
      ], environment: SettingsService.cliEnvironment);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            r.exitCode == 2 || r.exitCode == 0
                ? l.craReportWritten(path)
                : l.craFailed((r.stderr as String).trim()),
          ),
          duration: const Duration(seconds: 5),
        ),
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(l.craFailed('$e'))));
      }
    } finally {
      if (mounted) setState(() => _running = false);
    }
  }

  Future<void> _pickSbom() async {
    final r = await FilePicker.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['json', 'jsonld'],
    );
    if (r?.files.single.path != null) {
      setState(() => _sbom.text = r!.files.single.path!);
    }
  }

  Future<void> _pickConfig() async {
    final r = await FilePicker.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['yaml', 'yml', 'txt'],
    );
    if (r?.files.single.path != null) {
      setState(() => _configPath = r!.files.single.path);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Row(
          children: [
            const Icon(Icons.gpp_good_outlined, size: 18),
            const SizedBox(width: 8),
            Text(
              context.l10n.craTitle,
              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
            ),
            const SizedBox(width: 6),
            HelpIcon(context.l10n.craHelp),
          ],
        ),
        const SizedBox(height: 12),

        _field(
          _sbom,
          context.l10n.craSbomField,
          trailing: TextButton(
            onPressed: _pickSbom,
            child: Text(context.l10n.commonBrowse),
          ),
        ),
        const SizedBox(height: 8),

        ExpansionTile(
          title: Text(
            context.l10n.craProductMeta,
            style: const TextStyle(fontSize: 13),
          ),
          tilePadding: EdgeInsets.zero,
          childrenPadding: const EdgeInsets.only(bottom: 8),
          children: [
            _field(_manufacturer, context.l10n.craManufacturer),
            _field(_product, context.l10n.craProduct),
            _field(_productVersion, context.l10n.craProductVersion),
            _field(_supportUntil, context.l10n.craSupportUntil),
            _field(_vulnContact, context.l10n.craVulnContact),
            _field(_cvdUrl, context.l10n.craCvdUrl),
            const SizedBox(height: 4),
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                icon: const Icon(Icons.upload_file, size: 16),
                label: Text(
                  _configPath == null
                      ? context.l10n.craLoadConfig
                      : context.l10n.craConfigLoaded(
                          _configPath!.split('/').last,
                        ),
                ),
                onPressed: _pickConfig,
              ),
            ),
          ],
        ),
        const SizedBox(height: 4),

        Row(
          children: [
            Checkbox(
              value: _scan,
              onChanged: (v) => setState(() => _scan = v ?? true),
            ),
            Text(
              context.l10n.craScanVulns,
              style: const TextStyle(fontSize: 13),
            ),
            const SizedBox(width: 12),
            if (_scan)
              DropdownButton<String>(
                value: _scanner,
                isDense: true,
                items: [
                  const DropdownMenuItem(value: 'grype', child: Text('Grype')),
                  const DropdownMenuItem(
                    value: 'osv',
                    child: Text('OSV-Scanner'),
                  ),
                  const DropdownMenuItem(value: 'trivy', child: Text('Trivy')),
                  DropdownMenuItem(
                    value: 'all',
                    child: Text(context.l10n.craScannerAll),
                  ),
                ],
                onChanged: (v) => setState(() => _scanner = v ?? 'grype'),
              ),
          ],
        ),
        const SizedBox(height: 8),

        Row(
          children: [
            FilledButton.icon(
              icon: _running
                  ? const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.play_arrow, size: 18),
              label: Text(context.l10n.craEvaluate),
              onPressed: _running ? null : _run,
            ),
            const SizedBox(width: 8),
            OutlinedButton.icon(
              icon: const Icon(Icons.picture_as_pdf_outlined, size: 18),
              label: Text(context.l10n.craExportPdf),
              onPressed: _running || _sbom.text.trim().isEmpty
                  ? null
                  : _exportPdf,
            ),
          ],
        ),

        if (_error != null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(10),
            color: Colors.red.withValues(alpha: 0.08),
            child: SelectableText(
              _error!,
              style: TextStyle(color: Colors.red[800], fontSize: 12),
            ),
          ),
        ],
        if (_result != null) ...[
          const SizedBox(height: 16),
          _CraResultView(result: _result!),
        ],
      ],
    );
  }

  Widget _field(TextEditingController c, String label, {Widget? trailing}) =>
      Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          children: [
            Expanded(
              child: TextField(
                controller: c,
                style: const TextStyle(fontSize: 13),
                decoration: InputDecoration(
                  labelText: label,
                  isDense: true,
                  border: const OutlineInputBorder(),
                ),
              ),
            ),
            ?trailing,
          ],
        ),
      );
}

class _CraResultView extends StatelessWidget {
  final Map<String, dynamic> result;
  const _CraResultView({required this.result});

  Color _c(String status) => switch (status) {
    'ok' => Colors.green[700]!,
    'partial' => const Color(0xFF8A5000),
    'fail' => const Color(0xFFB3261E),
    _ => Colors.grey,
  };
  String _l(BuildContext context, String status) => switch (status) {
    'ok' => context.l10n.craStatusOk,
    'partial' => context.l10n.craStatusPartial,
    'fail' => context.l10n.craStatusFail,
    _ => context.l10n.craStatusNa,
  };

  @override
  Widget build(BuildContext context) {
    final verdict = result['verdict'] as String? ?? 'na';
    final sbom = (result['sbom'] as Map?) ?? const {};
    final vulns = (result['vulnerabilities'] as Map?) ?? const {};
    final checks = (sbom['fieldChecks'] as List?) ?? const [];
    final blockers = (result['blockers'] as List?)?.cast<String>() ?? const [];
    final ntia = (result['ntiaMinimumElements'] as Map?) ?? const {};
    final ntiaOk = ntia.values.where((v) => v == 'ok').length;

    Widget tile(String label, String value, {bool alert = false}) => Expanded(
      child: Column(
        children: [
          Text(
            value,
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: alert ? const Color(0xFFB3261E) : null,
            ),
          ),
          Text(
            label,
            textAlign: TextAlign.center,
            style: const TextStyle(fontSize: 11, color: Colors.grey),
          ),
        ],
      ),
    );

    final evaluated = vulns['evaluated'] == true;
    final noFix = ((vulns['withoutFix'] as List?) ?? const []).length;
    final kev = ((vulns['activelyExploited'] as List?) ?? const []).length;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: _c(verdict).withValues(alpha: 0.10),
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: _c(verdict).withValues(alpha: 0.5)),
          ),
          child: Text(
            '${context.l10n.craVerdict(_l(context, verdict))}\n'
            '${result['verdictSentence'] ?? ''}',
            style: TextStyle(
              color: _c(verdict),
              fontWeight: FontWeight.w600,
              fontSize: 12,
            ),
          ),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            tile(
              context.l10n.craTileFields,
              '${checks.where((c) => (c as Map)['status'] == 'ok').length} / ${checks.length}',
            ),
            tile(context.l10n.craTileNtia, '$ntiaOk / 7'),
            tile(
              context.l10n.craTileNoFix,
              evaluated ? '$noFix' : '—',
              alert: noFix > 0,
            ),
            tile(
              context.l10n.craTileKev,
              evaluated ? '$kev' : '—',
              alert: kev > 0,
            ),
          ],
        ),
        const SizedBox(height: 16),

        if (blockers.isNotEmpty) ...[
          Text(
            context.l10n.craBlockers,
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
          ),
          const SizedBox(height: 4),
          for (final b in blockers)
            Padding(
              padding: const EdgeInsets.only(bottom: 3),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('•  ', style: TextStyle(color: Color(0xFFB3261E))),
                  Expanded(
                    child: Text(b, style: const TextStyle(fontSize: 12)),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 12),
        ],

        Text(
          context.l10n.craFieldsTitle,
          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
        ),
        const SizedBox(height: 4),
        Table(
          columnWidths: const {
            0: FlexColumnWidth(3),
            1: FlexColumnWidth(2),
            2: FlexColumnWidth(2),
          },
          children: [
            TableRow(
              children: [
                _Th(context.l10n.craThField),
                _Th(context.l10n.craThCoverage),
                _Th(context.l10n.craThStatus),
              ],
            ),
            for (final c in checks.cast<Map>())
              TableRow(
                children: [
                  _Td('${c['field']}'),
                  _Td('${c['covered']} / ${c['total']}'),
                  _Td(
                    _l(context, '${c['status']}'),
                    color: _c('${c['status']}'),
                  ),
                ],
              ),
          ],
        ),
        const SizedBox(height: 12),
        Text(
          context.l10n.craSbomSummary(
            '${sbom['format']}',
            '${sbom['componentCount']}',
            '${sbom['dependencyRelations']}',
          ),
          style: const TextStyle(fontSize: 11, color: Colors.grey),
        ),
        if (evaluated)
          Text(
            context.l10n.craVulnSummary(
                  '${vulns['total']}',
                  '${(vulns['bySeverity'] as Map)['critical']}',
                  '${(vulns['bySeverity'] as Map)['high']}',
                ) +
                (vulns['article14NotificationRequired'] == true
                    ? context.l10n.craEnisaNotice
                    : ''),
            style: const TextStyle(fontSize: 11, color: Colors.grey),
          ),
      ],
    );
  }
}

class _Th extends StatelessWidget {
  final String t;
  const _Th(this.t);
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(right: 12, bottom: 3),
    child: Text(
      t,
      style: const TextStyle(
        fontSize: 10,
        fontWeight: FontWeight.bold,
        color: Colors.grey,
      ),
    ),
  );
}

class _Td extends StatelessWidget {
  final String t;
  final Color? color;
  const _Td(this.t, {this.color});
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(right: 12, bottom: 3),
    child: Text(
      t,
      style: TextStyle(
        fontSize: 12,
        color: color,
        fontWeight: color != null ? FontWeight.w600 : null,
      ),
    ),
  );
}
