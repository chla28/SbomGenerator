import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

import '../i18n.dart';
import '../services/scan_enrichment.dart';
import 'vex_ui.dart';
import 'pdf_report.dart' show frenchSeverityLabel;

/// Ce qu'un scanner donné rapporte sur une CVE. Les scanners divergent souvent
/// sur la sévérité, les versions corrigées et les dates — on les garde donc
/// séparément.
class ScannerCveView {
  final String scanner; // 'Grype' | 'OSV-Scanner' | 'Trivy'
  final String severity;
  final String packageName;
  final String installedVersion;
  final String fixedVersion;

  /// Champ libre propre au scanner : type de paquet (Grype), écosystème (OSV),
  /// titre de la CVE (Trivy). Vide si absent.
  final String extra;
  final DateTime? publishedDate;
  final DateTime? modifiedDate;

  const ScannerCveView({
    required this.scanner,
    required this.severity,
    required this.packageName,
    required this.installedVersion,
    required this.fixedVersion,
    this.extra = '',
    this.publishedDate,
    this.modifiedDate,
  });
}

/// Toutes les informations disponibles (en mémoire) sur une CVE, agrégées
/// depuis un ou plusieurs scanners et l'enrichissement d'exploitabilité.
class CveDetail {
  final String id;
  final List<ScannerCveView> views;
  final ExploitInfo exploit;

  const CveDetail({
    required this.id,
    required this.views,
    this.exploit = ExploitInfo.empty,
  });

  bool get isCve => id.toUpperCase().startsWith('CVE-');
  bool get isGhsa => id.toUpperCase().startsWith('GHSA-');

  /// Meilleure description « phrase » disponible (titre Trivy p. ex.) — on
  /// écarte les champs courts comme le type de paquet ou l'écosystème.
  String get description {
    var best = '';
    for (final v in views) {
      if (v.extra.contains(' ') &&
          v.extra.length > 12 &&
          v.extra.length > best.length) {
        best = v.extra;
      }
    }
    return best;
  }

  /// Paquet le plus renseigné (première vue non vide).
  ScannerCveView? get primary => views.isEmpty
      ? null
      : views.firstWhere(
          (v) => v.packageName.isNotEmpty,
          orElse: () => views.first,
        );

  String _fmtDate(DateTime? d) => d == null
      ? '—'
      : '${d.year.toString().padLeft(4, '0')}-'
            '${d.month.toString().padLeft(2, '0')}-'
            '${d.day.toString().padLeft(2, '0')}';

  /// Liens de référence externes, sous forme (libellé, URL).
  List<(String, String)> get links {
    final e = Uri.encodeComponent(id);
    return [
      if (isCve) ...[
        ('NVD', 'https://nvd.nist.gov/vuln/detail/$e'),
        ('CVE.org', 'https://www.cve.org/CVERecord?id=$e'),
      ],
      if (isGhsa) ('GitHub Advisory', 'https://github.com/advisories/$e'),
      ('osv.dev', 'https://osv.dev/vulnerability/$e'),
      if (exploit.inKev)
        (
          'CISA KEV',
          'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
              '?search_api_fulltext=$e',
        ),
    ];
  }

  /// Rendu AsciiDoc compact (une ligne « libellé | valeur » par attribut) —
  /// utilisé par l'export du tableau de bord.
  String toAdocRows(String Function(String) esc) {
    final b = StringBuffer();
    final p = primary;
    if (p != null && p.packageName.isNotEmpty) {
      final fixed = p.fixedVersion.isEmpty ? '' : ' → ${p.fixedVersion}';
      b.writeln(
        '| ${tr('Paquet')} | `${esc('${p.packageName} ${p.installedVersion}'
        '$fixed')}`',
      );
    }
    final reported = views
        .map((v) => '${v.scanner} (${frenchSeverityLabel(v.severity)})')
        .join(', ');
    if (reported.isNotEmpty) {
      b.writeln('| ${tr('Rapporté par')} | ${esc(reported)}');
    }
    final dates = views
        .where((v) => v.publishedDate != null || v.modifiedDate != null)
        .map(
          (v) => tr('{scanner} : publié {published}, modifié {modified}', {'scanner': v.scanner, 'published': _fmtDate(v.publishedDate), 'modified': _fmtDate(v.modifiedDate)}),
        )
        .join(' +\n');
    if (dates.isNotEmpty) b.writeln('| ${tr('Dates')} | ${esc(dates)}');
    if (description.isNotEmpty) {
      b.writeln('| ${tr('Description')} | ${esc(description)}');
    }

    final ex = exploit;
    if (ex.inKev) {
      final parts = <String>[tr('ajoutée {date}', {'date': _fmtDate(ex.kevDateAdded)})];
      if (ex.kevDueDate != null) {
        parts.add(tr('échéance {date}', {'date': _fmtDate(ex.kevDueDate)}));
      }
      if (ex.kevRansomware) parts.add(tr('usage par rançongiciel'));
      b.writeln('| CISA KEV | ${esc(tr('Oui — {details}', {'details': parts.join(', ')}))}');
    }
    if (ex.epssScore != null) {
      final pct = ((ex.epssPercentile ?? 0) * 100).round();
      b.writeln(
        '| EPSS | ${tr('{score} (percentile p{pct})', {'score': ex.epssScore!.toStringAsFixed(2), 'pct': pct})}',
      );
    }
    if (ex.cvssExploitabilityScore != null || ex.exploitMaturity != null) {
      final parts = <String>[];
      if (ex.cvssBaseScore != null) {
        parts.add(tr('base {score}', {'score': ex.cvssBaseScore!.toStringAsFixed(1)}));
      }
      if (ex.cvssExploitabilityScore != null) {
        parts.add(
          tr('exploitabilité {score}/3.9', {'score': ex.cvssExploitabilityScore!.toStringAsFixed(1)}),
        );
      }
      if (ex.exploitMaturity != null) {
        parts.add(tr('maturité {value}', {'value': ex.exploitMaturity!}));
      }
      b.writeln(
        '| CVSS | ${esc(parts.join(' · '))}'
        '${ex.cvssVector != null ? ' +\n`${esc(ex.cvssVector!)}`' : ''}',
      );
    }
    if (ex.pocKnown) {
      final n = ex.pocCount;
      b.writeln(
        '| ${tr('PoC public')} | ${n > 0 ? (isPlural(n) ? tr('{n} dépôts', {'n': n}) : tr('{n} dépôt', {'n': n})) : tr('oui')}'
        '${ex.pocUrls.isNotEmpty ? ' +\n${ex.pocUrls.map(esc).join(' +\n')}' : ''}',
      );
    }
    if (links.isNotEmpty) {
      b.writeln('| ${tr('Liens')} | ${links.map((x) => x.$2).join(' +\n')}');
    }
    return b.toString();
  }
}

/// Panneau de détail d'une CVE, affiché dans une ligne dépliée (tableau de
/// bord) ou sous une ligne de la table (onglets Grype / OSV / Trivy).
/// Paquets (nom, version) distincts rapportés pour la CVE.
List<({String name, String version})> _vexPackages(CveDetail d) {
  final seen = <String>{};
  return [
    for (final v in d.views)
      if (v.packageName.isNotEmpty &&
          seen.add('${v.packageName}@${v.installedVersion}'))
        (name: v.packageName, version: v.installedVersion),
  ];
}

class CveDetailPanel extends StatelessWidget {
  final CveDetail detail;

  const CveDetailPanel({super.key, required this.detail});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final e = detail.exploit;

    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(left: 8, right: 8, bottom: 6),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLow,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: theme.dividerColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                detail.id,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.bold,
                  fontSize: 13,
                ),
              ),
              const SizedBox(width: 6),
              IconButton(
                icon: const Icon(Icons.copy, size: 14),
                visualDensity: VisualDensity.compact,
                tooltip: tr('Copier l\'identifiant'),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: detail.id));
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(tr('CVE copié')),
                      duration: const Duration(seconds: 2),
                    ),
                  );
                },
              ),
            ],
          ),
          const SizedBox(height: 4),

          // ── Paquet(s) & versions ──
          ...detail.views.where((v) => v.packageName.isNotEmpty).map((v) {
            final fixed = v.fixedVersion.isEmpty
                ? const SizedBox.shrink()
                : Text(
                    '  →  ${v.fixedVersion}',
                    style: const TextStyle(fontSize: 12, color: Colors.green),
                  );
            return Padding(
              padding: const EdgeInsets.only(bottom: 2),
              child: Wrap(
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  _tag(v.scanner),
                  const SizedBox(width: 6),
                  Text(
                    '${v.packageName} ${v.installedVersion}',
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                    ),
                  ),
                  fixed,
                  if (v.extra.isNotEmpty && v.extra.length <= 24)
                    Text(
                      '   ${v.extra}',
                      style: const TextStyle(fontSize: 11, color: Colors.grey),
                    ),
                ],
              ),
            );
          }),
          if (detail.description.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 2, bottom: 2),
              child: Text(
                detail.description,
                style: const TextStyle(fontSize: 12, color: Colors.grey),
              ),
            ),
          const SizedBox(height: 6),

          // ── Sévérité par scanner + dates ──
          _sectionTitle(tr('Rapporté par')),
          Table(
            columnWidths: const {
              0: IntrinsicColumnWidth(),
              1: IntrinsicColumnWidth(),
              2: FlexColumnWidth(),
            },
            children: [
              TableRow(
                children: [
                  const _Th('Scanner'),
                  _Th(tr('Sévérité')),
                  _Th(tr('Publié / modifié')),
                ],
              ),
              for (final v in detail.views)
                TableRow(
                  children: [
                    _Td(v.scanner),
                    _Td(v.severity.isEmpty ? '?' : v.severity),
                    _Td(
                      '${detail._fmtDate(v.publishedDate)}'
                      ' / ${detail._fmtDate(v.modifiedDate)}',
                    ),
                  ],
                ),
            ],
          ),
          const SizedBox(height: 8),

          // ── Exploitabilité ──
          _sectionTitle(tr('Exploitabilité et exploitation active')),
          if (!e.hasAnySignal)
            Text(
              tr('Aucun signal d\'exploitation connu.'),
              style: const TextStyle(fontSize: 12, color: Colors.grey),
            )
          else ...[
            if (e.inKev)
              _line(
                Icons.local_fire_department,
                Colors.red,
                tr('CISA KEV — exploitée activement dans la nature') +
                    (e.kevDateAdded != null
                        ? tr(' · ajoutée le {date}', {'date': detail._fmtDate(e.kevDateAdded)})
                        : '') +
                    (e.kevDueDate != null
                        ? tr(' · échéance {date}', {'date': detail._fmtDate(e.kevDueDate)})
                        : '') +
                    (e.kevRansomware ? tr(' · usage par rançongiciel') : ''),
              ),
            if (e.epssScore != null)
              _line(
                Icons.trending_up,
                Colors.deepOrange,
                tr('EPSS {score} (percentile p{pct}) — probabilité d\'exploitation à 30 jours', {'score': e.epssScore!.toStringAsFixed(2), 'pct': ((e.epssPercentile ?? 0) * 100).round()}),
              ),
            if (e.cvssExploitabilityScore != null || e.exploitMaturity != null)
              _line(
                Icons.speed,
                Colors.teal,
                [
                  if (e.cvssBaseScore != null)
                    'CVSS base ${e.cvssBaseScore!.toStringAsFixed(1)}',
                  if (e.cvssExploitabilityScore != null)
                    tr('exploitabilité {score}/3.9', {'score': e.cvssExploitabilityScore!.toStringAsFixed(1)}),
                  if (e.exploitMaturity != null)
                    tr('maturité {value}', {'value': e.exploitMaturity!}),
                ].join(' · '),
                mono: e.cvssVector,
              ),
            if (e.pocKnown)
              _line(
                Icons.code,
                Colors.purple,
                e.pocCount > 0
                    ? (isPlural(e.pocCount) ? tr('{n} dépôts PoC publics recensés', {'n': e.pocCount}) : tr('{n} dépôt PoC public recensé', {'n': e.pocCount}))
                    : tr('Exploit / PoC public recensé'),
              ),
            for (final url in e.pocUrls)
              Padding(
                padding: const EdgeInsets.only(left: 24, top: 2),
                child: _LinkText(url),
              ),
          ],
          const SizedBox(height: 8),

          // ── VEX : déclarer la CVE non affectée / corrigée ──
          if (VexScope.maybeOf(context) case final vex?) ...[
            ListenableBuilder(
              listenable: vex,
              builder: (context, _) => CveVexRow(
                controller: vex,
                vulnId: detail.id,
                packages: _vexPackages(detail),
              ),
            ),
            const SizedBox(height: 8),
          ],

          // ── Liens externes ──
          if (detail.links.isNotEmpty) ...[
            _sectionTitle(tr('Références')),
            Wrap(
              spacing: 8,
              runSpacing: 4,
              children: [
                for (final (label, url) in detail.links)
                  OutlinedButton.icon(
                    icon: const Icon(Icons.open_in_new, size: 14),
                    label: Text(label, style: const TextStyle(fontSize: 12)),
                    style: OutlinedButton.styleFrom(
                      visualDensity: VisualDensity.compact,
                      padding: const EdgeInsets.symmetric(horizontal: 10),
                    ),
                    onPressed: () => launchUrl(
                      Uri.parse(url),
                      mode: LaunchMode.externalApplication,
                    ),
                  ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  static Widget _sectionTitle(String t) => Padding(
    padding: const EdgeInsets.only(bottom: 3),
    child: Text(
      t.toUpperCase(),
      style: const TextStyle(
        fontSize: 10,
        fontWeight: FontWeight.bold,
        color: Colors.grey,
        letterSpacing: 0.5,
      ),
    ),
  );

  static Widget _tag(String s) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
    decoration: BoxDecoration(
      color: Colors.grey.withValues(alpha: 0.18),
      borderRadius: BorderRadius.circular(4),
    ),
    child: Text(
      s,
      style: const TextStyle(fontSize: 10, fontWeight: FontWeight.w600),
    ),
  );

  static Widget _line(
    IconData icon,
    Color color,
    String text, {
    String? mono,
  }) => Padding(
    padding: const EdgeInsets.only(bottom: 3),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, size: 13, color: color),
            const SizedBox(width: 6),
            Expanded(child: Text(text, style: const TextStyle(fontSize: 12))),
          ],
        ),
        if (mono != null)
          Padding(
            padding: const EdgeInsets.only(left: 19, top: 1),
            child: SelectableText(
              mono,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 11,
                color: Colors.grey,
              ),
            ),
          ),
      ],
    ),
  );
}

class _Th extends StatelessWidget {
  final String text;
  const _Th(this.text);
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(right: 12, bottom: 2),
    child: Text(
      text,
      style: const TextStyle(
        fontSize: 10,
        fontWeight: FontWeight.bold,
        color: Colors.grey,
      ),
    ),
  );
}

class _Td extends StatelessWidget {
  final String text;
  const _Td(this.text);
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(right: 12, bottom: 2),
    child: Text(text, style: const TextStyle(fontSize: 12)),
  );
}

class _LinkText extends StatelessWidget {
  final String url;
  const _LinkText(this.url);
  @override
  Widget build(BuildContext context) => InkWell(
    onTap: () =>
        launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication),
    child: Text(
      url,
      style: TextStyle(
        fontSize: 11,
        color: Theme.of(context).colorScheme.primary,
        decoration: TextDecoration.underline,
      ),
    ),
  );
}
