import 'package:flutter/material.dart';

import 'grype_panel.dart';
import 'osv_panel.dart';
import 'trivy_panel.dart';

// ─── Tableau de bord de synthèse ─────────────────────────────────────────────

class DashboardPanel extends StatelessWidget {
  final List<GrypeVuln>? grypeVulns;
  final List<OsvVuln>? osvVulns;
  final List<TrivyVuln>? trivyVulns;

  const DashboardPanel({
    super.key,
    required this.grypeVulns,
    required this.osvVulns,
    required this.trivyVulns,
  });

  // Normalise les sévérités en clé minuscule commune
  static String _norm(String s) => s.toLowerCase();

  static Map<String, int> _countByKey(Iterable<String> severities) {
    final m = <String, int>{};
    for (final s in severities) {
      m[_norm(s)] = (m[_norm(s)] ?? 0) + 1;
    }
    return m;
  }

  @override
  Widget build(BuildContext context) {
    final grype = grypeVulns;
    final osv = osvVulns;
    final trivy = trivyVulns;

    // CVE IDs uniques sur l'ensemble des scanners
    final allIds = <String>{
      if (grype != null) ...grype.map((v) => v.id),
      if (osv != null) ...osv.map((v) => v.id),
      if (trivy != null) ...trivy.map((v) => v.id),
    };
    final scansRun = [grype, osv, trivy].where((l) => l != null).length;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Synthèse globale ──
          _GlobalSummary(
            uniqueIds: allIds.length,
            scansRun: scansRun,
            grypeCount: grype?.length,
            osvCount: osv?.length,
            trivyCount: trivy?.length,
          ),

          const SizedBox(height: 20),

          // ── Cartes par scanner ──
          LayoutBuilder(builder: (_, constraints) {
            final wide = constraints.maxWidth > 750;
            final cards = [
              _ScannerCard(
                name: 'Grype',
                icon: Icons.security_outlined,
                color: const Color(0xFF1565C0),
                vulns: grype,
                severities: grype?.map((v) => v.severity).toList(),
              ),
              _ScannerCard(
                name: 'OSV-Scanner',
                icon: Icons.plagiarism_outlined,
                color: const Color(0xFF6A1B9A),
                vulns: osv,
                severities: osv?.map((v) => v.severity).toList(),
              ),
              _ScannerCard(
                name: 'Trivy',
                icon: Icons.shield_outlined,
                color: const Color(0xFF00695C),
                vulns: trivy,
                severities: trivy?.map((v) => v.severity).toList(),
              ),
            ];
            return wide
                ? IntrinsicHeight(
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: cards
                          .expand((c) => [Expanded(child: c), const SizedBox(width: 16)])
                          .toList()
                        ..removeLast(),
                    ),
                  )
                : Column(
                    children: cards
                        .expand((c) => [c, const SizedBox(height: 16)])
                        .toList()
                      ..removeLast(),
                  );
          }),

          // ── CVEs présents dans plusieurs scanners ──
          if (scansRun >= 2 && allIds.isNotEmpty) ...[
            const SizedBox(height: 24),
            _CrossScannerSection(
              grypeVulns: grype,
              osvVulns: osv,
              trivyVulns: trivy,
            ),
          ],
        ],
      ),
    );
  }
}

// ─── Synthèse globale ─────────────────────────────────────────────────────────

class _GlobalSummary extends StatelessWidget {
  final int uniqueIds;
  final int scansRun;
  final int? grypeCount;
  final int? osvCount;
  final int? trivyCount;

  const _GlobalSummary({
    required this.uniqueIds,
    required this.scansRun,
    required this.grypeCount,
    required this.osvCount,
    required this.trivyCount,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Icon(Icons.dashboard_outlined,
                size: 32, color: theme.colorScheme.primary),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Tableau de bord des vulnérabilités',
                      style: theme.textTheme.titleMedium
                          ?.copyWith(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 4),
                  Text(
                    scansRun == 0
                        ? 'Aucun scanner exécuté — lancez un scan depuis les onglets Grype, OSV-Scanner ou Trivy.'
                        : '$scansRun scanner(s) exécuté(s) · $uniqueIds CVE(s) unique(s) détecté(s)',
                    style: TextStyle(
                        fontSize: 13,
                        color: theme.colorScheme.onSurface
                            .withValues(alpha: 0.7)),
                  ),
                ],
              ),
            ),
            if (scansRun > 0) ...[
              _StatBadge(label: 'CVE uniques', value: uniqueIds,
                  color: uniqueIds == 0 ? Colors.green : Colors.red[700]!),
            ],
          ],
        ),
      ),
    );
  }
}

class _StatBadge extends StatelessWidget {
  final String label;
  final int value;
  final Color color;
  const _StatBadge({required this.label, required this.value, required this.color});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text('$value',
            style: TextStyle(
                fontSize: 28, fontWeight: FontWeight.bold, color: color)),
        Text(label,
            style: const TextStyle(fontSize: 11, color: Colors.grey)),
      ],
    );
  }
}

// ─── Carte scanner ────────────────────────────────────────────────────────────

class _ScannerCard extends StatelessWidget {
  final String name;
  final IconData icon;
  final Color color;
  final List<dynamic>? vulns;
  final List<String>? severities;

  const _ScannerCard({
    required this.name,
    required this.icon,
    required this.color,
    required this.vulns,
    required this.severities,
  });

  @override
  Widget build(BuildContext context) {
    final total = vulns?.length ?? 0;
    final loaded = vulns != null;
    final counts = severities != null
        ? DashboardPanel._countByKey(severities!)
        : <String, int>{};

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── En-tête ──
            Row(
              children: [
                Icon(icon, size: 20, color: color),
                const SizedBox(width: 8),
                Text(name,
                    style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 14,
                        color: color)),
                const Spacer(),
                if (!loaded)
                  Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 8, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.grey[200],
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: const Text('Non exécuté',
                        style:
                            TextStyle(fontSize: 10, color: Colors.grey)),
                  )
                else
                  Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 8, vertical: 2),
                    decoration: BoxDecoration(
                      color: total == 0
                          ? Colors.green[50]
                          : Colors.red[50],
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      total == 0 ? '✓ Aucune' : '$total vulnérabilités',
                      style: TextStyle(
                          fontSize: 11,
                          color: total == 0
                              ? Colors.green[700]
                              : Colors.red[700],
                          fontWeight: FontWeight.w600),
                    ),
                  ),
              ],
            ),

            const SizedBox(height: 12),

            if (!loaded)
              Container(
                padding: const EdgeInsets.symmetric(vertical: 16),
                alignment: Alignment.center,
                child: Column(
                  children: [
                    Icon(Icons.play_circle_outline,
                        size: 32, color: Colors.grey[400]),
                    const SizedBox(height: 6),
                    Text(
                      'Lancez le scan depuis\nl\'onglet $name',
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                          fontSize: 11, color: Colors.grey),
                    ),
                  ],
                ),
              )
            else if (total == 0)
              Container(
                padding: const EdgeInsets.symmetric(vertical: 16),
                alignment: Alignment.center,
                child: Column(
                  children: [
                    Icon(Icons.verified_user_outlined,
                        size: 32, color: Colors.green[400]),
                    const SizedBox(height: 6),
                    Text('Aucune vulnérabilité détectée',
                        style: TextStyle(
                            fontSize: 11, color: Colors.green[700])),
                  ],
                ),
              )
            else ...[
              // ── Barre de sévérité empilée ──
              _SeverityBar(counts: counts, total: total),
              const SizedBox(height: 12),
              // ── Détail par sévérité ──
              for (final entry in _sevRows(counts))
                _SevRow(
                  label: entry.label,
                  count: entry.count,
                  total: total,
                  fg: entry.fg,
                  bg: entry.bg,
                ),
            ],
          ],
        ),
      ),
    );
  }

  static List<_SevEntry> _sevRows(Map<String, int> counts) {
    return [
      _SevEntry('Critical', counts['critical'] ?? 0,
          const Color(0xFFB71C1C), const Color(0xFFFFEBEE)),
      _SevEntry('High', counts['high'] ?? 0,
          const Color(0xFFBF360C), const Color(0xFFFBE9E7)),
      _SevEntry('Medium', counts['medium'] ?? 0,
          const Color(0xFFE65100), const Color(0xFFFFF3E0)),
      _SevEntry('Low', counts['low'] ?? 0,
          const Color(0xFF2E7D32), const Color(0xFFF1F8E9)),
      _SevEntry('Autre', (counts['negligible'] ?? 0) +
          (counts['unknown'] ?? 0) +
          counts.entries
              .where((e) => !const {
                    'critical', 'high', 'medium', 'low',
                    'negligible', 'unknown'
                  }.contains(e.key))
              .fold(0, (s, e) => s + e.value),
          Colors.grey, const Color(0xFFF5F5F5)),
    ].where((e) => e.count > 0).toList();
  }
}

class _SevEntry {
  final String label;
  final int count;
  final Color fg;
  final Color bg;
  const _SevEntry(this.label, this.count, this.fg, this.bg);
}

// ─── Barre empilée ────────────────────────────────────────────────────────────

class _SeverityBar extends StatelessWidget {
  final Map<String, int> counts;
  final int total;

  const _SeverityBar({required this.counts, required this.total});

  @override
  Widget build(BuildContext context) {
    if (total == 0) return const SizedBox.shrink();

    int c(String k) => counts[k] ?? 0;
    final other = total -
        c('critical') - c('high') - c('medium') - c('low') -
        c('negligible') - c('unknown');

    final segs = [
      (c('critical'), const Color(0xFFB71C1C)),
      (c('high'), const Color(0xFFBF360C)),
      (c('medium'), const Color(0xFFE65100)),
      (c('low'), const Color(0xFF2E7D32)),
      (c('negligible') + c('unknown') + (other > 0 ? other : 0), Colors.grey),
    ].where((s) => s.$1 > 0).toList();

    return ClipRRect(
      borderRadius: BorderRadius.circular(4),
      child: SizedBox(
        height: 10,
        child: Row(
          children: [
            for (final seg in segs)
              Expanded(
                flex: seg.$1,
                child: Container(color: seg.$2),
              ),
          ],
        ),
      ),
    );
  }
}

// ─── Ligne de sévérité ────────────────────────────────────────────────────────

class _SevRow extends StatelessWidget {
  final String label;
  final int count;
  final int total;
  final Color fg;
  final Color bg;

  const _SevRow({
    required this.label,
    required this.count,
    required this.total,
    required this.fg,
    required this.bg,
  });

  @override
  Widget build(BuildContext context) {
    final pct = total > 0 ? count / total : 0.0;
    return Padding(
      padding: const EdgeInsets.only(bottom: 5),
      child: Row(
        children: [
          Container(
            width: 68,
            padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
            decoration: BoxDecoration(
              color: bg,
              borderRadius: BorderRadius.circular(3),
              border: Border.all(color: fg, width: 0.6),
            ),
            child: Text(label,
                style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: fg)),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(3),
              child: LinearProgressIndicator(
                value: pct,
                minHeight: 7,
                backgroundColor: Colors.grey[200],
                valueColor: AlwaysStoppedAnimation<Color>(fg),
              ),
            ),
          ),
          const SizedBox(width: 6),
          SizedBox(
            width: 28,
            child: Text('$count',
                textAlign: TextAlign.right,
                style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                    color: fg)),
          ),
        ],
      ),
    );
  }
}

// ─── Section CVEs multi-scanners ─────────────────────────────────────────────

class _CrossScannerSection extends StatelessWidget {
  final List<GrypeVuln>? grypeVulns;
  final List<OsvVuln>? osvVulns;
  final List<TrivyVuln>? trivyVulns;

  const _CrossScannerSection({
    required this.grypeVulns,
    required this.osvVulns,
    required this.trivyVulns,
  });

  @override
  Widget build(BuildContext context) {
    // CVEs par scanner
    final grypeIds = grypeVulns?.map((v) => v.id).toSet() ?? {};
    final osvIds = osvVulns?.map((v) => v.id).toSet() ?? {};
    final trivyIds = trivyVulns?.map((v) => v.id).toSet() ?? {};

    // CVEs dans au moins 2 scanners
    final allIds = {...grypeIds, ...osvIds, ...trivyIds};
    final crossIds = allIds.where((id) {
      int n = 0;
      if (grypeIds.contains(id)) n++;
      if (osvIds.contains(id)) n++;
      if (trivyIds.contains(id)) n++;
      return n >= 2;
    }).toList();

    if (crossIds.isEmpty) return const SizedBox.shrink();

    // Trier par sévérité max (depuis grype en priorité)
    final grypeMap = {for (final v in grypeVulns ?? []) v.id: v.severity};
    final osvMap = {for (final v in osvVulns ?? []) v.id: v.severity};
    final trivyMap = {for (final v in trivyVulns ?? []) v.id: v.severity};

    int sevOrd(String? s) => switch ((s ?? '').toLowerCase()) {
          'critical' => 0,
          'high' => 1,
          'medium' => 2,
          'low' => 3,
          _ => 4,
        };

    crossIds.sort((a, b) {
      final sa = [grypeMap[a], osvMap[a], trivyMap[a]]
          .map((s) => sevOrd(s))
          .reduce((x, y) => x < y ? x : y);
      final sb = [grypeMap[b], osvMap[b], trivyMap[b]]
          .map((s) => sevOrd(s))
          .reduce((x, y) => x < y ? x : y);
      return sa.compareTo(sb);
    });

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.join_inner, size: 18, color: Colors.deepOrange),
                const SizedBox(width: 8),
                Text(
                  'CVE détectés par plusieurs scanners (${crossIds.length})',
                  style: const TextStyle(
                      fontWeight: FontWeight.bold, fontSize: 13),
                ),
              ],
            ),
            const SizedBox(height: 10),
            // En-têtes
            Container(
              color: Theme.of(context).colorScheme.surfaceContainerHigh,
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              child: Row(
                children: [
                  const SizedBox(
                    width: 80,
                    child: Text('SÉVÉRITÉ',
                        style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: Colors.grey)),
                  ),
                  const Expanded(
                    child: Text('CVE / ID',
                        style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: Colors.grey)),
                  ),
                  for (final s in ['Grype', 'OSV', 'Trivy'])
                    SizedBox(
                      width: 52,
                      child: Text(s,
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                              fontSize: 10,
                              fontWeight: FontWeight.bold,
                              color: Colors.grey)),
                    ),
                ],
              ),
            ),
            // Lignes — toutes affichées, le SingleChildScrollView parent gère le défilement
            for (final id in crossIds)
              _CrossRow(
                id: id,
                inGrype: grypeIds.contains(id),
                inOsv: osvIds.contains(id),
                inTrivy: trivyIds.contains(id),
                severity: grypeMap[id] ?? osvMap[id] ?? trivyMap[id] ?? '',
              ),
          ],
        ),
      ),
    );
  }
}

class _CrossRow extends StatelessWidget {
  final String id;
  final bool inGrype;
  final bool inOsv;
  final bool inTrivy;
  final String severity;

  const _CrossRow({
    required this.id,
    required this.inGrype,
    required this.inOsv,
    required this.inTrivy,
    required this.severity,
  });

  static Color _fg(String s) => switch (s.toLowerCase()) {
        'critical' => const Color(0xFFB71C1C),
        'high' => const Color(0xFFBF360C),
        'medium' => const Color(0xFFE65100),
        'low' => const Color(0xFF2E7D32),
        _ => Colors.grey,
      };

  static Color _bg(String s) => switch (s.toLowerCase()) {
        'critical' => const Color(0xFFFFEBEE),
        'high' => const Color(0xFFFBE9E7),
        'medium' => const Color(0xFFFFF3E0),
        'low' => const Color(0xFFF1F8E9),
        _ => const Color(0xFFF5F5F5),
      };

  @override
  Widget build(BuildContext context) {
    final fg = _fg(severity);
    final bg = _bg(severity);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        border: Border(
          bottom: BorderSide(color: Colors.grey[200]!, width: 0.5),
        ),
      ),
      child: Row(
        children: [
          SizedBox(
            width: 80,
            child: Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
              decoration: BoxDecoration(
                color: bg,
                borderRadius: BorderRadius.circular(3),
                border: Border.all(color: fg, width: 0.6),
              ),
              child: Text(
                severity.isEmpty ? '?' : severity,
                style: TextStyle(
                    fontSize: 9,
                    fontWeight: FontWeight.bold,
                    color: fg),
              ),
            ),
          ),
          Expanded(
            child: Text(
              id,
              style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  fontWeight: FontWeight.w500),
            ),
          ),
          for (final present in [inGrype, inOsv, inTrivy])
            SizedBox(
              width: 52,
              child: Icon(
                present ? Icons.check_circle : Icons.radio_button_unchecked,
                size: 14,
                color: present ? Colors.green[600] : Colors.grey[300],
              ),
            ),
        ],
      ),
    );
  }
}
