import 'dart:io';
import 'image_layers.dart';
import 'models.dart';
import 'i18n.dart';

/// Génère un rapport SBOM HTML autonome (aucune dépendance externe).
///
/// Le rapport contient :
///   • En-tête avec nom du document et statistiques
///   • Graphiques CSS-only (barres horizontales) pour les licences et écosystèmes
///   • Tableau filtrable + triable en JavaScript vanilla
class HtmlGenerator {
  /// Libellé de licence absente (aussi clé de regroupement des statistiques).
  String get _unspecified => tr('Non spécifiée', 'Not specified');

  Future<void> writeToFile(
    List<Package> packages,
    String outputPath, {
    String? documentName,
    LayerAnnotations? layers,
  }) async {
    final html =
        _buildHtml(packages, documentName: documentName, layers: layers);
    await File(outputPath).writeAsString(html, flush: true);
  }

  String _buildHtml(List<Package> packages,
      {String? documentName, LayerAnnotations? layers}) {
    var title = documentName ?? 'SBOM Report';
    if (layers?.isLayerDocument == true)
      title = '$title — ${layers!.layerLabel}';
    final now = DateTime.now();
    final date = '${now.year.toString().padLeft(4, '0')}-'
        '${now.month.toString().padLeft(2, '0')}-'
        '${now.day.toString().padLeft(2, '0')}';

    // Statistiques
    final ecosystems = <String, int>{};
    final licenses = <String, int>{};
    for (final pkg in packages) {
      ecosystems[pkg.packageType] = (ecosystems[pkg.packageType] ?? 0) + 1;
      final lic = pkg.license.isEmpty ? _unspecified : pkg.license;
      licenses[lic] = (licenses[lic] ?? 0) + 1;
    }

    final sortedEco = (ecosystems.entries.toList()
          ..sort((a, b) => b.value.compareTo(a.value)))
        .take(10)
        .toList();
    final sortedLic = (licenses.entries.toList()
          ..sort((a, b) => b.value.compareTo(a.value)))
        .take(15)
        .toList();

    final maxEco = sortedEco.isEmpty ? 1 : sortedEco.first.value;
    final maxLic = sortedLic.isEmpty ? 1 : sortedLic.first.value;

    final ecoRows = sortedEco.map((e) {
      final pct = (e.value / maxEco * 100).round();
      return '''
        <tr>
          <td class="label">${_esc(e.key)}</td>
          <td class="bar-cell"><div class="bar" style="width:${pct}%"></div></td>
          <td class="count">${e.value}</td>
        </tr>''';
    }).join('\n');

    final licRows = sortedLic.map((e) {
      final pct = (e.value / maxLic * 100).round();
      return '''
        <tr>
          <td class="label">${_esc(e.key)}</td>
          <td class="bar-cell"><div class="bar" style="width:${pct}%"></div></td>
          <td class="count">${e.value}</td>
        </tr>''';
    }).join('\n');

    // Lignes du tableau des composants
    final rows = packages.map((pkg) {
      final type = _ecosystemBadge(pkg.packageType);
      final lic = pkg.license.isEmpty ? '<em>—</em>' : _esc(pkg.license);
      final url = pkg.url.isNotEmpty
          ? '<a href="${_esc(pkg.url)}" target="_blank" rel="noopener">${_esc(pkg.url)}</a>'
          : '';
      final purl = pkg.purl.isNotEmpty ? '<code>${_esc(pkg.purl)}</code>' : '';
      return '<tr>'
          '<td>${_esc(pkg.name)}</td>'
          '<td>${_esc(pkg.version)}</td>'
          '<td>$type</td>'
          '<td>$lic</td>'
          '<td>${_esc(pkg.summary)}</td>'
          '<td>$url</td>'
          '<td class="purl-cell">$purl</td>'
          '${layers != null ? '<td>${_esc(layers.columnValue(pkg))}</td>' : ''}'
          '</tr>';
    }).join('\n');

    // Analyse par couche : description + composants supprimés.
    final layerInfo = layers == null
        ? ''
        : '''
  <div class="chart-card layer-info">
    <h2>${layers.isLayerDocument ? 'Couche' : 'Couches de l\'image'}</h2>
    <ul>${layers.describe().map((l) => '<li>${_esc(l)}</li>').join()}</ul>
  </div>''';
    final removedInfo = layers == null || layers.removed.isEmpty
        ? ''
        : '''
  <div class="chart-card layer-info">
    <h2>${tr('Supprimés par cette couche', 'Removed by this layer')} (${layers.removed.length})</h2>
    <ul>${layers.removed.map((p) => '<li>${_esc(p.name)} ${_esc(p.fullVersion)}</li>').join()}</ul>
  </div>''';

    return '''<!DOCTYPE html>
<html lang="${tr('fr', 'en')}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${_esc(title)}</title>
<style>
  :root {
    --accent: #3b82f6;
    --bg: #f8fafc;
    --card: #ffffff;
    --border: #e2e8f0;
    --text: #1e293b;
    --muted: #64748b;
    --badge-bg: #eff6ff;
    --badge-fg: #1d4ed8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); font-size: 14px; }
  header { background: var(--accent); color: #fff; padding: 24px 32px; }
  header h1 { font-size: 22px; font-weight: 700; }
  header .meta { opacity: .8; font-size: 13px; margin-top: 4px; }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
  .stat-card .num { font-size: 28px; font-weight: 700; color: var(--accent); }
  .stat-card .lbl { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  @media (max-width: 700px) { .charts { grid-template-columns: 1fr; } }
  .chart-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .chart-card h2 { font-size: 14px; font-weight: 600; margin-bottom: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
  table.chart { width: 100%; border-collapse: collapse; }
  table.chart .label { white-space: nowrap; padding: 3px 8px 3px 0; font-size: 12px; max-width: 160px; overflow: hidden; text-overflow: ellipsis; }
  table.chart .bar-cell { width: 100%; padding: 3px 8px; }
  table.chart .bar { height: 14px; background: var(--accent); border-radius: 3px; min-width: 2px; opacity: .75; }
  table.chart .count { white-space: nowrap; padding: 3px 0 3px 4px; font-size: 12px; color: var(--muted); }
  .toolbar { display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
  .toolbar input { padding: 7px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; width: 320px; }
  .toolbar select { padding: 7px 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; }
  .toolbar .count-label { color: var(--muted); font-size: 13px; margin-left: auto; }
  .table-wrapper { overflow-x: auto; background: var(--card); border: 1px solid var(--border); border-radius: 8px; }
  table.components { width: 100%; border-collapse: collapse; }
  table.components th { background: var(--bg); padding: 10px 12px; text-align: left; font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid var(--border); cursor: pointer; user-select: none; white-space: nowrap; }
  table.components th:hover { color: var(--text); }
  table.components th .sort-icon { margin-left: 4px; opacity: .4; }
  table.components th.sorted .sort-icon { opacity: 1; }
  table.components td { padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  table.components tr:last-child td { border-bottom: none; }
  table.components tr:hover td { background: var(--bg); }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: 600; background: var(--badge-bg); color: var(--badge-fg); }
  .purl-cell { max-width: 280px; }
  .purl-cell code { font-size: 11px; color: var(--muted); word-break: break-all; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .layer-info { margin-bottom: 24px; }
  .layer-info ul { padding-left: 20px; }
  .layer-info li { margin: 3px 0; word-break: break-word; }
  footer { text-align: center; color: var(--muted); font-size: 12px; padding: 24px; }
</style>
</head>
<body>
<header>
  <h1>${_esc(title)}</h1>
  <div class="meta">${tr('Généré le', 'Generated on')} $date &nbsp;•&nbsp; ${packages.length} ${tr('composant(s)', 'component(s)')} &nbsp;•&nbsp; sbom_generator</div>
</header>
<div class="container">

  <!-- Statistiques -->
  <div class="stats-grid">
    <div class="stat-card"><div class="num">${packages.length}</div><div class="lbl">${tr('Composants', 'Components')}</div></div>
    <div class="stat-card"><div class="num">${ecosystems.length}</div><div class="lbl">${tr('Écosystèmes', 'Ecosystems')}</div></div>
    <div class="stat-card"><div class="num">${licenses.length}</div><div class="lbl">${tr('Licences distinctes', 'Distinct licenses')}</div></div>
    <div class="stat-card"><div class="num">${licenses.entries.where((e) => e.key == _unspecified).fold(0, (s, e) => s + e.value)}</div><div class="lbl">${tr('Sans licence', 'No license')}</div></div>
  </div>

$layerInfo
$removedInfo

  <!-- Graphiques -->
  <div class="charts">
    <div class="chart-card">
      <h2>${tr('Écosystèmes', 'Ecosystems')}</h2>
      <table class="chart"><tbody>$ecoRows</tbody></table>
    </div>
    <div class="chart-card">
      <h2>${tr('Licences (top 15)', 'Licenses (top 15)')}</h2>
      <table class="chart"><tbody>$licRows</tbody></table>
    </div>
  </div>

  <!-- Tableau des composants -->
  <div class="toolbar">
    <input type="search" id="search" placeholder="${tr('Filtrer par nom, version, licence…', 'Filter by name, version, license…')}" oninput="filterTable()">
    <select id="typeFilter" onchange="filterTable()">
      <option value="">${tr('Tous les types', 'All types')}</option>
      ${sortedEco.map((e) => '<option value="${_esc(e.key)}">${_esc(e.key)} (${e.value})</option>').join('\n      ')}
    </select>
    <span class="count-label" id="countLabel">${packages.length} ${tr('composant(s)', 'component(s)')}</span>
  </div>
  <div class="table-wrapper">
    <table class="components" id="compTable">
      <thead>
        <tr>
          <th onclick="sortTable(0)" class="sorted">${tr('Nom', 'Name')} <span class="sort-icon">▲</span></th>
          <th onclick="sortTable(1)">Version <span class="sort-icon">↕</span></th>
          <th onclick="sortTable(2)">${tr('Type', 'Type')} <span class="sort-icon">↕</span></th>
          <th onclick="sortTable(3)">${tr('Licence', 'License')} <span class="sort-icon">↕</span></th>
          <th onclick="sortTable(4)">Description <span class="sort-icon">↕</span></th>
          <th onclick="sortTable(5)">URL <span class="sort-icon">↕</span></th>
          <th>PURL</th>
          ${layers != null ? '<th onclick="sortTable(7)">${_esc(layers.columnTitle)} <span class="sort-icon">↕</span></th>' : ''}
        </tr>
      </thead>
      <tbody id="compBody">
$rows
      </tbody>
    </table>
  </div>
</div>
<footer>${tr('Rapport généré par', 'Report generated by')} <strong>sbom_generator</strong></footer>

<script>
  let sortCol = 0, sortAsc = true;

  function filterTable() {
    const q = document.getElementById('search').value.toLowerCase();
    const type = document.getElementById('typeFilter').value.toLowerCase();
    const rows = document.querySelectorAll('#compBody tr');
    let visible = 0;
    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      const typeCell = row.cells[2].textContent.toLowerCase();
      const match = (!q || text.includes(q)) && (!type || typeCell.includes(type));
      row.style.display = match ? '' : 'none';
      if (match) visible++;
    });
    document.getElementById('countLabel').textContent = visible + ' ${tr('composant(s)', 'component(s)')}';
  }

  function sortTable(col) {
    if (sortCol === col) sortAsc = !sortAsc; else { sortCol = col; sortAsc = true; }
    const ths = document.querySelectorAll('#compTable th');
    ths.forEach((th, i) => {
      th.classList.toggle('sorted', i === col);
      const icon = th.querySelector('.sort-icon');
      if (icon) icon.textContent = i === col ? (sortAsc ? '▲' : '▼') : '↕';
    });
    const tbody = document.getElementById('compBody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => {
      const av = a.cells[col]?.textContent?.trim() ?? '';
      const bv = b.cells[col]?.textContent?.trim() ?? '';
      return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach(r => tbody.appendChild(r));
  }
</script>
</body>
</html>''';
  }

  String _ecosystemBadge(String type) =>
      '<span class="badge">${_esc(type)}</span>';

  String _esc(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');
}
