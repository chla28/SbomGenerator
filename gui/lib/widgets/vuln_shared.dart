// ─── Composants et helpers partagés entre grype_panel, trivy_panel et
// osv_panel : les trois onglets de scan de vulnérabilités affichent une
// table triable/filtrable/exportable sur le même modèle et dupliquaient
// jusqu'ici ce code presque à l'identique.

import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../models/cve_date_filter.dart';
import '../services/scan_enrichment.dart';
import 'cve_detail.dart';
import 'help_icon.dart';
import 'pdf_report.dart';

// ─── Couleurs de sévérité ───────────────────────────────────────────────────

/// Couleur de premier plan (texte/icône) associée à une sévérité de
/// vulnérabilité. Insensible à la casse ('Critical', 'CRITICAL', 'critical'
/// donnent le même résultat).
Color severityFg(String severity) => switch (severity.toLowerCase()) {
      'critical' => const Color(0xFFB71C1C),
      'high' => const Color(0xFFBF360C),
      'medium' => const Color(0xFFE65100),
      'low' => const Color(0xFF2E7D32),
      'negligible' => Colors.grey,
      _ => Colors.grey,
    };

/// Couleur de fond associée à une sévérité de vulnérabilité.
Color severityBg(String severity) => switch (severity.toLowerCase()) {
      'critical' => const Color(0xFFFFEBEE),
      'high' => const Color(0xFFFBE9E7),
      'medium' => const Color(0xFFFFF3E0),
      'low' => const Color(0xFFF1F8E9),
      'negligible' => const Color(0xFFF5F5F5),
      _ => const Color(0xFFF5F5F5),
    };

// ─── Export CSV ─────────────────────────────────────────────────────────────

/// Échappe une valeur pour l'écriture dans un fichier CSV (RFC 4180).
String csvEscape(String s) {
  if (s.contains(',') || s.contains('"') || s.contains('\n')) {
    return '"${s.replaceAll('"', '""')}"';
  }
  return s;
}

// ─── Export AsciiDoc + PDF ──────────────────────────────────────────────────

/// Échappe une valeur pour une cellule de tableau AsciiDoc : "|" en début de
/// contenu y est ambigu (nouvelle cellule), on l'échappe systématiquement.
String adocEscape(String s) => s.replaceAll('|', '\\|');

/// Associe le nom d'outil affiché (`widget.toolName` de grype/osv/trivy_panel)
/// à sa fonction de détection de version (pdf_report.dart).
Future<String?> _toolVersionFor(String toolName) => switch (toolName) {
      'Grype' => grypeVersion(),
      'OSV-Scanner' => osvScannerVersion(),
      'Trivy' => trivyVersion(),
      _ => Future.value(null),
    };

String _dateFilterSummary(CveDateFilter f) {
  final fieldLabel = switch (f.field) {
    CveDateField.published => 'publication',
    CveDateField.modified => 'dernière modification',
    CveDateField.latest => 'plus récente des deux',
  };
  final parts = <String>[];
  if (f.after != null) parts.add('après ${f.after!.toIso8601String().split('T').first}');
  if (f.before != null) parts.add('avant ${f.before!.toIso8601String().split('T').first}');
  final bounds = parts.isEmpty ? 'aucune borne' : parts.join(', ');
  final undated = f.includeUndated ? ', dont sans date connue' : '';
  return '$fieldLabel — $bounds$undated';
}

// ─── Bannière d'erreur ──────────────────────────────────────────────────────

class ErrorBanner extends StatelessWidget {
  final String message;
  const ErrorBanner({super.key, required this.message});

  @override
  Widget build(BuildContext context) => Container(
        color: Colors.red[50],
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Icon(Icons.error_outline, color: Colors.red, size: 18),
            const SizedBox(width: 8),
            Expanded(
              child: SelectableText(
                message,
                style: TextStyle(color: Colors.red[800], fontSize: 13),
                maxLines: 5,
              ),
            ),
          ],
        ),
      );
}

// ─── Vue JSON brut ────────────────────────────────────────────────────────

class JsonView extends StatelessWidget {
  final String json;
  const JsonView({super.key, required this.json});

  String _pretty() {
    try {
      return const JsonEncoder.withIndent('  ').convert(jsonDecode(json));
    } catch (_) {
      return json;
    }
  }

  @override
  Widget build(BuildContext context) {
    if (json.isEmpty) {
      return const Center(child: Text('Pas de sortie JSON.'));
    }
    final pretty = _pretty();
    return Stack(
      children: [
        Container(
          color: const Color(0xFF1E1E1E),
          padding: const EdgeInsets.all(12),
          child: SelectionArea(
            child: SingleChildScrollView(
              child: Text(
                pretty,
                style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: Color(0xFFD4D4D4),
                    height: 1.5),
              ),
            ),
          ),
        ),
        Positioned(
          top: 8,
          right: 8,
          child: Tooltip(
            message: 'Copier le JSON',
            child: IconButton(
              icon: const Icon(Icons.copy_outlined,
                  size: 18, color: Colors.white70),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: json));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('JSON copié'),
                    duration: Duration(seconds: 2),
                  ),
                );
              },
            ),
          ),
        ),
      ],
    );
  }
}

// ─── En-tête de colonne triable ─────────────────────────────────────────────

class SortHeader extends StatelessWidget {
  final String label;
  final bool active;
  final bool ascending;
  final VoidCallback onTap;
  final double? width;

  const SortHeader(this.label, this.active, this.ascending, this.onTap,
      {super.key, this.width});

  @override
  Widget build(BuildContext context) {
    final color =
        active ? Theme.of(context).colorScheme.primary : Colors.grey[600]!;
    final labelText = Text(label,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(
            fontSize: 10, fontWeight: FontWeight.bold, color: color));
    final bounded = width != null;
    Widget cell = InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(4),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 2, vertical: 2),
        child: Row(
          // Sous contrainte de largeur, la Row remplit la cellule et le
          // libellé (Flexible) cède la place à la flèche par ellipse.
          mainAxisSize: bounded ? MainAxisSize.max : MainAxisSize.min,
          children: [
            bounded ? Flexible(child: labelText) : labelText,
            if (active) ...[
              const SizedBox(width: 2),
              Icon(ascending ? Icons.arrow_upward : Icons.arrow_downward,
                  size: 11, color: color),
            ],
          ],
        ),
      ),
    );
    return bounded ? SizedBox(width: width, child: cell) : cell;
  }
}

// ─── Split-button pour sélection de fichier avec filtre ───────────────────

class SplitPickButton extends StatefulWidget {
  final String filterLabel;
  final VoidCallback onPickFiltered;
  final VoidCallback onPickAll;

  const SplitPickButton({
    super.key,
    required this.filterLabel,
    required this.onPickFiltered,
    required this.onPickAll,
  });

  @override
  State<SplitPickButton> createState() => _SplitPickButtonState();
}

class _SplitPickButtonState extends State<SplitPickButton> {
  final MenuController _menu = MenuController();

  @override
  Widget build(BuildContext context) {
    return MenuAnchor(
      controller: _menu,
      menuChildren: [
        MenuItemButton(
          leadingIcon: const Icon(Icons.filter_alt_outlined, size: 16),
          onPressed: () {
            _menu.close();
            widget.onPickFiltered();
          },
          child: Text('Type filtré (${widget.filterLabel})'),
        ),
        MenuItemButton(
          leadingIcon: const Icon(Icons.folder_open, size: 16),
          onPressed: () {
            _menu.close();
            widget.onPickAll();
          },
          child: const Text('Tous les fichiers'),
        ),
      ],
      builder: (context, controller, _) => OutlinedButton.icon(
        onPressed: controller.isOpen ? controller.close : controller.open,
        icon: const Icon(Icons.folder_open, size: 18),
        label: const Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('Choisir'),
            SizedBox(width: 4),
            Icon(Icons.arrow_drop_down, size: 16),
          ],
        ),
      ),
    );
  }
}

// ─── Sélection de la source à analyser (fichier SBOM ou image) ─────────────
//
// Grype, Trivy et osv-scanner savent tous les trois analyser directement une
// image de conteneur en plus d'un fichier SBOM déjà généré. Les trois
// panneaux partagent la bascule et le champ de référence d'image ; seule la
// commande envoyée au sous-processus diffère (voir chaque `*_runner.dart`).

/// Source choisie pour l'analyse : un fichier SBOM déjà généré, ou une image
/// de conteneur (registre, archive locale, ou répertoire OCI layout) scannée
/// directement par l'outil.
enum ScanSourceKind { sbomFile, image }

/// Heuristique pour distinguer un chemin local (archive ou répertoire OCI
/// layout) d'une référence de registre (ex. `nginx:latest`,
/// `ghcr.io/org/app:tag`) : un chemin local commence toujours par `/`, `./`,
/// `../` ou `~`.
bool looksLikeLocalPath(String s) =>
    s.startsWith('/') ||
    s.startsWith('./') ||
    s.startsWith('../') ||
    s.startsWith('~');

/// Bascule "Fichier SBOM" / "Image de conteneur", partagée par les 3 onglets
/// de scan.
class ScanSourceToggle extends StatelessWidget {
  final ScanSourceKind kind;
  final bool enabled;
  final ValueChanged<ScanSourceKind> onChanged;

  const ScanSourceToggle({
    super.key,
    required this.kind,
    required this.enabled,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    return SegmentedButton<ScanSourceKind>(
      segments: const [
        ButtonSegment(
          value: ScanSourceKind.sbomFile,
          icon: Icon(Icons.description_outlined, size: 16),
          label: Text('Fichier SBOM'),
        ),
        ButtonSegment(
          value: ScanSourceKind.image,
          icon: Icon(Icons.inventory_2_outlined, size: 16),
          label: Text('Image de conteneur'),
        ),
      ],
      selected: {kind},
      onSelectionChanged: enabled ? (s) => onChanged(s.first) : null,
      style: const ButtonStyle(
        visualDensity: VisualDensity.compact,
        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
      ),
    );
  }
}

/// Champ de référence d'image, avec sélecteurs pour une archive locale
/// (docker save / archive OCI) et, si [allowOciDir] est vrai, un répertoire
/// au format OCI layout. [allowOciDir] doit être à `false` pour les outils
/// qui ne savent pas lire un tel répertoire directement (osv-scanner, qui
/// n'accepte qu'une archive via `--archive`).
class ImageRefField extends StatelessWidget {
  final TextEditingController controller;
  final bool enabled;
  final bool allowOciDir;
  final VoidCallback onPickArchive;
  final VoidCallback? onPickOciDir;
  final ValueChanged<String>? onChanged;

  const ImageRefField({
    super.key,
    required this.controller,
    required this.enabled,
    required this.onPickArchive,
    this.allowOciDir = true,
    this.onPickOciDir,
    this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: TextField(
            controller: controller,
            enabled: enabled,
            decoration: InputDecoration(
              label: HelpLabel(
                'Image de conteneur',
                'Référence d\'une image à analyser directement, sans\n'
                    'passer par un fichier SBOM :\n'
                    '• Registre : nginx:latest, ghcr.io/org/app:tag\n'
                    '• Archive : ./image.tar(.gz) (docker save)\n'
                    '${allowOciDir ? '• Répertoire OCI layout : ./oci_dir/\n' : ''}'
                    'Un registre privé est résolu via la configuration\n'
                    'Docker locale (docker login), sans champ dédié ici.',
              ),
              hintText: allowOciDir
                  ? 'nginx:latest  •  ./image.tar(.gz)  •  ./oci_dir/'
                  : 'nginx:latest  •  ./image.tar(.gz)',
              border: const OutlineInputBorder(),
              isDense: true,
            ),
            style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
            onChanged: onChanged,
          ),
        ),
        const SizedBox(width: 8),
        IconButton.outlined(
          tooltip: 'Choisir une archive (.tar, .tar.gz, .tgz)',
          onPressed: enabled ? onPickArchive : null,
          icon: const Icon(Icons.archive_outlined, size: 18),
        ),
        if (allowOciDir) ...[
          const SizedBox(width: 4),
          IconButton.outlined(
            tooltip: 'Choisir un répertoire OCI layout',
            onPressed: enabled ? onPickOciDir : null,
            icon: const Icon(Icons.folder_outlined, size: 18),
          ),
        ],
      ],
    );
  }
}

// ─── Barre de filtre par date CVE ───────────────────────────────────────────

class DateFilterBar extends StatelessWidget {
  final CveDateFilter filter;
  final void Function(CveDateFilter)? onChanged;
  final void Function(CveDateFilter)? onPropagate;

  const DateFilterBar({
    super.key,
    required this.filter,
    this.onChanged,
    this.onPropagate,
  });

  Future<void> _pickDate(
    BuildContext context,
    DateTime? current,
    void Function(DateTime?) onPicked,
  ) async {
    final now = DateTime.now();
    final picked = await showDatePicker(
      context: context,
      initialDate: current ?? now,
      firstDate: DateTime(1999),
      lastDate: now,
    );
    if (picked != null) onPicked(picked);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerLowest,
        border: Border(
          bottom: BorderSide(color: theme.dividerColor, width: 0.5),
        ),
      ),
      child: Row(
        children: [
          const Icon(Icons.calendar_today_outlined, size: 14),
          const SizedBox(width: 6),
          const Text('Date CVE :', style: TextStyle(fontSize: 11)),
          const SizedBox(width: 6),
          // Champ de date (published / modified / latest)
          SegmentedButton<CveDateField>(
            segments: const [
              ButtonSegment(
                  value: CveDateField.published,
                  label: Text('Publication', style: TextStyle(fontSize: 10))),
              ButtonSegment(
                  value: CveDateField.modified,
                  label:
                      Text('Modification', style: TextStyle(fontSize: 10))),
              ButtonSegment(
                  value: CveDateField.latest,
                  label: Text('La plus récente',
                      style: TextStyle(fontSize: 10))),
            ],
            selected: {filter.field},
            onSelectionChanged: (s) =>
                onChanged?.call(filter.copyWith(field: s.first)),
            style: ButtonStyle(
              visualDensity: VisualDensity.compact,
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              textStyle:
                  WidgetStateProperty.all(const TextStyle(fontSize: 10)),
            ),
          ),
          const SizedBox(width: 10),
          // Après le
          DateChip(
            label: filter.after == null
                ? 'Après le…'
                : 'Après : ${_fmtDate(filter.after!)}',
            active: filter.after != null,
            onTap: () => _pickDate(context, filter.after,
                (d) => onChanged?.call(filter.copyWith(after: d))),
            onClear: filter.after == null
                ? null
                : () => onChanged?.call(filter.copyWith(after: null)),
          ),
          const SizedBox(width: 4),
          // Avant le
          DateChip(
            label: filter.before == null
                ? 'Avant le…'
                : 'Avant : ${_fmtDate(filter.before!)}',
            active: filter.before != null,
            onTap: () => _pickDate(context, filter.before,
                (d) => onChanged?.call(filter.copyWith(before: d))),
            onClear: filter.before == null
                ? null
                : () => onChanged?.call(filter.copyWith(before: null)),
          ),
          const SizedBox(width: 10),
          // Inclure CVE sans date
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(
                width: 16,
                height: 16,
                child: Checkbox(
                  value: filter.includeUndated,
                  onChanged: (v) => onChanged
                      ?.call(filter.copyWith(includeUndated: v ?? false)),
                  materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  visualDensity: VisualDensity.compact,
                ),
              ),
              const SizedBox(width: 4),
              const Text('Sans date', style: TextStyle(fontSize: 11)),
            ],
          ),
          const Spacer(),
          // Bouton Propager
          if (onPropagate != null)
            TextButton.icon(
              icon: const Icon(Icons.sync_alt, size: 14),
              label: const Text('Propager aux autres onglets',
                  style: TextStyle(fontSize: 11)),
              style: TextButton.styleFrom(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              onPressed: () => onPropagate!(filter),
            ),
        ],
      ),
    );
  }

  static String _fmtDate(DateTime d) =>
      '${d.year.toString().padLeft(4, '0')}-'
      '${d.month.toString().padLeft(2, '0')}-'
      '${d.day.toString().padLeft(2, '0')}';
}

class DateChip extends StatelessWidget {
  final String label;
  final bool active;
  final VoidCallback onTap;
  final VoidCallback? onClear;

  const DateChip({
    super.key,
    required this.label,
    required this.active,
    required this.onTap,
    this.onClear,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: active
              ? theme.colorScheme.primaryContainer
              : theme.colorScheme.surfaceContainerHigh,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: active
                ? theme.colorScheme.primary
                : theme.colorScheme.outline,
            width: 0.8,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              label,
              style: TextStyle(
                fontSize: 11,
                color: active
                    ? theme.colorScheme.onPrimaryContainer
                    : theme.colorScheme.onSurfaceVariant,
              ),
            ),
            if (onClear != null) ...[
              const SizedBox(width: 4),
              InkWell(
                onTap: onClear,
                child: Icon(Icons.close,
                    size: 12, color: theme.colorScheme.onPrimaryContainer),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// ─── Tableau de vulnérabilités partagé ─────────────────────────────────────
//
// grype/trivy/osv-scanner exposent chacun un modèle de vulnérabilité distinct
// (GrypeVuln/TrivyVuln/OsvVuln, conservés séparés car consommés avec leur
// propre type par DashboardPanel et ResultsPanel) mais partagent 7 des 8
// champs. VulnRow capture ce socle commun pour que le tableau — tri, filtre,
// recherche, export CSV, rendu de la liste — n'existe qu'une seule fois.

abstract class VulnRow {
  String get id;
  String get severity;
  String get packageName;
  String get installedVersion;
  String get fixedVersion;
  DateTime? get publishedDate;
  DateTime? get modifiedDate;

  /// Nombre d'emplacements distincts fusionnés dans cette entrée par
  /// [dedupeVulns] (1 = pas de fusion). Une même bibliothèque peut être
  /// détectée deux fois dans une image de conteneur — un jar autonome ET
  /// une copie « shadée » (reshadée/embarquée) dans un autre jar, par
  /// exemple — avec exactement la même sévérité/CVE/paquet/version : ces
  /// occurrences sont fusionnées en une seule ligne affichée, avec ce
  /// compteur, plutôt que montrées comme des doublons visuellement
  /// indiscernables.
  int get occurrenceCount;
}

/// Fusionne les entrées de [vulns] qui partagent (sévérité, identifiant,
/// paquet, version installée) — un même composant vulnérable détecté à
/// plusieurs emplacements distincts de l'image/du SBOM analysé — en une
/// seule entrée par groupe, dont [VulnRow.occurrenceCount] porte le nombre
/// d'occurrences fusionnées. [withOccurrenceCount] reconstruit une instance
/// de [T] à partir de la première occurrence rencontrée et du compteur final
/// (chaque modèle `XxxVuln` fournit sa propre méthode `withOccurrenceCount`,
/// le type concret n'étant pas connu ici). L'ordre de première apparition
/// est préservé.
///
/// Ne s'applique qu'aux vues dérivées (tableau, bannière, exports) : la vue
/// JSON brut reste fidèle à la sortie complète et non déduplifiée de l'outil.
List<T> dedupeVulns<T extends VulnRow>(
  List<T> vulns,
  T Function(T first, int count) withOccurrenceCount,
) {
  final merged = <String, ({T first, int count})>{};
  for (final v in vulns) {
    final key = [v.severity, v.id, v.packageName, v.installedVersion].join('\u0000');
    final existing = merged[key];
    merged[key] =
        existing == null ? (first: v, count: 1) : (first: existing.first, count: existing.count + 1);
  }
  return [for (final e in merged.values) withOccurrenceCount(e.first, e.count)];
}

enum VulnSortCol { severity, cveId, package, kev, epss }

class VulnTableView<T extends VulnRow> extends StatefulWidget {
  final List<T> vulns;
  final bool parseFailed;

  /// Message affiché quand [parseFailed] est vrai, ex. "Sortie grype illisible…".
  final String parseFailedMessage;

  /// Valeurs de sévérité telles qu'elles apparaissent dans les données de cet
  /// outil (la casse diffère selon l'outil : "Critical" vs "CRITICAL").
  final List<String> severityOrder;

  /// Nom de l'outil tel qu'affiché dans les rapports exportés (ex. "Grype",
  /// "OSV-Scanner", "Trivy").
  final String toolName;

  final String csvDialogTitle;
  final String csvFileName;
  final String csvHeader;
  final List<String> Function(T) csvRow;

  /// En-tête de la colonne optionnelle affichée en fin de ligne (ex. "TYPE",
  /// "ÉCOSYSTÈME"). Null si l'outil n'a pas de champ de classification.
  final String? extraColumnHeader;
  final String Function(T)? extraOf;

  /// Texte descriptif optionnel affiché en 2e ligne (ex. le titre de la CVE
  /// pour trivy). Null si l'outil n'a pas ce genre de champ.
  final String Function(T)? descriptionOf;

  final CveDateFilter dateFilter;
  final void Function(CveDateFilter)? onDateFilterChanged;
  final void Function(CveDateFilter)? onPropagate;

  /// Signaux d'exploitabilité / exploitation active par CVE (id normalisé via
  /// [normalizeCveId]). Vide = enrichissement non exécuté : les colonnes KEV /
  /// EPSS / PoC et le filtre associé sont alors masqués.
  final Map<String, ExploitInfo> exploitById;

  /// Vrai tant que l'enrichissement en ligne est en cours (bandeau d'attente).
  final bool enrichPending;

  /// Cible analysée (« SBOM x.cdx.json », « image nginx:latest ») — affichée
  /// dans l'en-tête du rapport exporté. `null` = non renseignée.
  final String? scanTarget;

  /// État du basculement « enrichir en ligne » (CISA KEV / EPSS / poc-in-github).
  final bool enrichOnline;

  /// Bascule l'enrichissement en ligne — l'appelant persiste le choix et
  /// relance l'enrichissement. Null = pas de bouton affiché.
  final ValueChanged<bool>? onEnrichOnlineChanged;

  const VulnTableView({
    super.key,
    required this.vulns,
    this.parseFailed = false,
    required this.parseFailedMessage,
    required this.severityOrder,
    required this.toolName,
    required this.csvDialogTitle,
    required this.csvFileName,
    required this.csvHeader,
    required this.csvRow,
    this.extraColumnHeader,
    this.extraOf,
    this.descriptionOf,
    this.dateFilter = CveDateFilter.empty,
    this.onDateFilterChanged,
    this.onPropagate,
    this.exploitById = const {},
    this.scanTarget,
    this.enrichPending = false,
    this.enrichOnline = true,
    this.onEnrichOnlineChanged,
  });

  @override
  State<VulnTableView<T>> createState() => _VulnTableViewState<T>();
}

class _VulnTableViewState<T extends VulnRow> extends State<VulnTableView<T>> {
  Set<String> _activeFilters = {};
  final _searchCtrl = TextEditingController();
  String _searchTerm = '';
  bool _kevOnly = false;
  VulnSortCol _sortCol = VulnSortCol.severity;
  bool _sortAsc = true; // true = ascendant par _sevOrd (Critical=0 en premier)

  final Set<String> _expanded = {};

  bool get _hasExploit => widget.exploitById.isNotEmpty;

  ExploitInfo _ex(T v) =>
      widget.exploitById[normalizeCveId(v.id)] ?? ExploitInfo.empty;

  /// Détail (un seul scanner : celui de cet onglet) pour la ligne dépliée.
  CveDetail _detailFor(T v) => CveDetail(
        id: v.id,
        views: [
          ScannerCveView(
            scanner: widget.toolName,
            severity: v.severity,
            packageName: v.packageName,
            installedVersion: v.installedVersion,
            fixedVersion: v.fixedVersion,
            extra: widget.descriptionOf?.call(v) ??
                widget.extraOf?.call(v) ??
                '',
            publishedDate: v.publishedDate,
            modifiedDate: v.modifiedDate,
          ),
        ],
        exploit: _ex(v),
      );

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  static int _sevOrd(String s) => switch (s.toLowerCase()) {
        'critical' => 0,
        'high' => 1,
        'medium' => 2,
        'low' => 3,
        _ => 4,
      };

  void _onSort(VulnSortCol col) => setState(() {
        if (_sortCol == col) {
          _sortAsc = !_sortAsc;
        } else {
          _sortCol = col;
          // Sévérité/KEV/EPSS : le plus « à risque » d'abord au 1er clic.
          _sortAsc = col == VulnSortCol.severity;
        }
      });

  List<T> get _filtered {
    var list = _activeFilters.isEmpty
        ? widget.vulns
        : widget.vulns.where((v) => _activeFilters.contains(v.severity)).toList();
    if (_kevOnly) {
      list = list.where((v) => _ex(v).inKev).toList();
    }
    if (_searchTerm.isNotEmpty) {
      final q = _searchTerm.toLowerCase();
      list = list
          .where((v) =>
              v.packageName.toLowerCase().contains(q) ||
              v.id.toLowerCase().contains(q))
          .toList();
    }
    if (widget.dateFilter.hasConstraints) {
      list = list
          .where((v) => widget.dateFilter.matches(v.publishedDate, v.modifiedDate))
          .toList();
    }
    list = List.of(list)
      ..sort((a, b) {
        final cmp = switch (_sortCol) {
          VulnSortCol.severity => _sevOrd(a.severity).compareTo(_sevOrd(b.severity)),
          VulnSortCol.cveId    => a.id.compareTo(b.id),
          VulnSortCol.package  => a.packageName.compareTo(b.packageName),
          // KEV puis (départage) EPSS ; EPSS décroissant.
          VulnSortCol.kev => _riskCmp(a, b),
          VulnSortCol.epss => -((_ex(a).epssScore ?? -1)
              .compareTo(_ex(b).epssScore ?? -1)),
        };
        return _sortAsc ? cmp : -cmp;
      });
    return list;
  }

  int _riskCmp(T a, T b) {
    final ea = _ex(a), eb = _ex(b);
    if (ea.inKev != eb.inKev) return ea.inKev ? -1 : 1;
    return -((ea.epssScore ?? -1).compareTo(eb.epssScore ?? -1));
  }

  static const _exploitHeaders = ['KEV', 'EPSS', 'PoC'];

  Widget _exploitBadges(ExploitInfo e) {
    Widget pill(String text, Color color, {IconData? icon}) => Container(
          padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
          decoration: BoxDecoration(
            color: color.withValues(alpha: 0.14),
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: color.withValues(alpha: 0.5), width: 0.6),
          ),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            if (icon != null) ...[
              Icon(icon, size: 10, color: color),
              const SizedBox(width: 2),
            ],
            Text(text,
                style: TextStyle(
                    fontSize: 10, fontWeight: FontWeight.w600, color: color)),
          ]),
        );

    final chips = <Widget>[];
    if (e.inKev) {
      chips.add(Tooltip(
        message: 'CISA KEV — exploitée activement dans la nature'
            '${e.kevDateAdded != null ? ' (ajoutée le '
                '${e.kevDateAdded!.toIso8601String().substring(0, 10)})' : ''}'
            '${e.kevRansomware ? ' · usage par rançongiciel' : ''}',
        child: pill('KEV', Colors.red, icon: Icons.local_fire_department),
      ));
    }
    if (e.epssScore != null) {
      final pct = ((e.epssPercentile ?? 0) * 100).round();
      chips.add(Tooltip(
        message: 'EPSS — probabilité d\'exploitation à 30 jours '
            '(percentile $pct)',
        child: pill('EPSS ${e.epssScore!.toStringAsFixed(2)}',
            e.epssScore! >= 0.10 ? Colors.deepOrange : Colors.blueGrey),
      ));
    }
    if (e.pocKnown) {
      chips.add(Tooltip(
        message: e.pocCount > 0
            ? '${e.pocCount} dépôt(s) PoC public(s) recensé(s)'
            : 'Maturité de l\'exploit : ${e.exploitMaturity ?? "PoC"}',
        child: pill(e.pocCount > 0 ? 'PoC ${e.pocCount}' : 'PoC',
            Colors.purple, icon: Icons.code),
      ));
    }
    if (e.cvssExploitabilityScore != null) {
      chips.add(Tooltip(
        message: 'Sous-score d\'exploitabilité CVSS (AV/AC/PR/UI)'
            '${e.exploitMaturity != null ? ' · maturité ${e.exploitMaturity}' : ''}',
        child: pill('expl. ${e.cvssExploitabilityScore!.toStringAsFixed(1)}',
            Colors.teal),
      ));
    }
    if (chips.isEmpty) {
      return const Padding(
        padding: EdgeInsets.only(top: 2),
        child: Text('aucun signal d\'exploitation',
            style: TextStyle(fontSize: 10, color: Colors.grey)),
      );
    }
    return Padding(
      padding: const EdgeInsets.only(top: 3),
      child: Wrap(spacing: 4, runSpacing: 2, children: chips),
    );
  }

  List<String> _exploitCells(T v) {
    final e = _ex(v);
    final epss = e.epssScore == null
        ? '—'
        : '${e.epssScore!.toStringAsFixed(2)} '
            '(p${((e.epssPercentile ?? 0) * 100).round()})';
    final poc = e.pocCount > 0
        ? '${e.pocCount}'
        : (e.pocKnown ? 'oui' : '—');
    return [e.inKev ? 'oui' : '—', epss, poc];
  }

  Future<void> _exportCsv(BuildContext context) async {
    final rows = _filtered;
    final buf = StringBuffer();
    buf.writeln(_hasExploit
        ? '${widget.csvHeader},${_exploitHeaders.join(',')}'
        : widget.csvHeader);
    for (final v in rows) {
      final cells = [
        ...widget.csvRow(v),
        if (_hasExploit) ..._exploitCells(v),
      ];
      buf.writeln(cells.map(csvEscape).join(','));
    }
    final path = await FilePicker.saveFile(
      dialogTitle: widget.csvDialogTitle,
      fileName: widget.csvFileName,
      type: FileType.custom,
      allowedExtensions: ['csv'],
    );
    if (path == null || !context.mounted) return;
    await File(path).writeAsString(buf.toString());
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text('${rows.length} vulnérabilité(s) exportée(s) → $path'),
        duration: const Duration(seconds: 4),
      ));
    }
  }

  Future<void> _exportAsciiDoc(BuildContext context) async {
    final rows = _filtered;
    final path = await FilePicker.saveFile(
      dialogTitle: 'Exporter le rapport ${widget.toolName} (AsciiDoc + PDF)',
      fileName: widget.csvFileName.replaceAll(RegExp(r'\.csv$'), '.adoc'),
      type: FileType.custom,
      allowedExtensions: ['adoc'],
    );
    if (path == null || !context.mounted) return;

    final counts = <String, int>{};
    for (final v in rows) {
      counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    }
    final columns = [
      ...widget.csvHeader.split(','),
      if (_hasExploit) ..._exploitHeaders,
    ];
    final kevCount = _hasExploit
        ? rows.where((v) => _ex(v).inKev).length
        : 0;

    int cnt(String key) => widget.severityOrder
        .where((s) => s.toLowerCase() == key)
        .fold(0, (n, s) => n + (counts[s] ?? 0));
    final crit = cnt('critical');
    final high = cnt('high');

    final buf = StringBuffer();
    buf.writeln('= Rapport de vulnérabilités: ${widget.toolName}');
    buf.writeln('SBOM Generator $kGuiVersion');
    buf.writeln(':doctype: article');
    buf.writeln(':title-page:');
    buf.writeln(':toc:');
    buf.writeln(':toc-title: Sommaire');
    buf.writeln(':toclevels: 2');
    buf.writeln(':revdate: ${pdfFrenchDate(DateTime.now())}');
    buf.writeln(':icons: font');
    buf.writeln();
    buf.writeln('== Résumé exécutif');
    buf.writeln();
    if (widget.scanTarget != null) {
      buf.writeln('*Cible analysée* : ${adocEscape(widget.scanTarget!)} +');
    }
    buf.writeln('*Scanner* : ${widget.toolName} — *${rows.length}* '
        'vulnérabilité(s)'
        '${widget.dateFilter.hasConstraints ? ' après filtre de date' : ''}');
    buf.writeln();
    final svg = buildSeverityBarSvg(counts);
    if (svg != null) {
      buf.writeln(svgImageMacro(svg));
      buf.writeln();
    }
    buf.writeln('[cols="^1,^1,^1,^1",frame=none,grid=cols]');
    buf.writeln('|===');
    buf.writeln('h| Critiques h| Élevées h| CISA KEV h| Total');
    buf.writeln('| [.${crit > 0 ? 'h1-num-alert' : 'h1-num'}]*$crit* '
        '| [.h1-num]*$high* '
        '| [.${kevCount > 0 ? 'h1-num-alert' : 'h1-num'}]*$kevCount* '
        '| [.h1-num]*${rows.length}*');
    buf.writeln('|===');
    buf.writeln();
    if (widget.dateFilter.hasConstraints) {
      buf.writeln('NOTE: Filtre de date appliqué — '
          '${_dateFilterSummary(widget.dateFilter)}.');
      buf.writeln();
    }
    buf.writeln('[cols="<2,>1",options="header"]');
    buf.writeln('|===');
    buf.writeln('| Sévérité | Nombre');
    for (final s in widget.severityOrder) {
      if (counts.containsKey(s)) {
        buf.writeln('| ${pdfSeverityBadge(s)} | ${counts[s]}');
      }
    }
    buf.writeln('|===');
    buf.writeln();

    // Versions détectées au moment de l'export (pas au moment du scan) —
    // toujours à jour même si l'outil a été mis à jour depuis.
    buf.writeln('== Outils');
    buf.writeln();
    buf.writeln('[cols="<3,<1",options="header"]');
    buf.writeln('|===');
    buf.writeln('| Outil | Version');
    buf.writeln(pdfToolVersionRow('sbom_generator_gui', kGuiVersion));
    buf.writeln(
        pdfToolVersionRow(widget.toolName, await _toolVersionFor(widget.toolName)));
    buf.writeln('|===');
    buf.writeln();

    buf.writeln('== Détail');
    buf.writeln();
    buf.writeln(
        '[cols="${List.filled(columns.length, "<1").join(',')}",options="header"]');
    buf.writeln('|===');
    buf.writeln('| ${columns.join(' | ')}');
    buf.writeln();
    for (final v in rows) {
      final cells = [
        ...widget.csvRow(v),
        if (_hasExploit) ..._exploitCells(v),
      ];
      final formatted = [
        pdfSeverityBadge(cells.first),
        ...cells.skip(1).map(adocEscape),
      ];
      buf.writeln('| ${formatted.join(' | ')}');
    }
    buf.writeln('|===');
    buf.writeln();

    await File(path).writeAsString(buf.toString());
    if (!context.mounted) return;

    final pdfPath = path.endsWith('.adoc')
        ? '${path.substring(0, path.length - 5)}.pdf'
        : '$path.pdf';

    try {
      final result = await runAsciidoctorPdf(path, pdfPath);
      if (!context.mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(result.exitCode == 0
            ? '${rows.length} vulnérabilité(s) exportée(s) → $path et $pdfPath'
            : '${rows.length} vulnérabilité(s) exportée(s) → $path '
                '(échec conversion PDF, code ${result.exitCode})'),
        duration: const Duration(seconds: 5),
      ));
    } catch (_) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text('${rows.length} vulnérabilité(s) exportée(s) → $path '
            '(asciidoctor-pdf introuvable, PDF non généré)'),
        duration: const Duration(seconds: 5),
      ));
    }
  }

  @override
  Widget build(BuildContext context) {
    if (widget.parseFailed) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline, size: 56, color: Colors.red),
            const SizedBox(height: 12),
            Text(widget.parseFailedMessage,
                style: const TextStyle(color: Colors.red, fontSize: 15)),
          ],
        ),
      );
    }
    if (widget.vulns.isEmpty) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.verified_user_outlined, size: 56, color: Colors.green),
            SizedBox(height: 12),
            Text('Aucune vulnérabilité détectée',
                style: TextStyle(color: Colors.green, fontSize: 15)),
          ],
        ),
      );
    }

    final counts = <String, int>{};
    for (final v in widget.vulns) {
      counts[v.severity] = (counts[v.severity] ?? 0) + 1;
    }
    final filtered = _filtered;

    return Column(
      children: [
        // ── Filtres + recherche ──
        Container(
          color: Theme.of(context).colorScheme.surfaceContainerLow,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          child: Row(
            children: [
              const Text('Filtre :', style: TextStyle(fontSize: 11)),
              const SizedBox(width: 8),
              Expanded(
                child: Wrap(
                  spacing: 6,
                  runSpacing: 2,
                  children: [
                    for (final s in widget.severityOrder)
                      if (counts.containsKey(s))
                        FilterChip(
                          label: Text('$s (${counts[s]})'),
                          labelStyle: TextStyle(
                              fontSize: 11,
                              color: _activeFilters.contains(s)
                                  ? Colors.white
                                  : severityFg(s)),
                          backgroundColor: severityBg(s),
                          selectedColor: severityFg(s),
                          selected: _activeFilters.contains(s),
                          onSelected: (v) => setState(() {
                            if (v) {
                              _activeFilters.add(s);
                            } else {
                              _activeFilters.remove(s);
                            }
                          }),
                        ),
                    if (_hasExploit &&
                        (_kevOnly || widget.vulns.any((v) => _ex(v).inKev)))
                      FilterChip(
                        avatar: Icon(Icons.local_fire_department,
                            size: 14,
                            color: _kevOnly ? Colors.white : Colors.red),
                        label: Text(
                            'CISA KEV '
                            '(${widget.vulns.where((v) => _ex(v).inKev).length})',
                            style: const TextStyle(fontSize: 11)),
                        labelStyle: TextStyle(
                            fontSize: 11,
                            color: _kevOnly ? Colors.white : Colors.red),
                        backgroundColor: Colors.red.withValues(alpha: 0.12),
                        selectedColor: Colors.red,
                        selected: _kevOnly,
                        onSelected: (v) => setState(() => _kevOnly = v),
                      ),
                    if (_activeFilters.isNotEmpty || _kevOnly)
                      ActionChip(
                        label: const Text('Tout voir',
                            style: TextStyle(fontSize: 11)),
                        onPressed: () => setState(() {
                          _activeFilters = {};
                          _kevOnly = false;
                        }),
                      ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              SizedBox(
                width: 200,
                child: TextField(
                  controller: _searchCtrl,
                  onChanged: (v) => setState(() => _searchTerm = v),
                  decoration: InputDecoration(
                    hintText: 'Paquet ou CVE…',
                    isDense: true,
                    prefixIcon: const Icon(Icons.search, size: 16),
                    suffixIcon: _searchTerm.isNotEmpty
                        ? IconButton(
                            icon: const Icon(Icons.clear, size: 14),
                            onPressed: () {
                              _searchCtrl.clear();
                              setState(() => _searchTerm = '');
                            },
                            padding: EdgeInsets.zero,
                          )
                        : null,
                    contentPadding:
                        const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
                    border: const OutlineInputBorder(),
                  ),
                  style: const TextStyle(fontSize: 12),
                ),
              ),
              const SizedBox(width: 4),
              if (widget.onEnrichOnlineChanged != null)
                IconButton(
                  icon: Icon(
                    widget.enrichOnline
                        ? Icons.cloud_done_outlined
                        : Icons.cloud_off_outlined,
                    size: 18,
                    color: widget.enrichOnline ? null : Colors.grey,
                  ),
                  tooltip: widget.enrichOnline
                      ? 'Enrichissement en ligne actif (CISA KEV / EPSS / '
                          'poc-in-github) — cliquer pour passer hors-ligne'
                      : 'Enrichissement hors-ligne (Grype + cache local '
                          'seulement) — cliquer pour réactiver le réseau',
                  onPressed: () =>
                      widget.onEnrichOnlineChanged!(!widget.enrichOnline),
                ),
              IconButton(
                icon: const Icon(Icons.download_outlined, size: 18),
                tooltip: 'Exporter CSV',
                onPressed:
                    _filtered.isEmpty ? null : () => _exportCsv(context),
              ),
              IconButton(
                icon: const Icon(Icons.picture_as_pdf_outlined, size: 18),
                tooltip: 'Exporter en AsciiDoc + PDF',
                onPressed:
                    _filtered.isEmpty ? null : () => _exportAsciiDoc(context),
              ),
            ],
          ),
        ),

        // ── Filtre date ──
        DateFilterBar(
          filter: widget.dateFilter,
          onChanged: widget.onDateFilterChanged,
          onPropagate: widget.onPropagate,
        ),

        // ── En-têtes de tri ──
        Container(
          color: Theme.of(context).colorScheme.surfaceContainerHigh,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 3),
          child: Row(
            children: [
              SortHeader('SÉVÉRITÉ', _sortCol == VulnSortCol.severity, _sortAsc,
                  () => _onSort(VulnSortCol.severity)),
              const SizedBox(width: 16),
              SortHeader('CVE / ID', _sortCol == VulnSortCol.cveId, _sortAsc,
                  () => _onSort(VulnSortCol.cveId)),
              const SizedBox(width: 16),
              SortHeader('PAQUET', _sortCol == VulnSortCol.package, _sortAsc,
                  () => _onSort(VulnSortCol.package)),
              if (_hasExploit) ...[
                const SizedBox(width: 16),
                SortHeader('KEV', _sortCol == VulnSortCol.kev, _sortAsc,
                    () => _onSort(VulnSortCol.kev)),
                const SizedBox(width: 16),
                SortHeader('EPSS', _sortCol == VulnSortCol.epss, _sortAsc,
                    () => _onSort(VulnSortCol.epss)),
              ],
              if (widget.extraColumnHeader != null) ...[
                const Spacer(),
                Text(widget.extraColumnHeader!,
                    style: const TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                        color: Colors.grey)),
              ],
            ],
          ),
        ),
        if (widget.enrichPending)
          Container(
            width: double.infinity,
            color: Theme.of(context).colorScheme.surfaceContainerLow,
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 3),
            child: const Text(
              'Enrichissement en ligne (CISA KEV / EPSS / PoC) en cours…',
              style: TextStyle(fontSize: 10, color: Colors.grey),
            ),
          ),

        // ── Liste ──
        Expanded(
          child: filtered.isEmpty
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        _searchTerm.isNotEmpty
                            ? Icons.search_off
                            : Icons.filter_alt_off_outlined,
                        size: 40,
                        color: Colors.grey,
                      ),
                      const SizedBox(height: 8),
                      Text(
                        _searchTerm.isNotEmpty
                            ? 'Aucun résultat pour "$_searchTerm"'
                            : 'Aucun résultat pour ${_activeFilters.join(', ')}',
                        style: const TextStyle(color: Colors.grey),
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  itemCount: filtered.length,
                  itemBuilder: (context, i) {
                    final v = filtered[i];
                    final fg = severityFg(v.severity);
                    final bg = severityBg(v.severity);
                    final description = widget.descriptionOf?.call(v) ?? '';
                    final key = '${v.id} ${v.packageName}'
                        ' ${v.installedVersion}';
                    final isOpen = _expanded.contains(key);
                    final tile = ListTile(
                      dense: true,
                      onTap: () => setState(() =>
                          isOpen ? _expanded.remove(key) : _expanded.add(key)),
                      leading: Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: bg,
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: fg, width: 0.8),
                        ),
                        child: Text(
                          v.severity.toUpperCase(),
                          style: TextStyle(
                              fontSize: 10,
                              fontWeight: FontWeight.bold,
                              color: fg),
                        ),
                      ),
                      title: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(
                            v.id,
                            style: const TextStyle(
                                fontFamily: 'monospace',
                                fontSize: 13,
                                fontWeight: FontWeight.w600),
                          ),
                          if (v.occurrenceCount > 1) ...[
                            const SizedBox(width: 6),
                            Tooltip(
                              message:
                                  'Ce composant est présent à ${v.occurrenceCount} '
                                  'emplacements distincts de l\'image/du SBOM '
                                  '(ex. une bibliothèque autonome et une copie '
                                  'embarquée dans un autre paquet) — la même '
                                  'vulnérabilité y a été fusionnée en une seule '
                                  'ligne.',
                              child: Container(
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 5, vertical: 1),
                                decoration: BoxDecoration(
                                  color: Theme.of(context)
                                      .colorScheme
                                      .surfaceContainerHighest,
                                  borderRadius: BorderRadius.circular(8),
                                ),
                                child: Text(
                                  '×${v.occurrenceCount}',
                                  style: TextStyle(
                                    fontSize: 10,
                                    fontWeight: FontWeight.bold,
                                    color: Theme.of(context)
                                        .colorScheme
                                        .onSurfaceVariant,
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ],
                      ),
                      subtitle: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Text(
                                v.packageName,
                                style: const TextStyle(
                                    fontFamily: 'monospace', fontSize: 11),
                              ),
                              Text(' ${v.installedVersion}',
                                  style: const TextStyle(
                                      fontSize: 11, color: Colors.grey)),
                              if (v.fixedVersion.isNotEmpty) ...[
                                const Text(' → ',
                                    style: TextStyle(
                                        fontSize: 11, color: Colors.green)),
                                Text(v.fixedVersion,
                                    style: const TextStyle(
                                        fontSize: 11, color: Colors.green)),
                              ],
                            ],
                          ),
                          if (description.isNotEmpty)
                            Text(
                              description,
                              style: const TextStyle(
                                  fontSize: 11, color: Colors.grey),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          if (_hasExploit) _exploitBadges(_ex(v)),
                        ],
                      ),
                      isThreeLine: description.isNotEmpty || _hasExploit,
                      trailing: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          if (widget.extraOf != null)
                            Text(
                              widget.extraOf!(v),
                              style: const TextStyle(
                                  fontSize: 11, color: Colors.grey),
                            ),
                          Icon(
                              isOpen
                                  ? Icons.expand_less
                                  : Icons.expand_more,
                              size: 18,
                              color: Colors.grey[500]),
                        ],
                      ),
                    );
                    return Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        tile,
                        if (isOpen)
                          CveDetailPanel(detail: _detailFor(v)),
                      ],
                    );
                  },
                ),
        ),
      ],
    );
  }
}
