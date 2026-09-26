// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for French (`fr`).
class AppLocalizationsFr extends AppLocalizations {
  AppLocalizationsFr([String locale = 'fr']) : super(locale);

  @override
  String get languageMenuTooltip => 'Langue de l\'interface';

  @override
  String get languageSystem => 'Système';

  @override
  String get languageFrench => 'Français';

  @override
  String get languageEnglish => 'English';

  @override
  String get commonCopy => 'Copier';

  @override
  String get commonClose => 'Fermer';

  @override
  String get commonStop => 'Stop';

  @override
  String get commonAnalyze => 'Analyser';

  @override
  String get commonBrowse => 'Choisir';

  @override
  String commonPickFiltered(String filter) {
    return 'Type filtré ($filter)';
  }

  @override
  String get commonPickAllFiles => 'Tous les fichiers';

  @override
  String commonFileNotFound(String path) {
    return 'Fichier introuvable : $path';
  }

  @override
  String get commonNone => '(aucun)';

  @override
  String get commonNoneFeminine => '(aucune)';

  @override
  String get commonPlatform => 'Plateforme';

  @override
  String get commonPlatformHint => 'linux/amd64, linux/arm64…';

  @override
  String get commonSbomFileHint => 'chemin/vers/sbom.cdx.json';

  @override
  String get jsonViewEmpty => 'Pas de sortie JSON.';

  @override
  String get jsonViewCopyTooltip => 'Copier le JSON';

  @override
  String get jsonViewCopied => 'JSON copié';

  @override
  String get scanSourceSbom => 'Fichier SBOM';

  @override
  String get scanSourceImage => 'Image de conteneur';

  @override
  String scanSourceImageHelp(String ociDirLine) {
    return 'Référence d\'une image à analyser directement, sans\npasser par un fichier SBOM :\n• Registre : nginx:latest, ghcr.io/org/app:tag\n• Archive : ./image.tar(.gz) (docker save)\n${ociDirLine}Un registre privé est résolu via la configuration\nDocker locale (docker login), sans champ dédié ici.';
  }

  @override
  String get scanSourceImageHelpOciDir =>
      '• Répertoire OCI layout : ./oci_dir/\n';

  @override
  String get scanSourcePickArchive =>
      'Choisir une archive (.tar, .tar.gz, .tgz)';

  @override
  String get scanSourcePickOciDir => 'Choisir un répertoire OCI layout';

  @override
  String get scanSourceMissingImage =>
      'Veuillez indiquer une image à analyser.';

  @override
  String get scanSourceMissingSbom => 'Veuillez sélectionner un fichier SBOM.';

  @override
  String get scanPickSbomTitle => 'Choisir un fichier SBOM';

  @override
  String get scanPickImageArchiveTitle =>
      'Choisir une archive image (docker save / OCI)';

  @override
  String scanUnreadableOutput(String tool, String error) {
    return 'Sortie $tool illisible (JSON invalide) : $error';
  }

  @override
  String scanUnreadableOutputShort(String tool) {
    return 'Sortie $tool illisible : voir le message d\'erreur ci-dessus';
  }

  @override
  String get scanNoVulnerabilities => 'Aucune vulnérabilité détectée';

  @override
  String scanSummary(int count, String details) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count vulnérabilités : $details',
      one: '1 vulnérabilité : $details',
    );
    return '$_temp0';
  }

  @override
  String scanExportCsvDialog(String tool) {
    return 'Exporter les vulnérabilités $tool';
  }

  @override
  String get layerScanCheckbox => 'Par couche';

  @override
  String get layerScanHelp =>
      'Attribue chaque vulnérabilité à la couche de l\'image qui\napporte le paquet vulnérable (SBOM par couche générés par\nsbom-generator --per-layer, via syft).\n• Rattachement : un seul scan de l\'image, chaque CVE\n  rattachée à la couche d\'origine de son paquet — CVE de\n  l\'image finale uniquement.\n• Chaque couche : le SBOM de chaque couche est scanné —\n  inclut les CVE d\'une version remplacée plus haut dans la\n  pile (avec le calcul Rootfs).\n• Métadonnées / Rootfs : calcul des couches (--layer-mode).';

  @override
  String get layerScanAttribute => 'Rattachement';

  @override
  String get layerScanAttributeTooltip =>
      'Un scan de l\'image, CVE rattachées à la couche d\'origine du paquet';

  @override
  String get layerScanEach => 'Chaque couche';

  @override
  String get layerScanEachTooltip => 'Un scan par SBOM de couche';

  @override
  String get layerModeMetadata => 'Métadonnées';

  @override
  String get layerModeMetadataTooltip =>
      'Couche d\'origine indiquée par syft — ajouts';

  @override
  String get layerModeRootfs => 'Rootfs';

  @override
  String get layerModeRootfsTooltip =>
      'Réanalyse après chaque couche — ajouts, modifications, suppressions';

  @override
  String get cliCommandButton => 'CLI Commande';

  @override
  String get cliCommandDialogTitle => 'Ligne de commande';

  @override
  String get cliCommandCopied => 'Commande copiée';

  @override
  String get cliCommandExecuted => 'Commande exécutée par l\'onglet';

  @override
  String get cliCommandExecutedLayered =>
      'Commandes exécutées par l\'onglet (analyse par couche)';

  @override
  String get cliCommandEquivalent => 'Équivalent sbom-generator scan';

  @override
  String cliCommandLayerDirNote(String dir) {
    return 'Le jeu de SBOM par couche est généré dans un répertoire temporaire (ici $dir).';
  }

  @override
  String get cliCommandImageNote =>
      'Avec --image, sbom-generator scanne le SBOM CycloneDX généré (syft), pas l\'image directement.';

  @override
  String cliCommandNotCarried(String options) {
    return 'Non transposable : $options.';
  }

  @override
  String get cliOptionPlatform => 'plateforme';

  @override
  String get vulnTableFilter => 'Filtre :';

  @override
  String get vulnTableShowAll => 'Tout voir';

  @override
  String vulnTableKevChip(int count) {
    return 'CISA KEV ($count)';
  }

  @override
  String get vulnTableSearchHint => 'Paquet ou CVE…';

  @override
  String get vulnTableEnrichOnline =>
      'Enrichissement en ligne actif (CISA KEV / EPSS / poc-in-github) — cliquer pour passer hors-ligne';

  @override
  String get vulnTableEnrichOffline =>
      'Enrichissement hors-ligne (Grype + cache local seulement) — cliquer pour réactiver le réseau';

  @override
  String get vulnTableExportCsv => 'Exporter CSV';

  @override
  String get vulnTableExportPdf => 'Exporter en AsciiDoc + PDF';

  @override
  String vulnTableExportPdfDialog(String tool) {
    return 'Exporter le rapport $tool (AsciiDoc + PDF)';
  }

  @override
  String vulnTableExported(int count, String path) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count vulnérabilités exportées → $path',
      one: '1 vulnérabilité exportée → $path',
    );
    return '$_temp0';
  }

  @override
  String vulnTableExportedPdf(int count, String path, String pdf) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count vulnérabilités exportées → $path et $pdf',
      one: '1 vulnérabilité exportée → $path et $pdf',
    );
    return '$_temp0';
  }

  @override
  String vulnTableExportedPdfFailed(int count, String path, int code) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          '$count vulnérabilités exportées → $path (échec conversion PDF, code $code)',
      one:
          '1 vulnérabilité exportée → $path (échec conversion PDF, code $code)',
    );
    return '$_temp0';
  }

  @override
  String vulnTableExportedNoPdf(int count, String path) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          '$count vulnérabilités exportées → $path (asciidoctor-pdf introuvable, PDF non généré)',
      one:
          '1 vulnérabilité exportée → $path (asciidoctor-pdf introuvable, PDF non généré)',
    );
    return '$_temp0';
  }

  @override
  String get vulnTableColSeverity => 'SÉVÉRITÉ';

  @override
  String get vulnTableColId => 'CVE / ID';

  @override
  String get vulnTableColPackage => 'PAQUET';

  @override
  String get vulnTableColLayer => 'COUCHE';

  @override
  String vulnTableUnattributed(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          '$count vulnérabilités sans couche connue (paquet absent du SBOM de l\'image) — colonne « ? ».',
      one:
          '1 vulnérabilité sans couche connue (paquet absent du SBOM de l\'image) — colonne « ? ».',
    );
    return '$_temp0';
  }

  @override
  String get vulnTableEnrichPending =>
      'Enrichissement en ligne (CISA KEV / EPSS / PoC) en cours…';

  @override
  String vulnTableNoMatchSearch(String term) {
    return 'Aucun résultat pour \"$term\"';
  }

  @override
  String vulnTableNoMatchFilter(String filters) {
    return 'Aucun résultat pour $filters';
  }

  @override
  String vulnTableOccurrences(int count) {
    return 'Ce composant est présent à $count emplacements distincts de l\'image/du SBOM (ex. une bibliothèque autonome et une copie embarquée dans un autre paquet) — la même vulnérabilité y a été fusionnée en une seule ligne.';
  }

  @override
  String get vulnTableNoExploitSignal => 'aucun signal d\'exploitation';

  @override
  String vulnTableKevTooltip(String added, String ransomware) {
    return 'CISA KEV — exploitée activement dans la nature$added$ransomware';
  }

  @override
  String vulnTableKevAdded(String date) {
    return ' (ajoutée le $date)';
  }

  @override
  String get vulnTableKevRansomware => ' · usage par rançongiciel';

  @override
  String vulnTableEpssTooltip(int percentile) {
    return 'EPSS — probabilité d\'exploitation à 30 jours (percentile $percentile)';
  }

  @override
  String vulnTablePocRepos(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count dépôts PoC publics recensés',
      one: '1 dépôt PoC public recensé',
    );
    return '$_temp0';
  }

  @override
  String vulnTablePocMaturity(String maturity) {
    return 'Maturité de l\'exploit : $maturity';
  }

  @override
  String vulnTableExploitabilityTooltip(String maturity) {
    return 'Sous-score d\'exploitabilité CVSS (AV/AC/PR/UI)$maturity';
  }

  @override
  String vulnTableExploitabilityMaturity(String maturity) {
    return ' · maturité $maturity';
  }

  @override
  String get vulnTableAllLayers => 'Toutes les couches';

  @override
  String vulnTableLayerItem(int index, int count) {
    return 'Couche $index ($count)';
  }

  @override
  String get vulnTableFlatList => 'Liste à plat';

  @override
  String get vulnTableGroupByLayer => 'Grouper par couche';

  @override
  String get vulnTableLayerUnknownTooltip =>
      'Couche inconnue (paquet absent du SBOM de l\'image)';

  @override
  String get vulnTableLayerUnknown => 'Couche inconnue';

  @override
  String vulnTableLayerLabel(int index) {
    return 'Couche $index';
  }

  @override
  String get dateFilterLabel => 'Date CVE :';

  @override
  String get dateFilterPublished => 'Publication';

  @override
  String get dateFilterModified => 'Modification';

  @override
  String get dateFilterLatest => 'La plus récente';

  @override
  String get dateFilterAfterEmpty => 'Après le…';

  @override
  String dateFilterAfter(String date) {
    return 'Après : $date';
  }

  @override
  String get dateFilterBeforeEmpty => 'Avant le…';

  @override
  String dateFilterBefore(String date) {
    return 'Avant : $date';
  }

  @override
  String get dateFilterUndated => 'Sans date';

  @override
  String get dateFilterPropagate => 'Propager aux autres onglets';

  @override
  String get grypePickConfigTitle => 'Choisir grype.yaml';

  @override
  String get grypePickTemplateTitle => 'Choisir un fichier template Grype';

  @override
  String grypeTabTable(int count) {
    return 'Table ($count)';
  }

  @override
  String get grypeTabJson => 'JSON';

  @override
  String get grypeTabTemplate => 'Template';

  @override
  String get grypeColType => 'TYPE';

  @override
  String get grypePlatformHelp =>
      'Optionnel. Force la plateforme cible sur une\nimage multi-architecture, ex. linux/arm64.\nLaisser vide = détection automatique par\ngrype (la case --platform linux ci-dessous ne\ns\'applique pas en mode image).';

  @override
  String get grypePlatformLinuxHelp =>
      'Fixe la plateforme cible à linux/amd64.\nÀ activer si Grype ne détecte pas\nautomatiquement la plateforme de l\'image.';

  @override
  String get grypeAddCpesHelp =>
      'Génère des CPE (Common Platform Enumeration)\npour les paquets qui n\'en ont pas.\nAméliore le taux de correspondance CVE.';

  @override
  String get grypeByCveHelp =>
      'Groupe les résultats par CVE plutôt que par\npaquet. Évite les doublons quand plusieurs\npaquets sont touchés par la même CVE.';

  @override
  String get grypeDistroHelp =>
      'Distribution cible pour l\'évaluation des CVE.\nSi vide, Grype tente de la détecter\nautomatiquement depuis le SBOM.';

  @override
  String get grypeFailOnHelp =>
      'Sévérité minimum pour que Grype retourne\nun code d\'erreur 1 (utile en CI/CD).\nSi vide, Grype retourne toujours 0.';

  @override
  String get grypeOnlyFixedHelp =>
      'N\'affiche que les vulnérabilités pour lesquelles\nune version corrigée est disponible.';

  @override
  String get grypeTemplateLabel => 'Template (-t)';

  @override
  String get grypeTemplateHelp =>
      'Modèle Go pour formater la sortie de Grype.\nEx : ./grype_csv.tmpl pour un export CSV.\nVoir la doc Grype pour la syntaxe des templates.';

  @override
  String get grypeConfigLabel => 'grype.yaml (optionnel)';

  @override
  String get grypeConfigHelp =>
      'Fichier de configuration Grype (YAML).\nPermet de définir des exceptions, des sources\nde données, ou de personnaliser le comportement.';

  @override
  String get grypeConfigHint => '/chemin/vers/grype.yaml';

  @override
  String get grypeTemplateEmptyRun =>
      'Lancez l\'analyse pour afficher la sortie template';

  @override
  String get grypeTemplateEmptyConfigure =>
      'Configurez un fichier template (-t) pour activer cette vue';

  @override
  String get grypeTemplateCopyTooltip => 'Copier la sortie';

  @override
  String get grypeTemplateCopied => 'Sortie template copiée';

  @override
  String get grypeEmptyHint =>
      'Choisissez un fichier SBOM ou une image de conteneur,\npuis lancez l\'analyse Grype';

  @override
  String get grypeRunning => 'Analyse Grype en cours…';

  @override
  String grypeCliTemplateOutputNote(String file) {
    return 'Sortie du template écrite dans un fichier temporaire (ici $file).';
  }

  @override
  String get grypeCliTemplateNotLayered =>
      'Le template (-t) n\'est pas appliqué en analyse par couche.';

  @override
  String get grypeCliCpesByCveUnchecked =>
      'décochage de --add-cpes-if-none / --by-cve (toujours actifs)';

  @override
  String get layerScanStepPreparing => 'Préparation des SBOM de couche…';

  @override
  String get layerScanStepImage => 'Analyse de l\'image…';

  @override
  String layerScanStepLayer(int index, int total) {
    return 'Couche $index/$total…';
  }
}
