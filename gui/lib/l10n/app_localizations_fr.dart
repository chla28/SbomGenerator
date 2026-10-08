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
  String get cliOsvGunzipNote =>
      'osv-scanner n\'accepte qu\'un tar non compressé : l\'application décompresse d\'abord l\'archive .tar.gz / .tgz vers un fichier temporaire (équivalent : gunzip -c archive.tar.gz > image.tar), le passe à osv-scanner puis le supprime.';

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

  @override
  String get scanSourcePackage => 'Paquet / archive';

  @override
  String get scanSourcePackageHint =>
      'chemin/vers/app.rpm, release.tar.gz, app.jar…';

  @override
  String get scanSourcePackageHelp =>
      'Paquet ou archive local (rpm, deb, tar/tgz, zip, jar/war/ear,\nwheel) analysé directement : le SBOM est d\'abord généré\npar sbom-generator (--input … --depth N) puis scanné.\nAvec une profondeur > 0, les jars, paquets et archives\ncontenus (ex. les jars d\'un RPM) sont aussi analysés.';

  @override
  String get scanPackageDepthLabel => 'Profondeur';

  @override
  String get scanPackageDepthHelp =>
      'Niveaux d\'objets imbriqués dans lesquels descendre :\n• 0 : l\'objet seul\n• N : N niveaux (1 = jars/paquets/archives contenus\n  dans l\'objet, 2 = ce que ceux-ci contiennent…)\n• Illimitée : tous les niveaux (plafonnés à 10)\nLes manifestes rencontrés (package-lock.json, go.sum,\npom.xml…) sont analysés. Extraction bornée en taille.';

  @override
  String get scanPackageDepthNone => '0 — objet seul';

  @override
  String get scanPackageDepthAll => 'Illimitée';

  @override
  String scanPackageDepthLevels(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count niveaux',
      one: '1 niveau',
    );
    return '$_temp0';
  }

  @override
  String get scanSourceMissingPackage =>
      'Veuillez sélectionner un paquet ou une archive.';

  @override
  String get scanPickPackageTitle => 'Choisir un paquet ou une archive';

  @override
  String get scanPackagePreparing => 'Génération du SBOM du paquet…';

  @override
  String scanPackageFailed(String error) {
    return 'Génération du SBOM impossible : $error';
  }

  @override
  String get cliCommandPackagePrepare =>
      'Génération du SBOM du paquet (étape préalable)';

  @override
  String get cliCommandPackageNote =>
      'Le SBOM est généré dans un répertoire temporaire ; chaque CVE est rattachée à l\'objet qui contient le paquet vulnérable (colonne OBJET) dans l\'équivalent sbom-generator scan.';

  @override
  String get layerGlobalSbom => 'SBOM global';

  @override
  String layerOption(int index, int total, String digest) {
    final intl.NumberFormat indexNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String indexString = indexNumberFormat.format(index);
    final intl.NumberFormat totalNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String totalString = totalNumberFormat.format(total);

    return 'Couche $indexString/$totalString ($digest)';
  }

  @override
  String layerCount(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString couches :',
      one: '$countString couche :',
    );
    return '$_temp0';
  }

  @override
  String layerRemovedChip(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString supprimés',
      one: '$countString supprimé',
    );
    return '$_temp0';
  }

  @override
  String get cveCopyId => 'Copier l\'identifiant';

  @override
  String get cveCopied => 'CVE copié';

  @override
  String get cveReportedBy => 'Rapporté par';

  @override
  String get cveThSeverity => 'Sévérité';

  @override
  String get cveThPublishedModified => 'Publié / modifié';

  @override
  String get cveExploitTitle => 'Exploitabilité et exploitation active';

  @override
  String get cveNoSignal => 'Aucun signal d\'exploitation connu.';

  @override
  String get cveKevLine => 'CISA KEV — exploitée activement dans la nature';

  @override
  String cveKevAddedOn(String date) {
    return ' · ajoutée le $date';
  }

  @override
  String cveKevDueOn(String date) {
    return ' · échéance $date';
  }

  @override
  String get cveKevRansomware => ' · usage par rançongiciel';

  @override
  String cveEpssLine(String score, int pct) {
    final intl.NumberFormat pctNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String pctString = pctNumberFormat.format(pct);

    return 'EPSS $score (percentile p$pctString) — probabilité d\'exploitation à 30 jours';
  }

  @override
  String cveExploitability(String score) {
    return 'exploitabilité $score/3.9';
  }

  @override
  String cveMaturity(String value) {
    return 'maturité $value';
  }

  @override
  String cvePocRepos(int n) {
    final intl.NumberFormat nNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String nString = nNumberFormat.format(n);

    String _temp0 = intl.Intl.pluralLogic(
      n,
      locale: localeName,
      other: '$nString dépôts PoC publics recensés',
      one: '$nString dépôt PoC public recensé',
    );
    return '$_temp0';
  }

  @override
  String get cvePocKnown => 'Exploit / PoC public recensé';

  @override
  String get cveReferences => 'Références';

  @override
  String get adocPackage => 'Paquet';

  @override
  String get adocDates => 'Dates';

  @override
  String adocDateEntry(String scanner, String published, String modified) {
    return '$scanner : publié $published, modifié $modified';
  }

  @override
  String get adocDescription => 'Description';

  @override
  String adocKevYes(String details) {
    return 'Oui — $details';
  }

  @override
  String adocKevAdded(String date) {
    return 'ajoutée $date';
  }

  @override
  String adocKevDue(String date) {
    return 'échéance $date';
  }

  @override
  String get adocKevRansomware => 'usage par rançongiciel';

  @override
  String adocEpss(String score, int pct) {
    final intl.NumberFormat pctNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String pctString = pctNumberFormat.format(pct);

    return '$score (percentile p$pctString)';
  }

  @override
  String adocCvssBase(String score) {
    return 'base $score';
  }

  @override
  String get adocPocPublic => 'PoC public';

  @override
  String adocPocRepos(int n) {
    final intl.NumberFormat nNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String nString = nNumberFormat.format(n);

    String _temp0 = intl.Intl.pluralLogic(
      n,
      locale: localeName,
      other: '$nString dépôts',
      one: '$nString dépôt',
    );
    return '$_temp0';
  }

  @override
  String get adocYes => 'oui';

  @override
  String get adocLinks => 'Liens';

  @override
  String get pdfSeverityCritical => 'CRITIQUE';

  @override
  String get pdfSeverityHigh => 'ÉLEVÉE';

  @override
  String get pdfSeverityMedium => 'MOYENNE';

  @override
  String get pdfSeverityLow => 'FAIBLE';

  @override
  String get pdfSeverityNegligible => 'NÉGLIGEABLE';

  @override
  String get pdfSeverityBarAlt => 'Répartition par sévérité';

  @override
  String get pdfUnavailable => '_indisponible_';

  @override
  String layerDocHeader(String index, String total, String mode) {
    return 'Couche $index/$total — mode $mode';
  }

  @override
  String layerDocDigest(String digest) {
    return 'Digest : $digest';
  }

  @override
  String layerDocInstruction(String text) {
    return 'Instruction : $text';
  }

  @override
  String layerDocCounts(String added, String modified, String removed) {
    return 'Ajoutés : $added — modifiés : $modified — supprimés : $removed';
  }

  @override
  String layerDocAnalyzed(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString couches analysées',
      one: '$countString couche analysée',
    );
    return '$_temp0';
  }

  @override
  String layerDocModeSuffix(String mode) {
    return ' — mode $mode';
  }

  @override
  String get layerColAdded => 'ajouté';

  @override
  String layerColModifiedWas(String prev) {
    return 'modifié (était $prev)';
  }

  @override
  String get layerColModified => 'modifié';

  @override
  String layerColLayer(String index) {
    return 'couche $index';
  }

  @override
  String layerColLayerModifiedBy(String index, String by) {
    return 'couche $index (modifié : $by)';
  }

  @override
  String get layerGroupAdded => 'Ajoutés';

  @override
  String get layerGroupModified => 'Modifiés';

  @override
  String get layerGroupUnknown => '(couche inconnue)';

  @override
  String layerGroupLayer(String index) {
    return 'Couche $index';
  }

  @override
  String get layerScanModeEach => 'SBOM de chaque couche scanné';

  @override
  String get layerScanModeAttribute =>
      'rattachement à la couche d\'origine du paquet';

  @override
  String get treeFormatUnknown => 'Format non reconnu (ni CycloneDX ni SPDX).';

  @override
  String treeReadError(String error) {
    return 'Erreur de lecture : $error';
  }

  @override
  String get treePickTitle => 'Sélectionner un fichier SBOM (JSON)';

  @override
  String get treeUnspecified => '(non spécifié)';

  @override
  String get treeExpandAll => 'Tout déplier';

  @override
  String get treeCollapseAll => 'Tout replier';

  @override
  String get treeFilterHint => 'Filtrer par nom, purl, licence…';

  @override
  String treeNoMatch(String term) {
    return 'Aucun composant pour \"$term\"';
  }

  @override
  String get treeNoFileSelected => 'Aucun fichier SBOM sélectionné';

  @override
  String treeGenerated(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return 'Générés ($countString)';
  }

  @override
  String get treeOpen => 'Ouvrir…';

  @override
  String treeComponentsChip(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString composants',
      one: '$countString composant',
    );
    return '$_temp0';
  }

  @override
  String treeLicensesChip(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString licences',
      one: '$countString licence',
    );
    return '$_temp0';
  }

  @override
  String get treeGroupBy => 'Grouper :';

  @override
  String get treeGroupHelp =>
      'Mode de regroupement des composants.\n• Aucun : liste à plat alphabétique\n• Type : groupé par écosystème (rpm, pypi…)\n• Licence : groupé par expression SPDX\n• Couche : groupé par couche d\'origine (SBOM global) ou par changement (SBOM de couche) — SBOM produits avec --per-layer';

  @override
  String get treeGroupNone => 'Aucun';

  @override
  String get treeGroupType => 'Type';

  @override
  String get treeGroupLicense => 'Licence';

  @override
  String get treeGroupLayer => 'Couche';

  @override
  String get treeDetailLicense => 'Licence';

  @override
  String get treeDetailLayer => 'Couche';

  @override
  String get treeEmptyNoSbom =>
      'Aucun fichier SBOM (JSON/JSON-LD) dans les sorties.';

  @override
  String get treeEmptyGenerate =>
      'Générez un SBOM ou ouvrez un fichier existant.';

  @override
  String get treeOpenSbom => 'Ouvrir un fichier SBOM';

  @override
  String get viewerOpenTitle => 'Ouvrir un fichier SBOM';

  @override
  String viewerParseError(String error) {
    return 'Impossible de parser le fichier : $error';
  }

  @override
  String get viewerUnspecified => 'Non spécifiée';

  @override
  String get viewerNoFile => 'Aucun fichier SBOM chargé';

  @override
  String get viewerOpenEllipsis => 'Ouvrir un fichier SBOM…';

  @override
  String get viewerStatComponents => 'composants';

  @override
  String get viewerStatTypes => 'types';

  @override
  String get viewerStatLicenses => 'licences';

  @override
  String get viewerOpenShort => 'Ouvrir…';

  @override
  String get viewerFilterHint => 'Filtrer…';

  @override
  String get viewerTypeHint => 'Type';

  @override
  String get viewerAll => 'Tous';

  @override
  String get viewerNoResult => 'Aucun résultat';

  @override
  String get viewerColName => 'Nom';

  @override
  String get viewerColLicense => 'Licence';

  @override
  String get viewerColChange => 'Changement';

  @override
  String get viewerColLayer => 'Couche';

  @override
  String get viewerCopyPurl => 'Copier le PURL';

  @override
  String get viewerPurlCopied => 'PURL copié';

  @override
  String get commonGeneratedFiles => 'Fichiers générés';

  @override
  String get commonOutputFile => 'Fichier de sortie';

  @override
  String get commonDocNameOptional => 'Nom du document (optionnel)';

  @override
  String get licPickTitle => 'Sélectionner un fichier SBOM';

  @override
  String get licChooseFile => 'Choisir un fichier…';

  @override
  String get licNoFile => 'Aucun fichier sélectionné';

  @override
  String get licGenerate => 'Générer';

  @override
  String licReportGenerated(String path) {
    return 'Rapport généré → $path';
  }

  @override
  String licReportFailed(int code) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return 'Échec de la génération (code $codeString) — voir le journal ci-dessous.';
  }

  @override
  String licLoadError(String error) {
    return 'Impossible de lire les licences : $error';
  }

  @override
  String get licSelectHint =>
      'Sélectionnez un fichier CycloneDX ou SPDX pour visualiser ses licences (regroupées par licence, avec signalement des licences copyleft et des paquets sans licence détectée), puis générer un rapport ci-dessous.';

  @override
  String get licFilterHint => 'Filtrer par licence ou par paquet…';

  @override
  String get licViewGrouped => 'Par licence';

  @override
  String get licViewTable => 'Tableau';

  @override
  String get licNoResult => 'Aucun résultat.';

  @override
  String licChipPackages(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString paquets',
      one: '$countString paquet',
    );
    return '$_temp0';
  }

  @override
  String licChipLicenses(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString licences',
      one: '$countString licence',
    );
    return '$_temp0';
  }

  @override
  String licChipStrong(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '$countString copyleft fort';
  }

  @override
  String licChipWeak(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '$countString copyleft faible';
  }

  @override
  String licChipNone(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '$countString sans licence';
  }

  @override
  String get licCategoryStrong => 'copyleft fort';

  @override
  String get licCategoryWeak => 'copyleft faible';

  @override
  String get licCategoryNone => 'sans licence';

  @override
  String get licNoLicenseDetected => 'Sans licence détectée';

  @override
  String get licColPackage => 'Paquet';

  @override
  String get licColLicense => 'Licence';

  @override
  String get mergePickTitle => 'Sélectionner des fichiers SBOM à fusionner';

  @override
  String get mergeAddFiles => 'Ajouter des fichiers…';

  @override
  String get mergeJsonOnly => '.json / .jsonld';

  @override
  String get mergeAllFiles => 'Tous les fichiers';

  @override
  String mergeSelected(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString fichiers sélectionnés',
      one: '$countString fichier sélectionné',
    );
    return '$_temp0';
  }

  @override
  String get mergeAtLeastTwo => ' — au moins 2 requis';

  @override
  String get mergeHint =>
      'Ajoutez au moins deux fichiers SBOM à fusionner\n(CycloneDX ou SPDX 2.x — un même format des deux côtés).';

  @override
  String get mergeButton => 'Fusionner';

  @override
  String mergeOk(String path) {
    return 'Fusion réussie → $path';
  }

  @override
  String mergeFailed(int code) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return 'Échec de la fusion (code $codeString) — voir le journal ci-dessous.';
  }

  @override
  String get diffFormatUnknown => 'Format non reconnu.';

  @override
  String get diffPickA => 'Sélectionner SBOM A (référence)';

  @override
  String get diffPickB => 'Sélectionner SBOM B (comparé)';

  @override
  String diffNoMatch(String term) {
    return 'Aucun résultat pour \"$term\"';
  }

  @override
  String get diffNoItems => 'Aucun élément pour les filtres sélectionnés.';

  @override
  String get diffSlotA => 'A – Référence';

  @override
  String get diffSlotB => 'B – Comparé';

  @override
  String get diffCompare => 'Comparer';

  @override
  String get diffNoFile => 'Aucun fichier sélectionné';

  @override
  String diffComponentsInfo(String format, int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString composants',
      one: '$countString composant',
    );
    return '$format · $_temp0';
  }

  @override
  String get diffOpenFile => 'Ouvrir un fichier…';

  @override
  String get diffAdded => 'Ajoutés';

  @override
  String get diffRemoved => 'Supprimés';

  @override
  String get diffChanged => 'Modifiés';

  @override
  String get diffUnchanged => 'Inchangés';

  @override
  String diffChipAdded(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '➕ Ajoutés ($countString)';
  }

  @override
  String diffChipRemoved(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '➖ Supprimés ($countString)';
  }

  @override
  String diffChipChanged(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '🔄 Modifiés ($countString)';
  }

  @override
  String diffChipUnchanged(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '✓ Inchangés ($countString)';
  }

  @override
  String get diffFilterHint => 'Filtrer par nom…';

  @override
  String get diffHdrStatus => 'STATUT';

  @override
  String get diffHdrName => 'NOM';

  @override
  String get diffHdrVersionA => 'VERSION A';

  @override
  String get diffHdrVersionB => 'VERSION B';

  @override
  String get diffHdrLicense => 'LICENCE';

  @override
  String get diffStatusAdded => 'Ajouté';

  @override
  String get diffStatusRemoved => 'Supprimé';

  @override
  String get diffStatusChanged => 'Modifié';

  @override
  String get diffStatusUnchanged => 'Inchangé';

  @override
  String get diffEmptyReady =>
      'Cliquez sur \"Comparer\" pour lancer l\'analyse.';

  @override
  String get diffEmptyPick =>
      'Sélectionnez deux fichiers SBOM (A et B) pour les comparer.';

  @override
  String get qualityPickTitle => 'Sélectionner un fichier SBOM';

  @override
  String qualitySbomqsError(int code) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return 'Erreur sbomqs (exit $codeString)';
  }

  @override
  String get qualitySbomqsMissing =>
      'sbomqs introuvable — installez-le et ajoutez-le au PATH';

  @override
  String qualityScorecardError(int code) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return 'Erreur sbom-scorecard (exit $codeString)';
  }

  @override
  String get qualityScorecardMissing =>
      'sbom-scorecard introuvable — installez-le et ajoutez-le au PATH';

  @override
  String get qualityFileLabel => 'Fichier SBOM';

  @override
  String get qualityAnalyze => 'Analyser';

  @override
  String get qualityProfiles => 'Profils :';

  @override
  String get qualityProfilesHelp =>
      'Profils de conformité SBOM évalués par sbomqs.\nChaque profil vérifie un ensemble de critères\nspécifiques (NTIA, BSI, OpenChain, Interlynk…).\nAucun profil sélectionné = tous évalués.';

  @override
  String get qualityTitle => 'Évaluation de la qualité SBOM';

  @override
  String get qualityIntro =>
      'Sélectionnez un fichier SBOM puis cliquez sur Analyser.\nL\'analyse utilise sbomqs (Interlynk) et sbom-scorecard (eBay).';

  @override
  String get qualityTableView => 'Vue tableau';

  @override
  String get qualityRawJson => 'JSON brut';

  @override
  String get qualityNoCriteria => 'Aucun critère détaillé disponible.';

  @override
  String get qualityOther => 'Autre';

  @override
  String get qualityShowAll => 'Tout voir';

  @override
  String get qualityChartView => 'Vue graphique';

  @override
  String get qualityRawOutput => 'Sortie brute';

  @override
  String get qualityIndustryProfiles => 'Profils d\'industrie';

  @override
  String get qualityIndustryHint =>
      'Sélectionnez des profils dans la barre de configuration\npour afficher le détail des critères';

  @override
  String qualityProfileSummary(String score, int passed, int total) {
    final intl.NumberFormat passedNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String passedString = passedNumberFormat.format(passed);
    final intl.NumberFormat totalNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String totalString = totalNumberFormat.format(total);

    return '$score/10  ·  $passedString/$totalString critères';
  }

  @override
  String get qualityRequiredNote => '* critère obligatoire';

  @override
  String get tabProgress => 'Progression';

  @override
  String get tabResults => 'Résultats';

  @override
  String tabResultsCount(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return 'Résultats ($countString)';
  }

  @override
  String get tabDashboard => 'Tableau de bord';

  @override
  String get tabCra => 'Conformité CRA';

  @override
  String get tabQuality => 'Qualité SBOM';

  @override
  String get tabTree => 'Arborescence';

  @override
  String get tabCompare => 'Comparaison';

  @override
  String get tabMerge => 'Fusion';

  @override
  String get tabLicenses => 'Licences';

  @override
  String get tabViewer => 'Visionneuse';

  @override
  String get tabPreview => 'Aperçu';

  @override
  String tabPreviewCount(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return 'Aperçu ($countString)';
  }

  @override
  String resultsPreviewTruncated(int total) {
    final intl.NumberFormat totalNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String totalString = totalNumberFormat.format(total);

    return '[… tronqué — $totalString caractères au total]';
  }

  @override
  String resultsReadError(String error) {
    return 'Erreur de lecture : $error';
  }

  @override
  String get resultsPdfConverting =>
      'Conversion PDF (asciidoctor-pdf) en cours…';

  @override
  String resultsProgressPackages(int current, int total) {
    final intl.NumberFormat currentNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String currentString = currentNumberFormat.format(current);
    final intl.NumberFormat totalNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String totalString = totalNumberFormat.format(total);

    return '$currentString / $totalString paquets';
  }

  @override
  String resultsSummaryOk(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString fichiers SBOM générés',
      one: '$countString fichier SBOM généré',
    );
    return '$_temp0';
  }

  @override
  String resultsSummaryWarnings(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString avertissements',
      one: '$countString avertissement',
    );
    return ' — $_temp0';
  }

  @override
  String resultsGenerationFailed(int code) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return 'Échec de la génération (exit $codeString)';
  }

  @override
  String get resultsLogsCopied => 'Logs copiés dans le presse-papier';

  @override
  String get resultsSave => 'Enregistrer';

  @override
  String get resultsSaveLogsTitle => 'Enregistrer les logs';

  @override
  String resultsStatPackages(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString paquets',
      one: '$countString paquet',
    );
    return '$_temp0';
  }

  @override
  String resultsStatFiles(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString fichiers SBOM',
      one: '$countString fichier SBOM',
    );
    return '$_temp0';
  }

  @override
  String resultsStatWarnings(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString avertissements',
      one: '$countString avertissement',
    );
    return '$_temp0';
  }

  @override
  String get resultsSectionFiles => 'Fichiers générés';

  @override
  String get resultsSectionScore => 'Score sbomqs';

  @override
  String resultsSectionWarnings(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return 'Avertissements ($countString)';
  }

  @override
  String get resultsSectionError => 'Erreur';

  @override
  String get resultsNoPreview =>
      'Aucun fichier texte généré pour la prévisualisation';

  @override
  String get resultsCopyContent => 'Copier le contenu';

  @override
  String get resultsContentCopied => 'Contenu copié';

  @override
  String get resultsSelectFile => 'Sélectionnez un fichier';

  @override
  String get resultsCopyPath => 'Copier le chemin';

  @override
  String get resultsPathCopied => 'Chemin copié';

  @override
  String get resultsOpenFile => 'Ouvrir le fichier';

  @override
  String get resultsCollapse => 'Réduire';

  @override
  String resultsShowMore(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return 'Voir $countString de plus…';
  }

  @override
  String get resultsEmptyHint =>
      'Configurez les options et lancez la génération';

  @override
  String homeGenerationFailed(int code) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return 'Génération échouée (exit $codeString)';
  }

  @override
  String get homePdfHeader => 'Conversion PDF (asciidoctor-pdf)…';

  @override
  String homePdfError(int code) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return 'Erreur asciidoctor-pdf (exit $codeString)';
  }

  @override
  String get homePdfMissing => 'Erreur : asciidoctor-pdf introuvable.';

  @override
  String get homePdfInstall => '  Installez avec : gem install asciidoctor-pdf';

  @override
  String get homeInterrupted => '[Génération interrompue par l\'utilisateur]';

  @override
  String get homePdfRunning => 'Conversion PDF en cours…';

  @override
  String get homeSbomRunning => 'Génération SBOM en cours…';

  @override
  String get homeHelpTooltip => 'Aide — Manuel utilisateur';

  @override
  String get homeThemeColor => 'Couleur du thème';

  @override
  String get homeLightMode => 'Mode clair';

  @override
  String get homeDarkMode => 'Mode sombre';

  @override
  String get homeAbout => 'À propos';

  @override
  String get homeAboutText =>
      'Interface graphique pour l\'outil sbom_generator.\n\nGénère des SBOM (Software Bill of Materials) depuis des listes de paquets RPM, .whl, .tar.gz, .deb, .zip, .jar, ou de manifestes (requirements.txt, go.sum, package-lock.json, pom.xml, pubspec.lock…) — fichier liste, paquet unique, ou dossier scanné récursivement.\n\nFormats supportés : CycloneDX 1.6/1.7, SPDX 2.3, SPDX 3.0 JSON-LD, JSON personnalisé, Markdown, AsciiDoc.';

  @override
  String get homeCancel => 'Annuler';

  @override
  String get themeBlue => 'Bleu';

  @override
  String get themePurple => 'Violet';

  @override
  String get themeGreen => 'Vert';

  @override
  String get themeRed => 'Rouge';

  @override
  String get themePink => 'Rose';

  @override
  String get themeSlate => 'Ardoise';

  @override
  String get themeBrown => 'Marron';

  @override
  String svcLaunchError(String error) {
    return 'Erreur de lancement : $error';
  }

  @override
  String get svcGrypeMissing =>
      'grype introuvable. Installez-le : https://github.com/anchore/grype';

  @override
  String get svcOsvMissing =>
      'osv-scanner introuvable — https://github.com/google/osv-scanner';

  @override
  String get svcTrivyMissing =>
      'trivy introuvable — https://github.com/aquasecurity/trivy';

  @override
  String svcLayerSbomFailed(int code, String detail) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return 'génération des SBOM de couche impossible (code $codeString) : $detail';
  }

  @override
  String svcNoLayer(String image) {
    return 'aucune couche trouvée dans $image';
  }

  @override
  String get svcNotInstalled => 'non installé';

  @override
  String get svcUpdateAvailable =>
      'Mise à jour disponible — cliquez pour accéder à la release';

  @override
  String get craInvalidSbom => 'Sélectionnez un fichier SBOM valide.';

  @override
  String craUnexpectedOutput(int code) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return 'Sortie inattendue (code $codeString).';
  }

  @override
  String craLaunchFailed(String error) {
    return 'Échec du lancement : $error';
  }

  @override
  String get craExportTitle => 'Exporter le rapport CRA (PDF)';

  @override
  String get craExportFileName => 'rapport-cra.pdf';

  @override
  String craReportWritten(String path) {
    return 'Rapport CRA écrit → $path';
  }

  @override
  String craFailed(String detail) {
    return 'Échec : $detail';
  }

  @override
  String get craTitle => 'Rapport de conformité — Cyber Resilience Act';

  @override
  String get craHelp =>
      'Périmètre vérifiable automatiquement uniquement : format et complétude du SBOM (Annexe I §2 point 1, BSI TR-03183-2, éléments minimaux NTIA), inventaire des vulnérabilités connues et disponibilité des correctifs, vulnérabilités activement exploitées (art. 14). Les autres obligations du CRA relèvent du fabricant. Ce rapport n\'est pas une déclaration de conformité.';

  @override
  String get craSbomField => 'Fichier SBOM à évaluer';

  @override
  String get craProductMeta => 'Métadonnées produit (facultatif)';

  @override
  String get craManufacturer => 'Fabricant';

  @override
  String get craProduct => 'Produit';

  @override
  String get craProductVersion => 'Version du produit';

  @override
  String get craSupportUntil => 'Fin de support (AAAA-MM-JJ)';

  @override
  String get craVulnContact => 'Contact de signalement des vulnérabilités';

  @override
  String get craCvdUrl => 'URL de la politique de divulgation coordonnée';

  @override
  String get craLoadConfig => 'Charger un cra.yaml';

  @override
  String craConfigLoaded(String name) {
    return 'cra.yaml : $name';
  }

  @override
  String get craScanVulns => 'Analyser les vulnérabilités connues';

  @override
  String get craScannerAll => 'Les trois';

  @override
  String get craEvaluate => 'Évaluer';

  @override
  String get craExportPdf => 'Exporter le rapport PDF';

  @override
  String get craStatusOk => 'Conforme';

  @override
  String get craStatusPartial => 'Partiel';

  @override
  String get craStatusFail => 'Non conforme';

  @override
  String get craStatusNa => 'Non évalué';

  @override
  String craVerdict(String status) {
    return 'Verdict (périmètre vérifié) : $status';
  }

  @override
  String get craTileFields => 'Champs SBOM conformes';

  @override
  String get craTileNtia => 'Éléments NTIA';

  @override
  String get craTileNoFix => 'Vuln. sans correctif';

  @override
  String get craTileKev => 'CVE exploitées (KEV)';

  @override
  String get craBlockers => 'Points bloquants';

  @override
  String get craFieldsTitle => 'Champs de données SBOM (BSI TR-03183-2)';

  @override
  String get craThField => 'Champ';

  @override
  String get craThCoverage => 'Couverture';

  @override
  String get craThStatus => 'Statut';

  @override
  String craSbomSummary(String format, String components, String relations) {
    return 'SBOM : $format — $components composants, $relations relations de dépendance.';
  }

  @override
  String craVulnSummary(String total, String critical, String high) {
    return 'Vulnérabilités : $total CVE — $critical critiques, $high élevées.';
  }

  @override
  String get craEnisaNotice =>
      ' ⚠ Notification ENISA sous 24 h requise (art. 14).';

  @override
  String get commonStopAction => 'Arrêter';

  @override
  String scanTargetImage(String target) {
    return 'image « $target »';
  }

  @override
  String scanTargetSbom(String name) {
    return 'SBOM $name';
  }

  @override
  String get cliPlaceholderPackage => '<paquet>';

  @override
  String scanBannerCount(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString vulnérabilités',
      one: '$countString vulnérabilité',
    );
    return '$_temp0 — ';
  }

  @override
  String get scanTabVulns => 'Vulnérabilités';

  @override
  String get scanTabRawJson => 'JSON brut';

  @override
  String get scanHintPick =>
      'Sélectionnez un SBOM ou une image et lancez l\'analyse';

  @override
  String scanRunningTool(String tool) {
    return 'Analyse $tool en cours…';
  }

  @override
  String scanRunButton(String tool) {
    return 'Analyser avec $tool';
  }

  @override
  String get scanNoVulnFound => 'Aucune vulnérabilité trouvée';

  @override
  String scanPlatformHelp(String tool) {
    return 'Optionnel. Force la plateforme cible sur une\nimage multi-architecture, ex. linux/arm64.\nLaisser vide = détection automatique par $tool.';
  }

  @override
  String get trivyPickConfigTitle => 'Choisir trivy.yaml';

  @override
  String get trivySeverityLabel => '--severity (laisser vide = tout)';

  @override
  String get trivySeverityHelp =>
      'Filtres de sévérité. Seules les vulnérabilités\ndont la sévérité est cochée sont affichées.\nLaisser vide = toutes les sévérités.';

  @override
  String get trivyIgnoreUnfixedHelp =>
      'Masque les vulnérabilités sans version\ncorrigée disponible. Réduit le bruit\ndans les résultats.';

  @override
  String get trivySkipDbHelp =>
      'Utilise la base CVE locale sans la mettre\nà jour. Accélère les analyses successives,\nmais la base peut être obsolète.';

  @override
  String get trivyConfigLabel => 'trivy.yaml (optionnel)';

  @override
  String get trivyConfigHelp =>
      'Fichier de configuration Trivy (YAML).\nPermet de définir des politiques, des\nexceptions ou des sources personnalisées.';

  @override
  String get trivyConfigHint => '/chemin/vers/trivy.yaml';

  @override
  String get trivyCliConfigNote => 'fichier de config';

  @override
  String get trivyCliPlatformNote => 'plateforme';

  @override
  String get osvPickConfigTitle => 'Choisir osv-scanner.toml';

  @override
  String get osvConfigLabel => 'Fichier de config (optionnel)';

  @override
  String get osvConfigHelp =>
      'Fichier TOML de configuration osv-scanner.\nPermet d\'exclure des CVE, de configurer\ndes sources ou de définir des politiques.';

  @override
  String get osvCliConfigNote => 'fichier de config (toml)';

  @override
  String get osvEcosystemColumn => 'ÉCOSYSTÈME';

  @override
  String get vulnCsvHeaderGrype =>
      'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Type,Emplacements';

  @override
  String get vulnCsvHeaderTrivy =>
      'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Titre,Emplacements';

  @override
  String get vulnCsvHeaderOsv =>
      'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Écosystème,Emplacements';

  @override
  String get pdfSeverityOther => 'AUTRE';

  @override
  String get repTocTitle => ':toc-title: Sommaire';

  @override
  String get repExecSummary => '== Résumé exécutif';

  @override
  String repTarget(String target) {
    return '*Cible analysée* : $target +';
  }

  @override
  String get repTools => '== Outils';

  @override
  String get repToolHeader => '| Outil | Version';

  @override
  String get repSevCountHeader => '| Sévérité | Nombre';

  @override
  String get repLayersTitle => '== Couches de l\'image';

  @override
  String get dashExportTitle => 'Exporter le tableau de bord (AsciiDoc + PDF)';

  @override
  String get dashExportFileAll => 'rapport-vulnerabilites.adoc';

  @override
  String dashExportFileThreshold(String threshold) {
    return 'rapport-vulnerabilites-$threshold.adoc';
  }

  @override
  String dashExported(String path, String pdf) {
    return 'Tableau de bord exporté → $path et $pdf';
  }

  @override
  String dashExportedNoPdf(String path) {
    return 'Tableau de bord exporté → $path (asciidoctor-pdf introuvable, PDF non généré)';
  }

  @override
  String get dashTitle => 'Tableau de bord des vulnérabilités';

  @override
  String get dashNoScan =>
      'Aucun scanner exécuté — lancez un scan depuis les onglets Grype, OSV-Scanner ou Trivy.';

  @override
  String dashScanSummary(int scans, int ids) {
    final intl.NumberFormat scansNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String scansString = scansNumberFormat.format(scans);
    final intl.NumberFormat idsNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String idsString = idsNumberFormat.format(ids);

    String _temp0 = intl.Intl.pluralLogic(
      scans,
      locale: localeName,
      other: '$scansString scanners exécutés',
      one: '$scansString scanner exécuté',
    );
    String _temp1 = intl.Intl.pluralLogic(
      ids,
      locale: localeName,
      other: '$idsString CVE uniques détectées',
      one: '$idsString CVE unique détectée',
    );
    return '$_temp0 · $_temp1';
  }

  @override
  String get dashUniqueCves => 'CVE uniques';

  @override
  String get dashThresholdTooltip =>
      'Sévérité minimale des CVE du rapport PDF (les CVE CISA KEV sont toujours incluses)';

  @override
  String get dashNotRun => 'Non exécuté';

  @override
  String get dashNone => '✓ Aucune';

  @override
  String dashTotalVulns(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString vulnérabilités',
      one: '$countString vulnérabilité',
    );
    return '$_temp0';
  }

  @override
  String dashRunScanFrom(String name) {
    return 'Lancez le scan depuis\nl\'onglet $name';
  }

  @override
  String get dashOtherSeverity => 'Autre';

  @override
  String dashCompareTitle(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return 'Comparaison inter-scanners ($countString CVE';
  }

  @override
  String dashCompareKev(int kev) {
    final intl.NumberFormat kevNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String kevString = kevNumberFormat.format(kev);

    return ', dont $kevString CISA KEV';
  }

  @override
  String get dashHdrSeverity => 'SÉV.';

  @override
  String get dashHdrLayers => 'COUCHE(S)';

  @override
  String dashSeenByOne(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return 'Vu par un seul scanner sur $countString';
  }

  @override
  String dashEpssTooltip(String score, int pct) {
    final intl.NumberFormat pctNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String pctString = pctNumberFormat.format(pct);

    return 'EPSS $score — probabilité d\'exploitation à 30 jours (percentile $pctString)';
  }

  @override
  String dashLayersCard(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return 'Couches de l\'image ($countString)';
  }

  @override
  String get dashHdrLayer => 'COUCHE';

  @override
  String get dashHdrHigh => 'ÉLEV.';

  @override
  String get cfgTitle => 'Configuration';

  @override
  String get cfgProfilesTooltip => 'Profils de configuration';

  @override
  String get cfgSectionInput => 'Entrée';

  @override
  String get cfgSectionOutput => 'Sortie';

  @override
  String get cfgSectionOptions => 'Options';

  @override
  String get cfgInputLabel => 'Paquets à analyser (--input)';

  @override
  String get cfgInputHintDrop => 'Déposez un fichier ou un dossier ici…';

  @override
  String get cfgInputHint => 'rpm.lst, un .jar, ou un dossier…';

  @override
  String get cfgInputHelp =>
      'Fichier liste (une référence par ligne),\nune archive/un paquet unique (.rpm, .deb,\n.whl, .jar, .zip, .tar.gz…), ou un dossier\nscanné récursivement pour tous ces types.';

  @override
  String get cfgPickInputFile => 'Sélectionner le fichier d\'entrée';

  @override
  String get cfgPickPackagesDir => 'Sélectionner un dossier de paquets';

  @override
  String get cfgInputRequired =>
      'Requis (ou spécifiez une image OCI / un binaire)';

  @override
  String get cfgDragHint =>
      'Glissez-déposez un fichier ou un dossier depuis votre gestionnaire';

  @override
  String get cfgOr => 'OU';

  @override
  String get cfgPickOciArchive => 'Sélectionner une archive OCI';

  @override
  String get cfgPickOciDir => 'Sélectionner un répertoire OCI layout';

  @override
  String get cfgPickBinary => 'Sélectionner un binaire';

  @override
  String get cfgBinarySyftForced =>
      'Backend : syft (forcé — seul capable d\'analyser un binaire autonome)';

  @override
  String get cfgOutputBase => 'Chemin de base (--output)';

  @override
  String get cfgOutputBaseHint => 'sbom  →  sbom.cdx.json, sbom.spdx.json…';

  @override
  String get cfgOutputBaseHelp =>
      'Préfixe du chemin de sortie. Le suffixe de\nformat est ajouté automatiquement.\nEx : sbom → sbom.cdx.json, sbom.spdx.json…';

  @override
  String get cfgOutputBaseTitle => 'Chemin de base du SBOM';

  @override
  String get cfgFormats => 'Formats (--format)';

  @override
  String get cfgFormatsHelp =>
      'Sélectionnez un ou plusieurs formats de sortie.\nCycloneDX (1.6 ou 1.7) et SPDX sont les standards industrie.\nMarkdown et AsciiDoc sont lisibles directement.';

  @override
  String get cfgPdf => 'Convertir en PDF (asciidoctor-pdf)';

  @override
  String get cfgPdfSub => 'Lance asciidoctor-pdf après la génération';

  @override
  String get cfgPdfPath => 'Chemin du PDF (optionnel)';

  @override
  String get cfgPdfPathHint => 'Défaut : même dossier que .adoc';

  @override
  String get cfgPdfSaveTitle => 'Enregistrer le PDF sous…';

  @override
  String get cfgName => 'Nom du document SBOM (--name)';

  @override
  String get cfgNameHelp =>
      'Nom logique du document SBOM\n(champ metadata.component.name).\nEx : \"Mon Application 1.0\"';

  @override
  String get cfgNameHint => 'Mon Application 1.0';

  @override
  String get cfgRpmDir => 'Répertoire RPM local (--rpm-dir)';

  @override
  String get cfgRpmDirHint => 'Dossier contenant des fichiers .rpm';

  @override
  String get cfgRpmDirHelp =>
      'Dossier contenant des fichiers .rpm.\nsbom_generator extrait les métadonnées\nsans installer les paquets (rpm -qp).';

  @override
  String get cfgRpmDirTitle => 'Répertoire de fichiers RPM';

  @override
  String get cfgLicenseMap => 'Override licences (--license-map)';

  @override
  String get cfgLicenseMapHint => 'Fichier \"paquet: SPDX-expression\"';

  @override
  String get cfgLicenseMapHelp =>
      'Fichier de substitution de licences,\nformat \"paquet: SPDX-expression\" par ligne.\nEx : mon-paquet-interne: MIT';

  @override
  String get cfgLicenseMapTitle => 'Fichier de map licences';

  @override
  String get cfgConcurrency => 'Concurrence (--concurrency)';

  @override
  String get cfgConcurrencyHelp =>
      'Nombre de paquets analysés simultanément.\n0 = illimité (tous en parallèle).\nRéduire si les outils externes nécessitent\ndes accès exclusifs ou si la machine est lente.';

  @override
  String get cfgUnlimited => 'illimitée';

  @override
  String get cfgConcurrencyZero => '0 = tous les paquets en parallèle';

  @override
  String get cfgConcurrencyNote => '1 = séquentiel  •  défaut : 4';

  @override
  String get cfgVerbose => 'Mode verbeux (--verbose)';

  @override
  String get cfgVerboseSub => 'Affiche les outils détectés et les statistiques';

  @override
  String get cfgVerboseHelp =>
      'Affiche pour chaque paquet : outil utilisé,\nversion, durée de traitement.\nUtile pour déboguer les paquets dont la\nlicence n\'est pas reconnue.';

  @override
  String get cfgSbomqs => 'Score qualité sbomqs';

  @override
  String get cfgSbomqsHelp =>
      'Exécute sbomqs (Interlynk) sur le SBOM généré\npour calculer un score de conformité (0–10).\nRequiert que sbomqs soit installé dans le PATH.';

  @override
  String get cfgSbomqsSub =>
      'Analyse le SBOM généré avec sbomqs après génération';

  @override
  String get cfgStop => 'Arrêter la génération';

  @override
  String get cfgGenerate => 'Générer le SBOM';

  @override
  String get cfgCopyCommand => 'Copier la commande';

  @override
  String get cfgBrowse => 'Parcourir…';

  @override
  String cfgPickFiltered(String filter) {
    return 'Type filtré ($filter)';
  }

  @override
  String get cfgPickAny => 'Tous les fichiers';

  @override
  String get cfgPickDirRecursive => 'Dossier (scan récursif)';

  @override
  String get cfgFilesToGenerate => 'Fichiers qui seront générés :';

  @override
  String get cfgProfDeleteTitle => 'Supprimer le profil';

  @override
  String cfgProfDeleteConfirm(String name) {
    return 'Supprimer « $name » ?';
  }

  @override
  String get cfgDelete => 'Supprimer';

  @override
  String get cfgProfTitle => 'Profils de configuration';

  @override
  String get cfgProfSaveCurrent => 'Enregistrer la configuration actuelle';

  @override
  String get cfgProfNameHint => 'Nom du profil…';

  @override
  String get cfgProfSave => 'Enregistrer';

  @override
  String get cfgProfSaved => 'Profils enregistrés';

  @override
  String get cfgProfNone => 'Aucun profil enregistré.';

  @override
  String get cfgProfLoad => 'Charger';

  @override
  String get cfgOciLabel => 'Image OCI (--image)';

  @override
  String get cfgOciHelp =>
      'Référence d\'une image conteneur à analyser.\n• Registre : nginx:latest, ghcr.io/org/app:v1\n• Archive tar : ./image.tar / .tar.gz / .tgz (docker save)\n• Répertoire OCI layout : ./oci/ (index.json)';

  @override
  String get cfgOciHint => 'nginx:latest  •  ./image.tar(.gz)  •  ./oci_dir/';

  @override
  String get cfgOciTar => 'Archive tar (.tar / .tar.gz / .tgz)';

  @override
  String get cfgOciDir => 'Répertoire OCI layout';

  @override
  String get cfgBinaryLabel => 'Binaire autonome (--binary)';

  @override
  String get cfgBinaryHelp =>
      'Exécutable local à analyser directement (pas une image de conteneur) — ex. un binaire Go lié statiquement.\nForce le backend syft : seul capable de lire les métadonnées embarquées dans un binaire (buildinfo Go via go-module-binary-cataloger ; classifieur générique syft pour quelques bibliothèques connues — OpenSSL, zlib, sqlite…).\nNe récupère pas les dépendances liées statiquement sans métadonnée embarquée (C/C++ « fait maison », Rust sans cargo-auditable).';

  @override
  String get cfgBinaryHint => '/usr/local/bin/mon-app';

  @override
  String get cfgDepthLabel => 'Profondeur (--depth)';

  @override
  String get cfgDepthHelp =>
      'Descend dans les objets contenus dans l\'entrée : par exemple les jars d\'un RPM, les paquets ou archives d\'un tar.gz, les jars d\'un fat jar.\n• 0 : l\'objet seul (défaut)\n• N : N niveaux (1 = objets directs, 2 = ce qu\'ils contiennent…)\n• Illimitée : tous les niveaux (plafonnés à 10)\nLes manifestes rencontrés (package-lock.json, go.sum, pom.xml…) sont analysés. Le SBOM global fusionne tous les composants (propriétés location/depth, dépendances parent → enfant). Extraction bornée en taille.';

  @override
  String get cfgDepth0 => '0 — objet seul';

  @override
  String get cfgDepthAll => 'Illimitée';

  @override
  String get cfgDepth1 => '1 niveau';

  @override
  String cfgDepthN(String n) {
    return '$n niveaux';
  }

  @override
  String get cfgNestedFiles => 'Un SBOM par objet imbriqué';

  @override
  String get cfgNestedFilesHelp =>
      'En plus du SBOM fusionné, écrit un SBOM par objet imbriqué (<sortie>.nested-NN-<objet>.<ext>, dans chaque format coché). Décocher = --no-nested-files : fusionné seulement.';

  @override
  String get cfgPerLayer => 'Un SBOM par couche (--per-layer)';

  @override
  String get cfgPerLayerHelp =>
      'Génère, en plus du SBOM global, un SBOM par couche de l\'image (<sortie>.layer-NN-<digest>.<ext>, dans chaque format coché) décrivant le delta de la couche : composants ajoutés ou modifiés, composants supprimés listés à part. Le SBOM global indique la couche d\'origine de chaque composant.\n• Métadonnées : couche d\'origine indiquée par Syft/Trivy — rapide, ajouts seulement\n• Rootfs : couches appliquées une à une et réanalysées — ajouts, modifications, suppressions (seul mode possible avec Skopeo et cdxgen)';

  @override
  String get cfgLayerMetadata => 'Métadonnées';

  @override
  String get cfgLayerMetadataTip => 'Couche d\'origine indiquée par le backend';

  @override
  String get cfgLayerRootfs => 'Rootfs';

  @override
  String get cfgLayerRootfsTip => 'Réanalyse du rootfs après chaque couche';

  @override
  String cfgRootfsForced(String tool) {
    return 'Mode rootfs forcé : $tool n\'indique pas la couche d\'origine des paquets';
  }

  @override
  String get cfgOciToolLabel => 'Backend OCI (--oci-tool)';

  @override
  String get cfgOciToolHelp =>
      'Outil utilisé pour extraire les paquets de l\'image :\n• Syft (Anchore) — le plus complet, tous écosystèmes\n• Trivy (Aqua) — rapide, CVE intégrées\n• Skopeo — extraction manuelle dpkg/rpm/apk\n• cdxgen (OWASP) — CycloneDX natif, tous écosystèmes';

  @override
  String get cfgSyftTip => 'Anchore Syft — tous écosystèmes';

  @override
  String get cfgTrivyTip => 'Aqua Trivy — tous écosystèmes';

  @override
  String get cfgSkopeoTip => 'Skopeo + extraction manuelle (dpkg/rpm/apk)';

  @override
  String get cfgCdxgenTip => 'OWASP cdxgen — CycloneDX natif, tous écosystèmes';

  @override
  String get cfgSyftDesc => 'Syft (recommandé) — supporte tous les écosystèmes';

  @override
  String get cfgTrivyDesc =>
      'Trivy — tous écosystèmes, déjà utilisé pour les CVE';

  @override
  String get cfgSkopeoDesc => 'Skopeo — extraction manuelle dpkg / rpm / apk';

  @override
  String get cfgCdxgenDesc =>
      'cdxgen — SBOM CycloneDX natif, tous écosystèmes (nécessite Node.js)';

  @override
  String get cfgCdxVersion => 'Version (--cyclonedx-version)';

  @override
  String get cfgCdxVersionHelp =>
      '1.6 — la plus répandue chez les consommateurs actuels (défaut).\n1.7 — ajoute citations / patentAssertions / distributionConstraints\n(voir --tlp et --patent-map en ligne de commande).';

  @override
  String get cfgLegendAccepted =>
      'Types acceptés (fichier liste, paquet unique, ou dossier scanné) :';

  @override
  String get cfgLegRpmInstalled => 'RPM installé';

  @override
  String get cfgLegRpmFile => 'Fichier .rpm';

  @override
  String get cfgLegWheel => 'Wheel Python';

  @override
  String get cfgLegTar => 'Archive tar';

  @override
  String get cfgLegZip => 'Archive .zip';

  @override
  String get cfgLegDeb => 'Paquet Debian';

  @override
  String get cfgLegJar => 'Archive Java';

  @override
  String get cfgLegManifest => 'Manifeste/lock';

  @override
  String get cfgLegendImage => 'Image OCI (champ --image) :';

  @override
  String get cfgLegRegistry => 'Registre';

  @override
  String get cfgLegOciLayout => 'OCI layout';

  @override
  String get cfgLegOciLayoutVal => '/path/oci_dir/  (index.json présent)';

  @override
  String get cfgLegendBinary => 'Binaire autonome (champ --binary) :';

  @override
  String get cfgLegendBinaryText =>
      'Exécutable local (ex. binaire Go lié statiquement) — force le backend syft. Dépendances Go embarquées lues systématiquement ; seul un catalogue fixe de bibliothèques connues (OpenSSL, zlib, sqlite…) est détecté pour les autres langages.';

  @override
  String get cfgLegOr => 'ou';

  @override
  String get qualitySbomqsNoResult => 'Aucun résultat retourné par sbomqs';

  @override
  String get formatJsonCustom => 'JSON personnalisé';

  @override
  String get helpTitle => 'Aide — Manuel utilisateur';

  @override
  String get helpSearchHint => 'Rechercher dans le manuel…';

  @override
  String get helpClear => 'Effacer';

  @override
  String helpNoMatch(String query) {
    return 'Aucun chapitre ne contient « $query ».';
  }

  @override
  String helpLoadError(String error) {
    return 'Aide indisponible : impossible de charger le manuel ($error).';
  }

  @override
  String vrTitle(String tool) {
    return '= Rapport de vulnérabilités: $tool';
  }

  @override
  String vrScannerLine(String tool, int count, String filtered) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '*$countString* vulnérabilités',
      one: '*$countString* vulnérabilité',
    );
    return '*Scanner* : $tool — $_temp0$filtered';
  }

  @override
  String get vrAfterDateFilter => ' après filtre de date';

  @override
  String get vrStatsHeader => 'h| Critiques h| Élevées h| CISA KEV h| Total';

  @override
  String vrDateNote(String summary) {
    return 'NOTE: Filtre de date appliqué — $summary.';
  }

  @override
  String get vrDetail => '== Détail';

  @override
  String vrLayerMethod(String mode, String extra) {
    return 'Méthode : $mode$extra.';
  }

  @override
  String vrLayerUnattr(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString vulnérabilités sans couche connue',
      one: '$countString vulnérabilité sans couche connue',
    );
    return ' — $_temp0';
  }

  @override
  String get vrLayersHeader =>
      '| Couche | Digest | Instruction | Vulnérabilités | Critiques | Élevées';

  @override
  String get vrLayersCol => 'Couche(s)';

  @override
  String get vrDatePublished => 'publication';

  @override
  String get vrDateModified => 'dernière modification';

  @override
  String get vrDateLatest => 'plus récente des deux';

  @override
  String vrDateAfter(String date) {
    return 'après $date';
  }

  @override
  String vrDateBefore(String date) {
    return 'avant $date';
  }

  @override
  String get vrDateNoBound => 'aucune borne';

  @override
  String get vrDateUndated => ', dont sans date connue';

  @override
  String get remedTitle => 'Remédiation : quoi mettre à jour';

  @override
  String remedSubtitle(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString paquets à mettre à jour',
      one: '1 paquet à mettre à jour',
    );
    return '$_temp0, classés par gain de risque (sévérité, exploitation active KEV, EPSS).';
  }

  @override
  String remedUpgrade(String pkg, String from, String to) {
    return '$pkg $from → $to';
  }

  @override
  String remedNoFixTitle(String pkg, String from) {
    return '$pkg $from — aucun correctif connu';
  }

  @override
  String remedFixes(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString CVE corrigées',
      one: '1 CVE corrigée',
    );
    return '$_temp0';
  }

  @override
  String remedKev(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '$countString exploitée(s) (KEV)';
  }

  @override
  String remedRemaining(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString CVE resteront sans correctif',
      one: '1 CVE restera sans correctif',
    );
    return '$_temp0';
  }

  @override
  String remedGain(String gain) {
    return 'Gain de risque : $gain';
  }

  @override
  String remedShowAll(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return 'Afficher les $countString paquets';
  }

  @override
  String get remedShowLess => 'Réduire la liste';

  @override
  String get remedExportCsv => 'Exporter en CSV';

  @override
  String get remedCopyCommand => 'Copier la liste';

  @override
  String get remedCopied => 'Plan de remédiation copié';

  @override
  String get remedCsvDialog => 'Exporter le plan de remédiation';

  @override
  String get remedCsvHeader =>
      'paquet,version installée,version cible,CVE corrigées,dont KEV,CVE sans correctif,gain de risque';

  @override
  String remedCsvSaved(String path) {
    return 'Plan de remédiation exporté → $path';
  }

  @override
  String get remedHelpNote =>
      'Heuristique : la version cible est la plus petite qui corrige toutes les CVE corrigeables du paquet ; vérifiez-la avec votre gestionnaire de paquets.';

  @override
  String get sessSave => 'Enregistrer la session…';

  @override
  String get sessOpen => 'Ouvrir une session…';

  @override
  String get sessHistory => 'Historique';

  @override
  String get sessNothingToSave => 'Aucun résultat de scan à enregistrer.';

  @override
  String get sessDialogSave => 'Enregistrer la session';

  @override
  String get sessDialogOpen => 'Ouvrir une session';

  @override
  String sessSaved(String path) {
    return 'Session enregistrée → $path';
  }

  @override
  String sessLoaded(String date) {
    return 'Session du $date chargée dans le tableau de bord';
  }

  @override
  String sessInvalid(String error) {
    return 'Fichier de session illisible : $error';
  }

  @override
  String get sessHistoryTitle => 'Historique des analyses';

  @override
  String get sessHistoryEmpty =>
      'Aucune analyse enregistrée. Les résultats des scans sont conservés automatiquement (une entrée par cible et par jour).';

  @override
  String sessHistoryItem(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '$countString CVE';
  }

  @override
  String get sessOpenAction => 'Ouvrir';

  @override
  String get sessCompareAction => 'Comparer';

  @override
  String get sessDeleteAction => 'Supprimer';

  @override
  String get sessClearHistory => 'Vider l\'historique';

  @override
  String get sessClearConfirm => 'Supprimer toutes les analyses enregistrées ?';

  @override
  String sessTrendTitle(String date) {
    return 'Tendance depuis le $date';
  }

  @override
  String sessTrendNew(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '$countString nouvelle(s)';
  }

  @override
  String sessTrendFixed(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '$countString disparue(s)';
  }

  @override
  String sessTrendSame(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '$countString inchangée(s)';
  }

  @override
  String sessTrendTotals(int before, int after) {
    final intl.NumberFormat beforeNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String beforeString = beforeNumberFormat.format(before);
    final intl.NumberFormat afterNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String afterString = afterNumberFormat.format(after);

    return 'Total : $beforeString → $afterString';
  }

  @override
  String get sessTrendNewList => 'Nouvelles :';

  @override
  String get sessTrendClear => 'Retirer la comparaison';

  @override
  String get sessTrendNone => 'Aucune différence avec la session de référence.';

  @override
  String get tabTasks => 'Tâches';

  @override
  String get tasksIntro =>
      'Mettez en file des analyses de vulnérabilités : elles s\'exécutent une à une, peuvent être annulées ou relancées, et leurs résultats alimentent le tableau de bord.';

  @override
  String get tasksTargetLabel => 'SBOM à analyser';

  @override
  String get tasksTargetNone => 'Aucun SBOM sélectionné';

  @override
  String get tasksBrowse => 'Parcourir…';

  @override
  String get tasksPickDialog => 'Choisir un SBOM à analyser';

  @override
  String get tasksEnqueue => 'Ajouter à la file';

  @override
  String get tasksNeedTarget => 'Choisissez d\'abord un SBOM.';

  @override
  String get tasksNeedScanner => 'Cochez au moins un scanner.';

  @override
  String get tasksEmpty => 'Aucune analyse en file.';

  @override
  String get tasksCancelAll => 'Tout annuler';

  @override
  String get tasksClearFinished => 'Retirer les terminées';

  @override
  String get tasksStatusQueued => 'En attente';

  @override
  String get tasksStatusRunning => 'En cours…';

  @override
  String tasksStatusDone(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString vulnérabilités',
      one: '$countString vulnérabilité',
    );
    return 'Terminée — $_temp0';
  }

  @override
  String tasksStatusFailed(String error) {
    return 'Échec : $error';
  }

  @override
  String get tasksStatusCancelled => 'Annulée';

  @override
  String tasksDuration(int seconds) {
    final intl.NumberFormat secondsNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String secondsString = secondsNumberFormat.format(seconds);

    return '$secondsString s';
  }

  @override
  String get tasksCancel => 'Annuler';

  @override
  String get tasksRetry => 'Relancer';

  @override
  String get tasksRemove => 'Retirer de la liste';

  @override
  String tasksToolMissing(String tool) {
    return '$tool introuvable (installez-le ou retirez-le de la sélection).';
  }

  @override
  String tasksNoOutput(String tool, int code, String detail) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return '$tool n\'a produit aucun résultat (code $codeString) : $detail';
  }

  @override
  String tasksParseFailed(String tool, String error) {
    return 'Sortie de $tool illisible : $error';
  }

  @override
  String get vexDeclare => 'Déclarer via VEX…';

  @override
  String get vexEdit => 'Modifier';

  @override
  String get vexRemove => 'Retirer';

  @override
  String vexCurrent(String status, String detail) {
    return 'VEX : $status$detail';
  }

  @override
  String get vexStatusNotAffected => 'non affectée';

  @override
  String get vexStatusAffected => 'affectée';

  @override
  String get vexStatusFixed => 'corrigée';

  @override
  String get vexStatusInvestigation => 'à l\'étude';

  @override
  String get vexJustComponentNotPresent => 'composant absent';

  @override
  String get vexJustCodeNotPresent => 'code vulnérable absent';

  @override
  String get vexJustNotInExecutePath => 'code vulnérable jamais exécuté';

  @override
  String get vexJustCannotBeControlled =>
      'code non contrôlable par un attaquant';

  @override
  String get vexJustInlineMitigations => 'mesures d\'atténuation déjà en place';

  @override
  String vexDialogTitle(String id) {
    return 'Déclaration VEX — $id';
  }

  @override
  String get vexFieldStatus => 'État';

  @override
  String get vexFieldJustification => 'Justification';

  @override
  String get vexFieldImpact => 'Explication (facultative)';

  @override
  String get vexFieldScope => 'Portée';

  @override
  String get vexScopeAll => 'Tous les paquets';

  @override
  String get vexNeedJustification =>
      'Une justification est requise pour « non affectée ».';

  @override
  String get vexSave => 'Enregistrer';

  @override
  String vexBarSummary(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$countString déclarations',
      one: '$countString déclaration',
    );
    return 'VEX : $_temp0';
  }

  @override
  String vexHideSuppressed(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return 'Masquer les CVE couvertes par un VEX ($countString)';
  }

  @override
  String get vexImport => 'Importer un VEX…';

  @override
  String get vexExport => 'Exporter';

  @override
  String get vexExportOpenVex => 'OpenVEX (.json)';

  @override
  String get vexExportCdx => 'CycloneDX VEX (.json)';

  @override
  String get vexManage => 'Gérer';

  @override
  String get vexManageTitle => 'Déclarations VEX';

  @override
  String get vexDialogImport => 'Importer un document VEX';

  @override
  String get vexDialogExport => 'Exporter les déclarations VEX';

  @override
  String vexImported(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '$countString déclaration(s) VEX importée(s)';
  }

  @override
  String vexExported(String path) {
    return 'VEX exporté → $path';
  }

  @override
  String vexInvalid(String error) {
    return 'Document VEX illisible : $error';
  }

  @override
  String get vexNothingToExport => 'Aucune déclaration VEX à exporter.';

  @override
  String get vexClearAll => 'Tout retirer';

  @override
  String get vexAnyPackage => 'tous les paquets';

  @override
  String get shortcutsTooltip => 'Raccourcis clavier';

  @override
  String get shortcutsTitle => 'Raccourcis clavier';

  @override
  String get shortcutRun => 'Lancer la génération';

  @override
  String get shortcutStop => 'Arrêter l\'exécution en cours';

  @override
  String get shortcutTabs => 'Aller à l\'onglet 1 à 9';

  @override
  String get shortcutNextTab => 'Onglet suivant / précédent';

  @override
  String get shortcutHelp => 'Ouvrir l\'aide';

  @override
  String get shortcutShortcuts => 'Afficher cette liste';

  @override
  String get shortcutNavigate =>
      'Parcourir : Tab / flèches ; ouvrir une ligne : Entrée ou Espace';

  @override
  String helpHitCount(int current, int total) {
    final intl.NumberFormat currentNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String currentString = currentNumberFormat.format(current);
    final intl.NumberFormat totalNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String totalString = totalNumberFormat.format(total);

    return 'Occurrence $currentString sur $totalString';
  }

  @override
  String get helpHitNone => 'Aucune occurrence dans ce chapitre';

  @override
  String get helpPrevHit => 'Occurrence précédente (Maj+F3)';

  @override
  String get helpNextHit => 'Occurrence suivante (F3 / Entrée)';

  @override
  String dashExportCliFailed(int code, String error) {
    final intl.NumberFormat codeNumberFormat = intl.NumberFormat.decimalPattern(
      localeName,
    );
    final String codeString = codeNumberFormat.format(code);

    return 'Échec de l\'export du rapport (code $codeString) : $error';
  }

  @override
  String dashExportCliMissing(String path) {
    return 'Impossible de lancer sbom-generator ($path) : le rapport est produit par le CLI.';
  }

  @override
  String remedMoreCves(int count) {
    final intl.NumberFormat countNumberFormat =
        intl.NumberFormat.decimalPattern(localeName);
    final String countString = countNumberFormat.format(count);

    return '… et $countString autre(s) CVE (voir l\'export CSV ou le détail ci-dessus)';
  }
}
