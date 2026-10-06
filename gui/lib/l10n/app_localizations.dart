import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_en.dart';
import 'app_localizations_fr.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
    : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations? of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations);
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
        delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('en'),
    Locale('fr'),
  ];

  /// Info-bulle du menu de choix de langue (barre d'application).
  ///
  /// In fr, this message translates to:
  /// **'Langue de l\'interface'**
  String get languageMenuTooltip;

  /// Choix de langue : suivre la langue du système.
  ///
  /// In fr, this message translates to:
  /// **'Système'**
  String get languageSystem;

  /// Nom de la langue française, toujours écrit en français.
  ///
  /// In fr, this message translates to:
  /// **'Français'**
  String get languageFrench;

  /// Nom de la langue anglaise, toujours écrit en anglais.
  ///
  /// In fr, this message translates to:
  /// **'English'**
  String get languageEnglish;

  /// Info-bulle / action : copier dans le presse-papiers.
  ///
  /// In fr, this message translates to:
  /// **'Copier'**
  String get commonCopy;

  /// Bouton de fermeture d'un dialogue.
  ///
  /// In fr, this message translates to:
  /// **'Fermer'**
  String get commonClose;

  /// Bouton d'arrêt d'une analyse en cours.
  ///
  /// In fr, this message translates to:
  /// **'Stop'**
  String get commonStop;

  /// Bouton de lancement d'une analyse.
  ///
  /// In fr, this message translates to:
  /// **'Analyser'**
  String get commonAnalyze;

  /// Bouton ouvrant le menu de sélection de fichier.
  ///
  /// In fr, this message translates to:
  /// **'Choisir'**
  String get commonBrowse;

  /// Menu de sélection de fichier : ne montrer que les extensions attendues.
  ///
  /// In fr, this message translates to:
  /// **'Type filtré ({filter})'**
  String commonPickFiltered(String filter);

  /// Menu de sélection de fichier : aucun filtre d'extension.
  ///
  /// In fr, this message translates to:
  /// **'Tous les fichiers'**
  String get commonPickAllFiles;

  /// Erreur : le fichier ou répertoire indiqué n'existe pas.
  ///
  /// In fr, this message translates to:
  /// **'Fichier introuvable : {path}'**
  String commonFileNotFound(String path);

  /// Valeur vide d'une liste déroulante (masculin).
  ///
  /// In fr, this message translates to:
  /// **'(aucun)'**
  String get commonNone;

  /// Valeur vide d'une liste déroulante (féminin, ex. distribution).
  ///
  /// In fr, this message translates to:
  /// **'(aucune)'**
  String get commonNoneFeminine;

  /// Libellé du champ de plateforme d'image (ex. linux/arm64).
  ///
  /// In fr, this message translates to:
  /// **'Plateforme'**
  String get commonPlatform;

  /// Exemple affiché dans le champ de plateforme.
  ///
  /// In fr, this message translates to:
  /// **'linux/amd64, linux/arm64…'**
  String get commonPlatformHint;

  /// Exemple affiché dans le champ de fichier SBOM.
  ///
  /// In fr, this message translates to:
  /// **'chemin/vers/sbom.cdx.json'**
  String get commonSbomFileHint;

  /// Vue JSON brut vide.
  ///
  /// In fr, this message translates to:
  /// **'Pas de sortie JSON.'**
  String get jsonViewEmpty;

  /// Info-bulle du bouton de copie de la vue JSON.
  ///
  /// In fr, this message translates to:
  /// **'Copier le JSON'**
  String get jsonViewCopyTooltip;

  /// Confirmation de copie du JSON.
  ///
  /// In fr, this message translates to:
  /// **'JSON copié'**
  String get jsonViewCopied;

  /// Bascule de source d'analyse : fichier SBOM (aussi libellé du champ).
  ///
  /// In fr, this message translates to:
  /// **'Fichier SBOM'**
  String get scanSourceSbom;

  /// Bascule de source d'analyse : image de conteneur (aussi libellé du champ).
  ///
  /// In fr, this message translates to:
  /// **'Image de conteneur'**
  String get scanSourceImage;

  /// Aide du champ image ; ociDirLine = scanSourceImageHelpOciDir ou vide.
  ///
  /// In fr, this message translates to:
  /// **'Référence d\'une image à analyser directement, sans\npasser par un fichier SBOM :\n• Registre : nginx:latest, ghcr.io/org/app:tag\n• Archive : ./image.tar(.gz) (docker save)\n{ociDirLine}Un registre privé est résolu via la configuration\nDocker locale (docker login), sans champ dédié ici.'**
  String scanSourceImageHelp(String ociDirLine);

  /// Ligne d'aide optionnelle (répertoire OCI layout), terminée par un saut de ligne.
  ///
  /// In fr, this message translates to:
  /// **'• Répertoire OCI layout : ./oci_dir/\n'**
  String get scanSourceImageHelpOciDir;

  /// Info-bulle du bouton de choix d'archive d'image.
  ///
  /// In fr, this message translates to:
  /// **'Choisir une archive (.tar, .tar.gz, .tgz)'**
  String get scanSourcePickArchive;

  /// Info-bulle / titre du sélecteur de répertoire OCI layout.
  ///
  /// In fr, this message translates to:
  /// **'Choisir un répertoire OCI layout'**
  String get scanSourcePickOciDir;

  /// Erreur : aucune image saisie.
  ///
  /// In fr, this message translates to:
  /// **'Veuillez indiquer une image à analyser.'**
  String get scanSourceMissingImage;

  /// Erreur : aucun fichier SBOM choisi.
  ///
  /// In fr, this message translates to:
  /// **'Veuillez sélectionner un fichier SBOM.'**
  String get scanSourceMissingSbom;

  /// Titre du sélecteur de fichier SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Choisir un fichier SBOM'**
  String get scanPickSbomTitle;

  /// Titre du sélecteur d'archive d'image.
  ///
  /// In fr, this message translates to:
  /// **'Choisir une archive image (docker save / OCI)'**
  String get scanPickImageArchiveTitle;

  /// Erreur de lecture de la sortie JSON d'un scanner.
  ///
  /// In fr, this message translates to:
  /// **'Sortie {tool} illisible (JSON invalide) : {error}'**
  String scanUnreadableOutput(String tool, String error);

  /// Message du tableau quand la sortie du scanner est illisible.
  ///
  /// In fr, this message translates to:
  /// **'Sortie {tool} illisible : voir le message d\'erreur ci-dessus'**
  String scanUnreadableOutputShort(String tool);

  /// Aucune vulnérabilité trouvée.
  ///
  /// In fr, this message translates to:
  /// **'Aucune vulnérabilité détectée'**
  String get scanNoVulnerabilities;

  /// Bannière de résultat : total et détail par sévérité (ex. « 2 High, 1 Low »).
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, =1{1 vulnérabilité : {details}} other{{count} vulnérabilités : {details}}}'**
  String scanSummary(int count, String details);

  /// Titre du dialogue d'export CSV.
  ///
  /// In fr, this message translates to:
  /// **'Exporter les vulnérabilités {tool}'**
  String scanExportCsvDialog(String tool);

  /// Case d'activation de l'analyse par couche.
  ///
  /// In fr, this message translates to:
  /// **'Par couche'**
  String get layerScanCheckbox;

  /// Aide de l'option d'analyse par couche.
  ///
  /// In fr, this message translates to:
  /// **'Attribue chaque vulnérabilité à la couche de l\'image qui\napporte le paquet vulnérable (SBOM par couche générés par\nsbom-generator --per-layer, via syft).\n• Rattachement : un seul scan de l\'image, chaque CVE\n  rattachée à la couche d\'origine de son paquet — CVE de\n  l\'image finale uniquement.\n• Chaque couche : le SBOM de chaque couche est scanné —\n  inclut les CVE d\'une version remplacée plus haut dans la\n  pile (avec le calcul Rootfs).\n• Métadonnées / Rootfs : calcul des couches (--layer-mode).'**
  String get layerScanHelp;

  /// Méthode : un scan, CVE rattachées à la couche d'origine du paquet.
  ///
  /// In fr, this message translates to:
  /// **'Rattachement'**
  String get layerScanAttribute;

  /// Info-bulle de la méthode Rattachement.
  ///
  /// In fr, this message translates to:
  /// **'Un scan de l\'image, CVE rattachées à la couche d\'origine du paquet'**
  String get layerScanAttributeTooltip;

  /// Méthode : un scan par SBOM de couche.
  ///
  /// In fr, this message translates to:
  /// **'Chaque couche'**
  String get layerScanEach;

  /// Info-bulle de la méthode Chaque couche.
  ///
  /// In fr, this message translates to:
  /// **'Un scan par SBOM de couche'**
  String get layerScanEachTooltip;

  /// Calcul des couches : couche d'origine indiquée par syft.
  ///
  /// In fr, this message translates to:
  /// **'Métadonnées'**
  String get layerModeMetadata;

  /// Info-bulle du calcul Métadonnées.
  ///
  /// In fr, this message translates to:
  /// **'Couche d\'origine indiquée par syft — ajouts'**
  String get layerModeMetadataTooltip;

  /// Calcul des couches : réanalyse après chaque couche.
  ///
  /// In fr, this message translates to:
  /// **'Rootfs'**
  String get layerModeRootfs;

  /// Info-bulle du calcul Rootfs.
  ///
  /// In fr, this message translates to:
  /// **'Réanalyse après chaque couche — ajouts, modifications, suppressions'**
  String get layerModeRootfsTooltip;

  /// Bouton ouvrant le popup des lignes de commande.
  ///
  /// In fr, this message translates to:
  /// **'CLI Commande'**
  String get cliCommandButton;

  /// Titre du popup des lignes de commande.
  ///
  /// In fr, this message translates to:
  /// **'Ligne de commande'**
  String get cliCommandDialogTitle;

  /// Confirmation de copie d'une commande.
  ///
  /// In fr, this message translates to:
  /// **'Commande copiée'**
  String get cliCommandCopied;

  /// Titre : commande native exécutée.
  ///
  /// In fr, this message translates to:
  /// **'Commande exécutée par l\'onglet'**
  String get cliCommandExecuted;

  /// Note de l'aperçu CLI Commande d'OSV-Scanner pour une archive d'image compressée
  ///
  /// In fr, this message translates to:
  /// **'osv-scanner n\'accepte qu\'un tar non compressé : l\'application décompresse d\'abord l\'archive .tar.gz / .tgz vers un fichier temporaire (équivalent : gunzip -c archive.tar.gz > image.tar), le passe à osv-scanner puis le supprime.'**
  String get cliOsvGunzipNote;

  /// Titre : séquence de commandes de l'analyse par couche.
  ///
  /// In fr, this message translates to:
  /// **'Commandes exécutées par l\'onglet (analyse par couche)'**
  String get cliCommandExecutedLayered;

  /// Titre : commande sbom-generator équivalente.
  ///
  /// In fr, this message translates to:
  /// **'Équivalent sbom-generator scan'**
  String get cliCommandEquivalent;

  /// Remarque sur le répertoire temporaire des SBOM de couche.
  ///
  /// In fr, this message translates to:
  /// **'Le jeu de SBOM par couche est généré dans un répertoire temporaire (ici {dir}).'**
  String cliCommandLayerDirNote(String dir);

  /// Remarque : différence de cible avec --image.
  ///
  /// In fr, this message translates to:
  /// **'Avec --image, sbom-generator scanne le SBOM CycloneDX généré (syft), pas l\'image directement.'**
  String get cliCommandImageNote;

  /// Remarque : options de l'onglet sans équivalent CLI.
  ///
  /// In fr, this message translates to:
  /// **'Non transposable : {options}.'**
  String cliCommandNotCarried(String options);

  /// Nom d'option dans la liste des options non transposables.
  ///
  /// In fr, this message translates to:
  /// **'plateforme'**
  String get cliOptionPlatform;

  /// Libellé de la barre de filtres de sévérité.
  ///
  /// In fr, this message translates to:
  /// **'Filtre :'**
  String get vulnTableFilter;

  /// Puce réinitialisant les filtres.
  ///
  /// In fr, this message translates to:
  /// **'Tout voir'**
  String get vulnTableShowAll;

  /// Puce de filtre CISA KEV.
  ///
  /// In fr, this message translates to:
  /// **'CISA KEV ({count})'**
  String vulnTableKevChip(int count);

  /// Champ de recherche du tableau.
  ///
  /// In fr, this message translates to:
  /// **'Paquet ou CVE…'**
  String get vulnTableSearchHint;

  /// Info-bulle du bouton d'enrichissement (état en ligne).
  ///
  /// In fr, this message translates to:
  /// **'Enrichissement en ligne actif (CISA KEV / EPSS / poc-in-github) — cliquer pour passer hors-ligne'**
  String get vulnTableEnrichOnline;

  /// Info-bulle du bouton d'enrichissement (état hors-ligne).
  ///
  /// In fr, this message translates to:
  /// **'Enrichissement hors-ligne (Grype + cache local seulement) — cliquer pour réactiver le réseau'**
  String get vulnTableEnrichOffline;

  /// Info-bulle du bouton d'export CSV.
  ///
  /// In fr, this message translates to:
  /// **'Exporter CSV'**
  String get vulnTableExportCsv;

  /// Info-bulle du bouton d'export AsciiDoc + PDF.
  ///
  /// In fr, this message translates to:
  /// **'Exporter en AsciiDoc + PDF'**
  String get vulnTableExportPdf;

  /// Titre du dialogue d'export AsciiDoc + PDF.
  ///
  /// In fr, this message translates to:
  /// **'Exporter le rapport {tool} (AsciiDoc + PDF)'**
  String vulnTableExportPdfDialog(String tool);

  /// Confirmation d'export.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, =1{1 vulnérabilité exportée → {path}} other{{count} vulnérabilités exportées → {path}}}'**
  String vulnTableExported(int count, String path);

  /// Confirmation d'export AsciiDoc + PDF.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, =1{1 vulnérabilité exportée → {path} et {pdf}} other{{count} vulnérabilités exportées → {path} et {pdf}}}'**
  String vulnTableExportedPdf(int count, String path, String pdf);

  /// Export AsciiDoc réussi, conversion PDF en échec.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, =1{1 vulnérabilité exportée → {path} (échec conversion PDF, code {code})} other{{count} vulnérabilités exportées → {path} (échec conversion PDF, code {code})}}'**
  String vulnTableExportedPdfFailed(int count, String path, int code);

  /// Export AsciiDoc réussi, asciidoctor-pdf absent.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, =1{1 vulnérabilité exportée → {path} (asciidoctor-pdf introuvable, PDF non généré)} other{{count} vulnérabilités exportées → {path} (asciidoctor-pdf introuvable, PDF non généré)}}'**
  String vulnTableExportedNoPdf(int count, String path);

  /// En-tête de colonne (majuscules).
  ///
  /// In fr, this message translates to:
  /// **'SÉVÉRITÉ'**
  String get vulnTableColSeverity;

  /// En-tête de colonne (majuscules).
  ///
  /// In fr, this message translates to:
  /// **'CVE / ID'**
  String get vulnTableColId;

  /// En-tête de colonne (majuscules).
  ///
  /// In fr, this message translates to:
  /// **'PAQUET'**
  String get vulnTableColPackage;

  /// En-tête de colonne (majuscules).
  ///
  /// In fr, this message translates to:
  /// **'COUCHE'**
  String get vulnTableColLayer;

  /// Bandeau : vulnérabilités sans couche connue.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, =1{1 vulnérabilité sans couche connue (paquet absent du SBOM de l\'image) — colonne « ? ».} other{{count} vulnérabilités sans couche connue (paquet absent du SBOM de l\'image) — colonne « ? ».}}'**
  String vulnTableUnattributed(int count);

  /// Bandeau pendant l'enrichissement.
  ///
  /// In fr, this message translates to:
  /// **'Enrichissement en ligne (CISA KEV / EPSS / PoC) en cours…'**
  String get vulnTableEnrichPending;

  /// Aucune ligne pour la recherche.
  ///
  /// In fr, this message translates to:
  /// **'Aucun résultat pour \"{term}\"'**
  String vulnTableNoMatchSearch(String term);

  /// Aucune ligne pour les filtres de sévérité.
  ///
  /// In fr, this message translates to:
  /// **'Aucun résultat pour {filters}'**
  String vulnTableNoMatchFilter(String filters);

  /// Info-bulle du badge ×N d'occurrences fusionnées.
  ///
  /// In fr, this message translates to:
  /// **'Ce composant est présent à {count} emplacements distincts de l\'image/du SBOM (ex. une bibliothèque autonome et une copie embarquée dans un autre paquet) — la même vulnérabilité y a été fusionnée en une seule ligne.'**
  String vulnTableOccurrences(int count);

  /// Ligne sans signal KEV/EPSS/PoC.
  ///
  /// In fr, this message translates to:
  /// **'aucun signal d\'exploitation'**
  String get vulnTableNoExploitSignal;

  /// Info-bulle du badge KEV ; added/ransomware = compléments optionnels.
  ///
  /// In fr, this message translates to:
  /// **'CISA KEV — exploitée activement dans la nature{added}{ransomware}'**
  String vulnTableKevTooltip(String added, String ransomware);

  /// Complément : date d'ajout au catalogue KEV.
  ///
  /// In fr, this message translates to:
  /// **' (ajoutée le {date})'**
  String vulnTableKevAdded(String date);

  /// Complément : usage par rançongiciel.
  ///
  /// In fr, this message translates to:
  /// **' · usage par rançongiciel'**
  String get vulnTableKevRansomware;

  /// Info-bulle du badge EPSS.
  ///
  /// In fr, this message translates to:
  /// **'EPSS — probabilité d\'exploitation à 30 jours (percentile {percentile})'**
  String vulnTableEpssTooltip(int percentile);

  /// Info-bulle du badge PoC (nombre de dépôts).
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, =1{1 dépôt PoC public recensé} other{{count} dépôts PoC publics recensés}}'**
  String vulnTablePocRepos(int count);

  /// Info-bulle du badge PoC (maturité CVSS).
  ///
  /// In fr, this message translates to:
  /// **'Maturité de l\'exploit : {maturity}'**
  String vulnTablePocMaturity(String maturity);

  /// Info-bulle du badge d'exploitabilité ; maturity = complément optionnel.
  ///
  /// In fr, this message translates to:
  /// **'Sous-score d\'exploitabilité CVSS (AV/AC/PR/UI){maturity}'**
  String vulnTableExploitabilityTooltip(String maturity);

  /// Complément : maturité de l'exploit.
  ///
  /// In fr, this message translates to:
  /// **' · maturité {maturity}'**
  String vulnTableExploitabilityMaturity(String maturity);

  /// Menu de filtre par couche : aucune couche sélectionnée.
  ///
  /// In fr, this message translates to:
  /// **'Toutes les couches'**
  String get vulnTableAllLayers;

  /// Entrée du menu de filtre par couche.
  ///
  /// In fr, this message translates to:
  /// **'Couche {index} ({count})'**
  String vulnTableLayerItem(int index, int count);

  /// Info-bulle : revenir à la liste à plat.
  ///
  /// In fr, this message translates to:
  /// **'Liste à plat'**
  String get vulnTableFlatList;

  /// Info-bulle : regrouper par couche.
  ///
  /// In fr, this message translates to:
  /// **'Grouper par couche'**
  String get vulnTableGroupByLayer;

  /// Info-bulle d'une couche inconnue.
  ///
  /// In fr, this message translates to:
  /// **'Couche inconnue (paquet absent du SBOM de l\'image)'**
  String get vulnTableLayerUnknownTooltip;

  /// En-tête de groupe : couche inconnue.
  ///
  /// In fr, this message translates to:
  /// **'Couche inconnue'**
  String get vulnTableLayerUnknown;

  /// Nom d'une couche (suivi éventuellement du digest).
  ///
  /// In fr, this message translates to:
  /// **'Couche {index}'**
  String vulnTableLayerLabel(int index);

  /// Libellé de la barre de filtre de date.
  ///
  /// In fr, this message translates to:
  /// **'Date CVE :'**
  String get dateFilterLabel;

  /// Champ de date : publication.
  ///
  /// In fr, this message translates to:
  /// **'Publication'**
  String get dateFilterPublished;

  /// Champ de date : dernière modification.
  ///
  /// In fr, this message translates to:
  /// **'Modification'**
  String get dateFilterModified;

  /// Champ de date : la plus récente des deux.
  ///
  /// In fr, this message translates to:
  /// **'La plus récente'**
  String get dateFilterLatest;

  /// Puce de borne basse vide.
  ///
  /// In fr, this message translates to:
  /// **'Après le…'**
  String get dateFilterAfterEmpty;

  /// Puce de borne basse renseignée.
  ///
  /// In fr, this message translates to:
  /// **'Après : {date}'**
  String dateFilterAfter(String date);

  /// Puce de borne haute vide.
  ///
  /// In fr, this message translates to:
  /// **'Avant le…'**
  String get dateFilterBeforeEmpty;

  /// Puce de borne haute renseignée.
  ///
  /// In fr, this message translates to:
  /// **'Avant : {date}'**
  String dateFilterBefore(String date);

  /// Case : inclure les CVE sans date.
  ///
  /// In fr, this message translates to:
  /// **'Sans date'**
  String get dateFilterUndated;

  /// Bouton : appliquer le filtre aux autres onglets.
  ///
  /// In fr, this message translates to:
  /// **'Propager aux autres onglets'**
  String get dateFilterPropagate;

  /// Titre du sélecteur de configuration Grype.
  ///
  /// In fr, this message translates to:
  /// **'Choisir grype.yaml'**
  String get grypePickConfigTitle;

  /// Titre du sélecteur de template Grype.
  ///
  /// In fr, this message translates to:
  /// **'Choisir un fichier template Grype'**
  String get grypePickTemplateTitle;

  /// Onglet de résultats : tableau.
  ///
  /// In fr, this message translates to:
  /// **'Table ({count})'**
  String grypeTabTable(int count);

  /// Onglet de résultats : JSON brut.
  ///
  /// In fr, this message translates to:
  /// **'JSON'**
  String get grypeTabJson;

  /// Onglet de résultats : sortie template.
  ///
  /// In fr, this message translates to:
  /// **'Template'**
  String get grypeTabTemplate;

  /// En-tête de la colonne supplémentaire (type de paquet).
  ///
  /// In fr, this message translates to:
  /// **'TYPE'**
  String get grypeColType;

  /// Aide du champ Plateforme (Grype).
  ///
  /// In fr, this message translates to:
  /// **'Optionnel. Force la plateforme cible sur une\nimage multi-architecture, ex. linux/arm64.\nLaisser vide = détection automatique par\ngrype (la case --platform linux ci-dessous ne\ns\'applique pas en mode image).'**
  String get grypePlatformHelp;

  /// Aide de l'option --platform linux.
  ///
  /// In fr, this message translates to:
  /// **'Fixe la plateforme cible à linux/amd64.\nÀ activer si Grype ne détecte pas\nautomatiquement la plateforme de l\'image.'**
  String get grypePlatformLinuxHelp;

  /// Aide de l'option --add-cpes-if-none.
  ///
  /// In fr, this message translates to:
  /// **'Génère des CPE (Common Platform Enumeration)\npour les paquets qui n\'en ont pas.\nAméliore le taux de correspondance CVE.'**
  String get grypeAddCpesHelp;

  /// Aide de l'option --by-cve.
  ///
  /// In fr, this message translates to:
  /// **'Groupe les résultats par CVE plutôt que par\npaquet. Évite les doublons quand plusieurs\npaquets sont touchés par la même CVE.'**
  String get grypeByCveHelp;

  /// Aide de l'option --distro.
  ///
  /// In fr, this message translates to:
  /// **'Distribution cible pour l\'évaluation des CVE.\nSi vide, Grype tente de la détecter\nautomatiquement depuis le SBOM.'**
  String get grypeDistroHelp;

  /// Aide de l'option --fail-on.
  ///
  /// In fr, this message translates to:
  /// **'Sévérité minimum pour que Grype retourne\nun code d\'erreur 1 (utile en CI/CD).\nSi vide, Grype retourne toujours 0.'**
  String get grypeFailOnHelp;

  /// Aide de l'option --only-fixed.
  ///
  /// In fr, this message translates to:
  /// **'N\'affiche que les vulnérabilités pour lesquelles\nune version corrigée est disponible.'**
  String get grypeOnlyFixedHelp;

  /// Libellé du champ template.
  ///
  /// In fr, this message translates to:
  /// **'Template (-t)'**
  String get grypeTemplateLabel;

  /// Aide du champ template.
  ///
  /// In fr, this message translates to:
  /// **'Modèle Go pour formater la sortie de Grype.\nEx : ./grype_csv.tmpl pour un export CSV.\nVoir la doc Grype pour la syntaxe des templates.'**
  String get grypeTemplateHelp;

  /// Libellé du champ de configuration Grype.
  ///
  /// In fr, this message translates to:
  /// **'grype.yaml (optionnel)'**
  String get grypeConfigLabel;

  /// Aide du champ de configuration Grype.
  ///
  /// In fr, this message translates to:
  /// **'Fichier de configuration Grype (YAML).\nPermet de définir des exceptions, des sources\nde données, ou de personnaliser le comportement.'**
  String get grypeConfigHelp;

  /// Exemple du champ de configuration Grype.
  ///
  /// In fr, this message translates to:
  /// **'/chemin/vers/grype.yaml'**
  String get grypeConfigHint;

  /// Vue template vide (template configuré).
  ///
  /// In fr, this message translates to:
  /// **'Lancez l\'analyse pour afficher la sortie template'**
  String get grypeTemplateEmptyRun;

  /// Vue template vide (aucun template).
  ///
  /// In fr, this message translates to:
  /// **'Configurez un fichier template (-t) pour activer cette vue'**
  String get grypeTemplateEmptyConfigure;

  /// Info-bulle de copie de la sortie template.
  ///
  /// In fr, this message translates to:
  /// **'Copier la sortie'**
  String get grypeTemplateCopyTooltip;

  /// Confirmation de copie de la sortie template.
  ///
  /// In fr, this message translates to:
  /// **'Sortie template copiée'**
  String get grypeTemplateCopied;

  /// État initial de l'onglet Grype.
  ///
  /// In fr, this message translates to:
  /// **'Choisissez un fichier SBOM ou une image de conteneur,\npuis lancez l\'analyse Grype'**
  String get grypeEmptyHint;

  /// État pendant l'analyse Grype.
  ///
  /// In fr, this message translates to:
  /// **'Analyse Grype en cours…'**
  String get grypeRunning;

  /// Remarque CLI : fichier de sortie du template.
  ///
  /// In fr, this message translates to:
  /// **'Sortie du template écrite dans un fichier temporaire (ici {file}).'**
  String grypeCliTemplateOutputNote(String file);

  /// Remarque CLI : template ignoré par couche.
  ///
  /// In fr, this message translates to:
  /// **'Le template (-t) n\'est pas appliqué en analyse par couche.'**
  String get grypeCliTemplateNotLayered;

  /// Option non transposable : cases décochées.
  ///
  /// In fr, this message translates to:
  /// **'décochage de --add-cpes-if-none / --by-cve (toujours actifs)'**
  String get grypeCliCpesByCveUnchecked;

  /// Étape de l'analyse par couche : génération des SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Préparation des SBOM de couche…'**
  String get layerScanStepPreparing;

  /// Étape de l'analyse par couche : scan de l'image (rattachement).
  ///
  /// In fr, this message translates to:
  /// **'Analyse de l\'image…'**
  String get layerScanStepImage;

  /// Étape de l'analyse par couche : scan du SBOM d'une couche.
  ///
  /// In fr, this message translates to:
  /// **'Couche {index}/{total}…'**
  String layerScanStepLayer(int index, int total);

  /// Bascule de source d'analyse : paquet ou archive locale (aussi libellé du champ).
  ///
  /// In fr, this message translates to:
  /// **'Paquet / archive'**
  String get scanSourcePackage;

  /// Exemple affiché dans le champ de paquet/archive.
  ///
  /// In fr, this message translates to:
  /// **'chemin/vers/app.rpm, release.tar.gz, app.jar…'**
  String get scanSourcePackageHint;

  /// Aide du champ paquet/archive.
  ///
  /// In fr, this message translates to:
  /// **'Paquet ou archive local (rpm, deb, tar/tgz, zip, jar/war/ear,\nwheel) analysé directement : le SBOM est d\'abord généré\npar sbom-generator (--input … --depth N) puis scanné.\nAvec une profondeur > 0, les jars, paquets et archives\ncontenus (ex. les jars d\'un RPM) sont aussi analysés.'**
  String get scanSourcePackageHelp;

  /// Libellé du sélecteur de profondeur de descente (--depth).
  ///
  /// In fr, this message translates to:
  /// **'Profondeur'**
  String get scanPackageDepthLabel;

  /// Aide du sélecteur de profondeur.
  ///
  /// In fr, this message translates to:
  /// **'Niveaux d\'objets imbriqués dans lesquels descendre :\n• 0 : l\'objet seul\n• N : N niveaux (1 = jars/paquets/archives contenus\n  dans l\'objet, 2 = ce que ceux-ci contiennent…)\n• Illimitée : tous les niveaux (plafonnés à 10)\nLes manifestes rencontrés (package-lock.json, go.sum,\npom.xml…) sont analysés. Extraction bornée en taille.'**
  String get scanPackageDepthHelp;

  /// Valeur de profondeur 0.
  ///
  /// In fr, this message translates to:
  /// **'0 — objet seul'**
  String get scanPackageDepthNone;

  /// Valeur de profondeur « all ».
  ///
  /// In fr, this message translates to:
  /// **'Illimitée'**
  String get scanPackageDepthAll;

  /// Valeur de profondeur N (N ≥ 1).
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{1 niveau} other{{count} niveaux}}'**
  String scanPackageDepthLevels(int count);

  /// Erreur : aucun paquet/archive saisi.
  ///
  /// In fr, this message translates to:
  /// **'Veuillez sélectionner un paquet ou une archive.'**
  String get scanSourceMissingPackage;

  /// Titre du sélecteur de paquet/archive.
  ///
  /// In fr, this message translates to:
  /// **'Choisir un paquet ou une archive'**
  String get scanPickPackageTitle;

  /// État affiché pendant la génération du SBOM du paquet avant son scan.
  ///
  /// In fr, this message translates to:
  /// **'Génération du SBOM du paquet…'**
  String get scanPackagePreparing;

  /// Erreur : sbom-generator a échoué sur le paquet.
  ///
  /// In fr, this message translates to:
  /// **'Génération du SBOM impossible : {error}'**
  String scanPackageFailed(String error);

  /// Titre de la section CLI : génération du SBOM d'un paquet.
  ///
  /// In fr, this message translates to:
  /// **'Génération du SBOM du paquet (étape préalable)'**
  String get cliCommandPackagePrepare;

  /// Remarque : SBOM de paquet temporaire.
  ///
  /// In fr, this message translates to:
  /// **'Le SBOM est généré dans un répertoire temporaire ; chaque CVE est rattachée à l\'objet qui contient le paquet vulnérable (colonne OBJET) dans l\'équivalent sbom-generator scan.'**
  String get cliCommandPackageNote;

  /// Entrée du sélecteur de couche : le SBOM global de l'image.
  ///
  /// In fr, this message translates to:
  /// **'SBOM global'**
  String get layerGlobalSbom;

  /// Entrée du sélecteur de couche : couche numéro index sur total.
  ///
  /// In fr, this message translates to:
  /// **'Couche {index}/{total} ({digest})'**
  String layerOption(int index, int total, String digest);

  /// Libellé devant le sélecteur de couche (nombre de couches du jeu).
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} couche :} other{{count} couches :}}'**
  String layerCount(int count);

  /// Pastille : nombre de composants supprimés par la couche.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} supprimé} other{{count} supprimés}}'**
  String layerRemovedChip(int count);

  /// Info-bulle du bouton de copie de l'identifiant d'une CVE.
  ///
  /// In fr, this message translates to:
  /// **'Copier l\'identifiant'**
  String get cveCopyId;

  /// Message : l'identifiant de CVE a été copié dans le presse-papiers.
  ///
  /// In fr, this message translates to:
  /// **'CVE copié'**
  String get cveCopied;

  /// Titre de section : scanners qui rapportent la CVE.
  ///
  /// In fr, this message translates to:
  /// **'Rapporté par'**
  String get cveReportedBy;

  /// En-tête de colonne : sévérité.
  ///
  /// In fr, this message translates to:
  /// **'Sévérité'**
  String get cveThSeverity;

  /// En-tête de colonne : dates de publication / modification.
  ///
  /// In fr, this message translates to:
  /// **'Publié / modifié'**
  String get cveThPublishedModified;

  /// Titre de section : signaux d'exploitabilité d'une CVE.
  ///
  /// In fr, this message translates to:
  /// **'Exploitabilité et exploitation active'**
  String get cveExploitTitle;

  /// Message : aucun signal d'exploitation pour cette CVE.
  ///
  /// In fr, this message translates to:
  /// **'Aucun signal d\'exploitation connu.'**
  String get cveNoSignal;

  /// Ligne de détail : la CVE est au catalogue CISA KEV.
  ///
  /// In fr, this message translates to:
  /// **'CISA KEV — exploitée activement dans la nature'**
  String get cveKevLine;

  /// Suite de la ligne KEV : date d'ajout au catalogue.
  ///
  /// In fr, this message translates to:
  /// **' · ajoutée le {date}'**
  String cveKevAddedOn(String date);

  /// Suite de la ligne KEV : échéance de remédiation.
  ///
  /// In fr, this message translates to:
  /// **' · échéance {date}'**
  String cveKevDueOn(String date);

  /// Suite de la ligne KEV : exploitée par un rançongiciel.
  ///
  /// In fr, this message translates to:
  /// **' · usage par rançongiciel'**
  String get cveKevRansomware;

  /// Ligne de détail : score EPSS et percentile.
  ///
  /// In fr, this message translates to:
  /// **'EPSS {score} (percentile p{pct}) — probabilité d\'exploitation à 30 jours'**
  String cveEpssLine(String score, int pct);

  /// Sous-score d'exploitabilité CVSS (0 à 3,9).
  ///
  /// In fr, this message translates to:
  /// **'exploitabilité {score}/3.9'**
  String cveExploitability(String score);

  /// Maturité de l'exploit (vecteur CVSS).
  ///
  /// In fr, this message translates to:
  /// **'maturité {value}'**
  String cveMaturity(String value);

  /// Ligne de détail : nombre de dépôts PoC publics.
  ///
  /// In fr, this message translates to:
  /// **'{n, plural, one{{n} dépôt PoC public recensé} other{{n} dépôts PoC publics recensés}}'**
  String cvePocRepos(int n);

  /// Ligne de détail : un exploit public existe.
  ///
  /// In fr, this message translates to:
  /// **'Exploit / PoC public recensé'**
  String get cvePocKnown;

  /// Titre de section : liens externes d'une CVE.
  ///
  /// In fr, this message translates to:
  /// **'Références'**
  String get cveReferences;

  /// Rapport AsciiDoc, détail d'une CVE : libellé de la ligne « paquet ».
  ///
  /// In fr, this message translates to:
  /// **'Paquet'**
  String get adocPackage;

  /// Rapport AsciiDoc, détail d'une CVE : libellé de la ligne « dates ».
  ///
  /// In fr, this message translates to:
  /// **'Dates'**
  String get adocDates;

  /// Rapport AsciiDoc : dates de publication et modification vues par un scanner.
  ///
  /// In fr, this message translates to:
  /// **'{scanner} : publié {published}, modifié {modified}'**
  String adocDateEntry(String scanner, String published, String modified);

  /// Rapport AsciiDoc : libellé de la ligne « description ».
  ///
  /// In fr, this message translates to:
  /// **'Description'**
  String get adocDescription;

  /// Rapport AsciiDoc : la CVE est au catalogue KEV, avec le détail.
  ///
  /// In fr, this message translates to:
  /// **'Oui — {details}'**
  String adocKevYes(String details);

  /// Rapport AsciiDoc : date d'ajout au catalogue KEV.
  ///
  /// In fr, this message translates to:
  /// **'ajoutée {date}'**
  String adocKevAdded(String date);

  /// Rapport AsciiDoc : échéance de remédiation KEV.
  ///
  /// In fr, this message translates to:
  /// **'échéance {date}'**
  String adocKevDue(String date);

  /// Rapport AsciiDoc : exploitée par un rançongiciel.
  ///
  /// In fr, this message translates to:
  /// **'usage par rançongiciel'**
  String get adocKevRansomware;

  /// Rapport AsciiDoc : score EPSS et percentile.
  ///
  /// In fr, this message translates to:
  /// **'{score} (percentile p{pct})'**
  String adocEpss(String score, int pct);

  /// Rapport AsciiDoc : score de base CVSS.
  ///
  /// In fr, this message translates to:
  /// **'base {score}'**
  String adocCvssBase(String score);

  /// Rapport AsciiDoc : libellé de la ligne « PoC public ».
  ///
  /// In fr, this message translates to:
  /// **'PoC public'**
  String get adocPocPublic;

  /// Rapport AsciiDoc : nombre de dépôts PoC.
  ///
  /// In fr, this message translates to:
  /// **'{n, plural, one{{n} dépôt} other{{n} dépôts}}'**
  String adocPocRepos(int n);

  /// Rapport AsciiDoc : réponse affirmative.
  ///
  /// In fr, this message translates to:
  /// **'oui'**
  String get adocYes;

  /// Rapport AsciiDoc : libellé de la ligne « liens ».
  ///
  /// In fr, this message translates to:
  /// **'Liens'**
  String get adocLinks;

  /// Rapport : libellé de sévérité critique (badge, majuscules).
  ///
  /// In fr, this message translates to:
  /// **'CRITIQUE'**
  String get pdfSeverityCritical;

  /// Rapport : libellé de sévérité élevée (badge, majuscules).
  ///
  /// In fr, this message translates to:
  /// **'ÉLEVÉE'**
  String get pdfSeverityHigh;

  /// Rapport : libellé de sévérité moyenne (badge, majuscules).
  ///
  /// In fr, this message translates to:
  /// **'MOYENNE'**
  String get pdfSeverityMedium;

  /// Rapport : libellé de sévérité faible (badge, majuscules).
  ///
  /// In fr, this message translates to:
  /// **'FAIBLE'**
  String get pdfSeverityLow;

  /// Rapport : libellé de sévérité négligeable (badge, majuscules).
  ///
  /// In fr, this message translates to:
  /// **'NÉGLIGEABLE'**
  String get pdfSeverityNegligible;

  /// Rapport : texte alternatif de la barre de répartition par sévérité.
  ///
  /// In fr, this message translates to:
  /// **'Répartition par sévérité'**
  String get pdfSeverityBarAlt;

  /// Rapport : version d'un outil non détectée (AsciiDoc, en italique).
  ///
  /// In fr, this message translates to:
  /// **'_indisponible_'**
  String get pdfUnavailable;

  /// Description d'un SBOM de couche : numéro de la couche, total, mode de calcul.
  ///
  /// In fr, this message translates to:
  /// **'Couche {index}/{total} — mode {mode}'**
  String layerDocHeader(String index, String total, String mode);

  /// Description d'un SBOM de couche : digest de la couche.
  ///
  /// In fr, this message translates to:
  /// **'Digest : {digest}'**
  String layerDocDigest(String digest);

  /// Description d'un SBOM de couche : instruction de build.
  ///
  /// In fr, this message translates to:
  /// **'Instruction : {text}'**
  String layerDocInstruction(String text);

  /// Description d'un SBOM de couche : compteurs de composants.
  ///
  /// In fr, this message translates to:
  /// **'Ajoutés : {added} — modifiés : {modified} — supprimés : {removed}'**
  String layerDocCounts(String added, String modified, String removed);

  /// Description du SBOM global d'une image : nombre de couches analysées.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} couche analysée} other{{count} couches analysées}}'**
  String layerDocAnalyzed(int count);

  /// Suite de la description du SBOM global : mode de calcul des couches.
  ///
  /// In fr, this message translates to:
  /// **' — mode {mode}'**
  String layerDocModeSuffix(String mode);

  /// Colonne « couche / changement » : composant ajouté par la couche.
  ///
  /// In fr, this message translates to:
  /// **'ajouté'**
  String get layerColAdded;

  /// Colonne « couche / changement » : composant modifié, avec l'ancienne version.
  ///
  /// In fr, this message translates to:
  /// **'modifié (était {prev})'**
  String layerColModifiedWas(String prev);

  /// Colonne « couche / changement » : composant modifié.
  ///
  /// In fr, this message translates to:
  /// **'modifié'**
  String get layerColModified;

  /// Colonne « couche » : couche d'origine du composant.
  ///
  /// In fr, this message translates to:
  /// **'couche {index}'**
  String layerColLayer(String index);

  /// Colonne « couche » : couche d'origine et couches qui l'ont modifié.
  ///
  /// In fr, this message translates to:
  /// **'couche {index} (modifié : {by})'**
  String layerColLayerModifiedBy(String index, String by);

  /// Regroupement par couche : composants ajoutés.
  ///
  /// In fr, this message translates to:
  /// **'Ajoutés'**
  String get layerGroupAdded;

  /// Regroupement par couche : composants modifiés.
  ///
  /// In fr, this message translates to:
  /// **'Modifiés'**
  String get layerGroupModified;

  /// Regroupement par couche : composants sans couche connue.
  ///
  /// In fr, this message translates to:
  /// **'(couche inconnue)'**
  String get layerGroupUnknown;

  /// Regroupement par couche : en-tête de groupe (index sur deux chiffres).
  ///
  /// In fr, this message translates to:
  /// **'Couche {index}'**
  String layerGroupLayer(String index);

  /// Rapport : méthode « chaque couche » de l'analyse par couche.
  ///
  /// In fr, this message translates to:
  /// **'SBOM de chaque couche scanné'**
  String get layerScanModeEach;

  /// Rapport : méthode « rattachement » de l'analyse par couche.
  ///
  /// In fr, this message translates to:
  /// **'rattachement à la couche d\'origine du paquet'**
  String get layerScanModeAttribute;

  /// Arborescence : le fichier ouvert n'est ni CycloneDX ni SPDX.
  ///
  /// In fr, this message translates to:
  /// **'Format non reconnu (ni CycloneDX ni SPDX).'**
  String get treeFormatUnknown;

  /// Arborescence : échec de lecture du fichier.
  ///
  /// In fr, this message translates to:
  /// **'Erreur de lecture : {error}'**
  String treeReadError(String error);

  /// Titre du sélecteur de fichier SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner un fichier SBOM (JSON)'**
  String get treePickTitle;

  /// Arborescence : groupe des composants sans licence.
  ///
  /// In fr, this message translates to:
  /// **'(non spécifié)'**
  String get treeUnspecified;

  /// Info-bulle : déplier tous les groupes.
  ///
  /// In fr, this message translates to:
  /// **'Tout déplier'**
  String get treeExpandAll;

  /// Info-bulle : replier tous les groupes.
  ///
  /// In fr, this message translates to:
  /// **'Tout replier'**
  String get treeCollapseAll;

  /// Champ de filtre de l'arborescence.
  ///
  /// In fr, this message translates to:
  /// **'Filtrer par nom, purl, licence…'**
  String get treeFilterHint;

  /// Arborescence : aucun résultat pour le filtre.
  ///
  /// In fr, this message translates to:
  /// **'Aucun composant pour \"{term}\"'**
  String treeNoMatch(String term);

  /// Barre de fichier : aucun SBOM chargé.
  ///
  /// In fr, this message translates to:
  /// **'Aucun fichier SBOM sélectionné'**
  String get treeNoFileSelected;

  /// Menu des SBOM générés (nombre de fichiers).
  ///
  /// In fr, this message translates to:
  /// **'Générés ({count})'**
  String treeGenerated(int count);

  /// Bouton : ouvrir un fichier SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir…'**
  String get treeOpen;

  /// Pastille : nombre de composants du SBOM.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} composant} other{{count} composants}}'**
  String treeComponentsChip(int count);

  /// Pastille : nombre de licences distinctes.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} licence} other{{count} licences}}'**
  String treeLicensesChip(int count);

  /// Libellé du sélecteur de regroupement.
  ///
  /// In fr, this message translates to:
  /// **'Grouper :'**
  String get treeGroupBy;

  /// Aide du sélecteur de regroupement.
  ///
  /// In fr, this message translates to:
  /// **'Mode de regroupement des composants.\n• Aucun : liste à plat alphabétique\n• Type : groupé par écosystème (rpm, pypi…)\n• Licence : groupé par expression SPDX\n• Couche : groupé par couche d\'origine (SBOM global) ou par changement (SBOM de couche) — SBOM produits avec --per-layer'**
  String get treeGroupHelp;

  /// Regroupement : aucun.
  ///
  /// In fr, this message translates to:
  /// **'Aucun'**
  String get treeGroupNone;

  /// Regroupement : par type.
  ///
  /// In fr, this message translates to:
  /// **'Type'**
  String get treeGroupType;

  /// Regroupement : par licence.
  ///
  /// In fr, this message translates to:
  /// **'Licence'**
  String get treeGroupLicense;

  /// Regroupement : par couche.
  ///
  /// In fr, this message translates to:
  /// **'Couche'**
  String get treeGroupLayer;

  /// Détail d'un composant : licence.
  ///
  /// In fr, this message translates to:
  /// **'Licence'**
  String get treeDetailLicense;

  /// Détail d'un composant : couche.
  ///
  /// In fr, this message translates to:
  /// **'Couche'**
  String get treeDetailLayer;

  /// Arborescence vide : des sorties existent mais aucun SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Aucun fichier SBOM (JSON/JSON-LD) dans les sorties.'**
  String get treeEmptyNoSbom;

  /// Arborescence vide : rien à afficher.
  ///
  /// In fr, this message translates to:
  /// **'Générez un SBOM ou ouvrez un fichier existant.'**
  String get treeEmptyGenerate;

  /// Bouton : ouvrir un fichier SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir un fichier SBOM'**
  String get treeOpenSbom;

  /// Titre du sélecteur de fichier de la visionneuse.
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir un fichier SBOM'**
  String get viewerOpenTitle;

  /// Visionneuse : échec d'analyse du fichier.
  ///
  /// In fr, this message translates to:
  /// **'Impossible de parser le fichier : {error}'**
  String viewerParseError(String error);

  /// Visionneuse : libellé d'une licence absente (statistiques).
  ///
  /// In fr, this message translates to:
  /// **'Non spécifiée'**
  String get viewerUnspecified;

  /// Visionneuse vide.
  ///
  /// In fr, this message translates to:
  /// **'Aucun fichier SBOM chargé'**
  String get viewerNoFile;

  /// Bouton : ouvrir un fichier SBOM (visionneuse vide).
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir un fichier SBOM…'**
  String get viewerOpenEllipsis;

  /// Visionneuse : étiquette du badge « nombre de composants ».
  ///
  /// In fr, this message translates to:
  /// **'composants'**
  String get viewerStatComponents;

  /// Visionneuse : étiquette du badge « nombre de types ».
  ///
  /// In fr, this message translates to:
  /// **'types'**
  String get viewerStatTypes;

  /// Visionneuse : étiquette du badge « nombre de licences ».
  ///
  /// In fr, this message translates to:
  /// **'licences'**
  String get viewerStatLicenses;

  /// Bouton : ouvrir un fichier.
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir…'**
  String get viewerOpenShort;

  /// Champ de filtre de la visionneuse.
  ///
  /// In fr, this message translates to:
  /// **'Filtrer…'**
  String get viewerFilterHint;

  /// Filtre par type : indication.
  ///
  /// In fr, this message translates to:
  /// **'Type'**
  String get viewerTypeHint;

  /// Filtre par type : tous les types.
  ///
  /// In fr, this message translates to:
  /// **'Tous'**
  String get viewerAll;

  /// Visionneuse : aucun composant ne correspond au filtre.
  ///
  /// In fr, this message translates to:
  /// **'Aucun résultat'**
  String get viewerNoResult;

  /// En-tête de colonne : nom.
  ///
  /// In fr, this message translates to:
  /// **'Nom'**
  String get viewerColName;

  /// En-tête de colonne : licence.
  ///
  /// In fr, this message translates to:
  /// **'Licence'**
  String get viewerColLicense;

  /// En-tête de colonne : changement (SBOM de couche).
  ///
  /// In fr, this message translates to:
  /// **'Changement'**
  String get viewerColChange;

  /// En-tête de colonne : couche d'origine (SBOM global).
  ///
  /// In fr, this message translates to:
  /// **'Couche'**
  String get viewerColLayer;

  /// Info-bulle : copier le PURL.
  ///
  /// In fr, this message translates to:
  /// **'Copier le PURL'**
  String get viewerCopyPurl;

  /// Message : PURL copié.
  ///
  /// In fr, this message translates to:
  /// **'PURL copié'**
  String get viewerPurlCopied;

  /// Menu : fichiers générés par la dernière génération.
  ///
  /// In fr, this message translates to:
  /// **'Fichiers générés'**
  String get commonGeneratedFiles;

  /// Champ : chemin du fichier de sortie.
  ///
  /// In fr, this message translates to:
  /// **'Fichier de sortie'**
  String get commonOutputFile;

  /// Champ : nom du document (facultatif).
  ///
  /// In fr, this message translates to:
  /// **'Nom du document (optionnel)'**
  String get commonDocNameOptional;

  /// Titre du sélecteur de fichier (onglet Licences).
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner un fichier SBOM'**
  String get licPickTitle;

  /// Bouton : choisir un fichier SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Choisir un fichier…'**
  String get licChooseFile;

  /// Licences : aucun fichier choisi.
  ///
  /// In fr, this message translates to:
  /// **'Aucun fichier sélectionné'**
  String get licNoFile;

  /// Bouton : générer le rapport de licences.
  ///
  /// In fr, this message translates to:
  /// **'Générer'**
  String get licGenerate;

  /// Licences : rapport écrit.
  ///
  /// In fr, this message translates to:
  /// **'Rapport généré → {path}'**
  String licReportGenerated(String path);

  /// Licences : échec de la génération.
  ///
  /// In fr, this message translates to:
  /// **'Échec de la génération (code {code}) — voir le journal ci-dessous.'**
  String licReportFailed(int code);

  /// Licences : échec de lecture des licences du SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Impossible de lire les licences : {error}'**
  String licLoadError(String error);

  /// Licences : texte d'accueil de l'onglet.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionnez un fichier CycloneDX ou SPDX pour visualiser ses licences (regroupées par licence, avec signalement des licences copyleft et des paquets sans licence détectée), puis générer un rapport ci-dessous.'**
  String get licSelectHint;

  /// Licences : champ de filtre.
  ///
  /// In fr, this message translates to:
  /// **'Filtrer par licence ou par paquet…'**
  String get licFilterHint;

  /// Licences : vue regroupée par licence.
  ///
  /// In fr, this message translates to:
  /// **'Par licence'**
  String get licViewGrouped;

  /// Licences : vue en tableau.
  ///
  /// In fr, this message translates to:
  /// **'Tableau'**
  String get licViewTable;

  /// Licences : aucun résultat pour le filtre.
  ///
  /// In fr, this message translates to:
  /// **'Aucun résultat.'**
  String get licNoResult;

  /// Licences : pastille du nombre de paquets.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} paquet} other{{count} paquets}}'**
  String licChipPackages(int count);

  /// Licences : pastille du nombre de licences distinctes.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} licence} other{{count} licences}}'**
  String licChipLicenses(int count);

  /// Licences : pastille des paquets sous copyleft fort.
  ///
  /// In fr, this message translates to:
  /// **'{count} copyleft fort'**
  String licChipStrong(int count);

  /// Licences : pastille des paquets sous copyleft faible.
  ///
  /// In fr, this message translates to:
  /// **'{count} copyleft faible'**
  String licChipWeak(int count);

  /// Licences : pastille des paquets sans licence.
  ///
  /// In fr, this message translates to:
  /// **'{count} sans licence'**
  String licChipNone(int count);

  /// Licences : badge de catégorie copyleft fort.
  ///
  /// In fr, this message translates to:
  /// **'copyleft fort'**
  String get licCategoryStrong;

  /// Licences : badge de catégorie copyleft faible.
  ///
  /// In fr, this message translates to:
  /// **'copyleft faible'**
  String get licCategoryWeak;

  /// Licences : badge de catégorie sans licence.
  ///
  /// In fr, this message translates to:
  /// **'sans licence'**
  String get licCategoryNone;

  /// Licences : titre du groupe des paquets sans licence.
  ///
  /// In fr, this message translates to:
  /// **'Sans licence détectée'**
  String get licNoLicenseDetected;

  /// En-tête de colonne : paquet.
  ///
  /// In fr, this message translates to:
  /// **'Paquet'**
  String get licColPackage;

  /// En-tête de colonne : licence.
  ///
  /// In fr, this message translates to:
  /// **'Licence'**
  String get licColLicense;

  /// Titre du sélecteur de fichiers (onglet Fusion).
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner des fichiers SBOM à fusionner'**
  String get mergePickTitle;

  /// Bouton : ajouter des fichiers SBOM à fusionner.
  ///
  /// In fr, this message translates to:
  /// **'Ajouter des fichiers…'**
  String get mergeAddFiles;

  /// Menu : filtrer sur les extensions JSON.
  ///
  /// In fr, this message translates to:
  /// **'.json / .jsonld'**
  String get mergeJsonOnly;

  /// Menu : aucun filtre d'extension.
  ///
  /// In fr, this message translates to:
  /// **'Tous les fichiers'**
  String get mergeAllFiles;

  /// Fusion : nombre de fichiers sélectionnés.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} fichier sélectionné} other{{count} fichiers sélectionnés}}'**
  String mergeSelected(int count);

  /// Fusion : suite du compteur quand moins de deux fichiers sont choisis.
  ///
  /// In fr, this message translates to:
  /// **' — au moins 2 requis'**
  String get mergeAtLeastTwo;

  /// Fusion : texte d'accueil.
  ///
  /// In fr, this message translates to:
  /// **'Ajoutez au moins deux fichiers SBOM à fusionner\n(CycloneDX ou SPDX 2.x — un même format des deux côtés).'**
  String get mergeHint;

  /// Bouton : lancer la fusion.
  ///
  /// In fr, this message translates to:
  /// **'Fusionner'**
  String get mergeButton;

  /// Fusion : réussite.
  ///
  /// In fr, this message translates to:
  /// **'Fusion réussie → {path}'**
  String mergeOk(String path);

  /// Fusion : échec.
  ///
  /// In fr, this message translates to:
  /// **'Échec de la fusion (code {code}) — voir le journal ci-dessous.'**
  String mergeFailed(int code);

  /// Comparaison : le fichier n'est ni CycloneDX ni SPDX.
  ///
  /// In fr, this message translates to:
  /// **'Format non reconnu.'**
  String get diffFormatUnknown;

  /// Titre du sélecteur de fichier pour le SBOM A.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner SBOM A (référence)'**
  String get diffPickA;

  /// Titre du sélecteur de fichier pour le SBOM B.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner SBOM B (comparé)'**
  String get diffPickB;

  /// Comparaison : aucun résultat pour la recherche.
  ///
  /// In fr, this message translates to:
  /// **'Aucun résultat pour \"{term}\"'**
  String diffNoMatch(String term);

  /// Comparaison : aucun élément pour les filtres de statut.
  ///
  /// In fr, this message translates to:
  /// **'Aucun élément pour les filtres sélectionnés.'**
  String get diffNoItems;

  /// Comparaison : intitulé de l'emplacement du SBOM A.
  ///
  /// In fr, this message translates to:
  /// **'A – Référence'**
  String get diffSlotA;

  /// Comparaison : intitulé de l'emplacement du SBOM B.
  ///
  /// In fr, this message translates to:
  /// **'B – Comparé'**
  String get diffSlotB;

  /// Bouton : lancer la comparaison.
  ///
  /// In fr, this message translates to:
  /// **'Comparer'**
  String get diffCompare;

  /// Comparaison : aucun fichier dans l'emplacement.
  ///
  /// In fr, this message translates to:
  /// **'Aucun fichier sélectionné'**
  String get diffNoFile;

  /// Comparaison : format du SBOM et nombre de composants.
  ///
  /// In fr, this message translates to:
  /// **'{format} · {count, plural, one{{count} composant} other{{count} composants}}'**
  String diffComponentsInfo(String format, int count);

  /// Info-bulle : ouvrir un fichier.
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir un fichier…'**
  String get diffOpenFile;

  /// Comparaison : composants ajoutés.
  ///
  /// In fr, this message translates to:
  /// **'Ajoutés'**
  String get diffAdded;

  /// Comparaison : composants supprimés.
  ///
  /// In fr, this message translates to:
  /// **'Supprimés'**
  String get diffRemoved;

  /// Comparaison : composants modifiés.
  ///
  /// In fr, this message translates to:
  /// **'Modifiés'**
  String get diffChanged;

  /// Comparaison : composants inchangés.
  ///
  /// In fr, this message translates to:
  /// **'Inchangés'**
  String get diffUnchanged;

  /// Comparaison : filtre « ajoutés » avec compteur.
  ///
  /// In fr, this message translates to:
  /// **'➕ Ajoutés ({count})'**
  String diffChipAdded(int count);

  /// Comparaison : filtre « supprimés » avec compteur.
  ///
  /// In fr, this message translates to:
  /// **'➖ Supprimés ({count})'**
  String diffChipRemoved(int count);

  /// Comparaison : filtre « modifiés » avec compteur.
  ///
  /// In fr, this message translates to:
  /// **'🔄 Modifiés ({count})'**
  String diffChipChanged(int count);

  /// Comparaison : filtre « inchangés » avec compteur.
  ///
  /// In fr, this message translates to:
  /// **'✓ Inchangés ({count})'**
  String diffChipUnchanged(int count);

  /// Comparaison : champ de filtre.
  ///
  /// In fr, this message translates to:
  /// **'Filtrer par nom…'**
  String get diffFilterHint;

  /// Comparaison : en-tête de colonne statut.
  ///
  /// In fr, this message translates to:
  /// **'STATUT'**
  String get diffHdrStatus;

  /// Comparaison : en-tête de colonne nom.
  ///
  /// In fr, this message translates to:
  /// **'NOM'**
  String get diffHdrName;

  /// Comparaison : en-tête de colonne version A.
  ///
  /// In fr, this message translates to:
  /// **'VERSION A'**
  String get diffHdrVersionA;

  /// Comparaison : en-tête de colonne version B.
  ///
  /// In fr, this message translates to:
  /// **'VERSION B'**
  String get diffHdrVersionB;

  /// Comparaison : en-tête de colonne licence.
  ///
  /// In fr, this message translates to:
  /// **'LICENCE'**
  String get diffHdrLicense;

  /// Comparaison : statut d'une ligne ajoutée.
  ///
  /// In fr, this message translates to:
  /// **'Ajouté'**
  String get diffStatusAdded;

  /// Comparaison : statut d'une ligne supprimée.
  ///
  /// In fr, this message translates to:
  /// **'Supprimé'**
  String get diffStatusRemoved;

  /// Comparaison : statut d'une ligne modifiée.
  ///
  /// In fr, this message translates to:
  /// **'Modifié'**
  String get diffStatusChanged;

  /// Comparaison : statut d'une ligne inchangée.
  ///
  /// In fr, this message translates to:
  /// **'Inchangé'**
  String get diffStatusUnchanged;

  /// Comparaison : invite quand les deux fichiers sont chargés.
  ///
  /// In fr, this message translates to:
  /// **'Cliquez sur \"Comparer\" pour lancer l\'analyse.'**
  String get diffEmptyReady;

  /// Comparaison : invite quand il manque un fichier.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionnez deux fichiers SBOM (A et B) pour les comparer.'**
  String get diffEmptyPick;

  /// Titre du sélecteur de fichier (onglet Qualité SBOM).
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner un fichier SBOM'**
  String get qualityPickTitle;

  /// Qualité : sbomqs a échoué sans message.
  ///
  /// In fr, this message translates to:
  /// **'Erreur sbomqs (exit {code})'**
  String qualitySbomqsError(int code);

  /// Qualité : sbomqs n'est pas installé.
  ///
  /// In fr, this message translates to:
  /// **'sbomqs introuvable — installez-le et ajoutez-le au PATH'**
  String get qualitySbomqsMissing;

  /// Qualité : sbom-scorecard a échoué sans message.
  ///
  /// In fr, this message translates to:
  /// **'Erreur sbom-scorecard (exit {code})'**
  String qualityScorecardError(int code);

  /// Qualité : sbom-scorecard n'est pas installé.
  ///
  /// In fr, this message translates to:
  /// **'sbom-scorecard introuvable — installez-le et ajoutez-le au PATH'**
  String get qualityScorecardMissing;

  /// Champ : fichier SBOM à évaluer.
  ///
  /// In fr, this message translates to:
  /// **'Fichier SBOM'**
  String get qualityFileLabel;

  /// Bouton : lancer l'évaluation de la qualité.
  ///
  /// In fr, this message translates to:
  /// **'Analyser'**
  String get qualityAnalyze;

  /// Libellé de la liste des profils sbomqs.
  ///
  /// In fr, this message translates to:
  /// **'Profils :'**
  String get qualityProfiles;

  /// Aide : profils de conformité sbomqs.
  ///
  /// In fr, this message translates to:
  /// **'Profils de conformité SBOM évalués par sbomqs.\nChaque profil vérifie un ensemble de critères\nspécifiques (NTIA, BSI, OpenChain, Interlynk…).\nAucun profil sélectionné = tous évalués.'**
  String get qualityProfilesHelp;

  /// Qualité : titre de l'écran d'accueil.
  ///
  /// In fr, this message translates to:
  /// **'Évaluation de la qualité SBOM'**
  String get qualityTitle;

  /// Qualité : texte d'accueil.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionnez un fichier SBOM puis cliquez sur Analyser.\nL\'analyse utilise sbomqs (Interlynk) et sbom-scorecard (eBay).'**
  String get qualityIntro;

  /// Info-bulle : passer en vue tableau.
  ///
  /// In fr, this message translates to:
  /// **'Vue tableau'**
  String get qualityTableView;

  /// Info-bulle : afficher le JSON brut.
  ///
  /// In fr, this message translates to:
  /// **'JSON brut'**
  String get qualityRawJson;

  /// Qualité : aucune donnée de critères.
  ///
  /// In fr, this message translates to:
  /// **'Aucun critère détaillé disponible.'**
  String get qualityNoCriteria;

  /// Qualité : catégorie sans nom.
  ///
  /// In fr, this message translates to:
  /// **'Autre'**
  String get qualityOther;

  /// Qualité : bouton « tout afficher » des filtres.
  ///
  /// In fr, this message translates to:
  /// **'Tout voir'**
  String get qualityShowAll;

  /// Info-bulle : passer en vue graphique.
  ///
  /// In fr, this message translates to:
  /// **'Vue graphique'**
  String get qualityChartView;

  /// Info-bulle : afficher la sortie brute.
  ///
  /// In fr, this message translates to:
  /// **'Sortie brute'**
  String get qualityRawOutput;

  /// Qualité : titre de la section des profils.
  ///
  /// In fr, this message translates to:
  /// **'Profils d\'industrie'**
  String get qualityIndustryProfiles;

  /// Qualité : info-bulle de la section des profils.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionnez des profils dans la barre de configuration\npour afficher le détail des critères'**
  String get qualityIndustryHint;

  /// Qualité : score d'un profil et critères satisfaits.
  ///
  /// In fr, this message translates to:
  /// **'{score}/10  ·  {passed}/{total} critères'**
  String qualityProfileSummary(String score, int passed, int total);

  /// Qualité : légende de l'astérisque.
  ///
  /// In fr, this message translates to:
  /// **'* critère obligatoire'**
  String get qualityRequiredNote;

  /// Onglet des résultats : progression de la génération.
  ///
  /// In fr, this message translates to:
  /// **'Progression'**
  String get tabProgress;

  /// Onglet des résultats : fichiers produits.
  ///
  /// In fr, this message translates to:
  /// **'Résultats'**
  String get tabResults;

  /// Onglet des résultats avec le nombre de fichiers.
  ///
  /// In fr, this message translates to:
  /// **'Résultats ({count})'**
  String tabResultsCount(int count);

  /// Onglet : tableau de bord des vulnérabilités.
  ///
  /// In fr, this message translates to:
  /// **'Tableau de bord'**
  String get tabDashboard;

  /// Onglet : rapport de conformité Cyber Resilience Act.
  ///
  /// In fr, this message translates to:
  /// **'Conformité CRA'**
  String get tabCra;

  /// Onglet : qualité du SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Qualité SBOM'**
  String get tabQuality;

  /// Onglet : arborescence du SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Arborescence'**
  String get tabTree;

  /// Onglet : comparaison de deux SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Comparaison'**
  String get tabCompare;

  /// Onglet : fusion de SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Fusion'**
  String get tabMerge;

  /// Onglet : licences du SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Licences'**
  String get tabLicenses;

  /// Onglet : visionneuse de SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Visionneuse'**
  String get tabViewer;

  /// Onglet : aperçu des fichiers générés.
  ///
  /// In fr, this message translates to:
  /// **'Aperçu'**
  String get tabPreview;

  /// Onglet : aperçu avec le nombre de fichiers.
  ///
  /// In fr, this message translates to:
  /// **'Aperçu ({count})'**
  String tabPreviewCount(int count);

  /// Aperçu : fichier tronqué.
  ///
  /// In fr, this message translates to:
  /// **'[… tronqué — {total} caractères au total]'**
  String resultsPreviewTruncated(int total);

  /// Aperçu : échec de lecture du fichier.
  ///
  /// In fr, this message translates to:
  /// **'Erreur de lecture : {error}'**
  String resultsReadError(String error);

  /// Bandeau : conversion PDF en cours.
  ///
  /// In fr, this message translates to:
  /// **'Conversion PDF (asciidoctor-pdf) en cours…'**
  String get resultsPdfConverting;

  /// Progression : paquets traités sur total.
  ///
  /// In fr, this message translates to:
  /// **'{current} / {total} paquets'**
  String resultsProgressPackages(int current, int total);

  /// Résumé : nombre de fichiers SBOM générés.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} fichier SBOM généré} other{{count} fichiers SBOM générés}}'**
  String resultsSummaryOk(int count);

  /// Résumé : suite avec le nombre d'avertissements.
  ///
  /// In fr, this message translates to:
  /// **' — {count, plural, one{{count} avertissement} other{{count} avertissements}}'**
  String resultsSummaryWarnings(int count);

  /// Résumé : la génération a échoué.
  ///
  /// In fr, this message translates to:
  /// **'Échec de la génération (exit {code})'**
  String resultsGenerationFailed(int code);

  /// Message : journal copié.
  ///
  /// In fr, this message translates to:
  /// **'Logs copiés dans le presse-papier'**
  String get resultsLogsCopied;

  /// Bouton : enregistrer le journal.
  ///
  /// In fr, this message translates to:
  /// **'Enregistrer'**
  String get resultsSave;

  /// Titre du dialogue d'enregistrement du journal.
  ///
  /// In fr, this message translates to:
  /// **'Enregistrer les logs'**
  String get resultsSaveLogsTitle;

  /// Résumé : nombre de paquets.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} paquet} other{{count} paquets}}'**
  String resultsStatPackages(int count);

  /// Résumé : nombre de fichiers SBOM.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} fichier SBOM} other{{count} fichiers SBOM}}'**
  String resultsStatFiles(int count);

  /// Résumé : nombre d'avertissements.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} avertissement} other{{count} avertissements}}'**
  String resultsStatWarnings(int count);

  /// Résultats : titre de section.
  ///
  /// In fr, this message translates to:
  /// **'Fichiers générés'**
  String get resultsSectionFiles;

  /// Résultats : titre de section du score sbomqs.
  ///
  /// In fr, this message translates to:
  /// **'Score sbomqs'**
  String get resultsSectionScore;

  /// Résultats : titre de section des avertissements.
  ///
  /// In fr, this message translates to:
  /// **'Avertissements ({count})'**
  String resultsSectionWarnings(int count);

  /// Résultats : titre de section de l'erreur fatale.
  ///
  /// In fr, this message translates to:
  /// **'Erreur'**
  String get resultsSectionError;

  /// Aperçu : aucun fichier prévisualisable.
  ///
  /// In fr, this message translates to:
  /// **'Aucun fichier texte généré pour la prévisualisation'**
  String get resultsNoPreview;

  /// Info-bulle : copier le contenu du fichier.
  ///
  /// In fr, this message translates to:
  /// **'Copier le contenu'**
  String get resultsCopyContent;

  /// Message : contenu copié.
  ///
  /// In fr, this message translates to:
  /// **'Contenu copié'**
  String get resultsContentCopied;

  /// Aperçu : aucun fichier sélectionné.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionnez un fichier'**
  String get resultsSelectFile;

  /// Info-bulle : copier le chemin du fichier.
  ///
  /// In fr, this message translates to:
  /// **'Copier le chemin'**
  String get resultsCopyPath;

  /// Message : chemin copié.
  ///
  /// In fr, this message translates to:
  /// **'Chemin copié'**
  String get resultsPathCopied;

  /// Info-bulle : ouvrir le fichier.
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir le fichier'**
  String get resultsOpenFile;

  /// Bouton : réduire la liste.
  ///
  /// In fr, this message translates to:
  /// **'Réduire'**
  String get resultsCollapse;

  /// Bouton : afficher les avertissements restants.
  ///
  /// In fr, this message translates to:
  /// **'Voir {count} de plus…'**
  String resultsShowMore(int count);

  /// Résultats : texte d'accueil.
  ///
  /// In fr, this message translates to:
  /// **'Configurez les options et lancez la génération'**
  String get resultsEmptyHint;

  /// Erreur affichée quand le CLI se termine avec un code non nul.
  ///
  /// In fr, this message translates to:
  /// **'Génération échouée (exit {code})'**
  String homeGenerationFailed(int code);

  /// Journal : début de la conversion AsciiDoc → PDF. Doit commencer par « Conversion PDF » ou « PDF conversion » (coloration du journal).
  ///
  /// In fr, this message translates to:
  /// **'Conversion PDF (asciidoctor-pdf)…'**
  String get homePdfHeader;

  /// Journal : asciidoctor-pdf a échoué.
  ///
  /// In fr, this message translates to:
  /// **'Erreur asciidoctor-pdf (exit {code})'**
  String homePdfError(int code);

  /// Journal : asciidoctor-pdf n'est pas installé.
  ///
  /// In fr, this message translates to:
  /// **'Erreur : asciidoctor-pdf introuvable.'**
  String get homePdfMissing;

  /// Journal : commande d'installation de asciidoctor-pdf.
  ///
  /// In fr, this message translates to:
  /// **'  Installez avec : gem install asciidoctor-pdf'**
  String get homePdfInstall;

  /// Journal : génération arrêtée par l'utilisateur.
  ///
  /// In fr, this message translates to:
  /// **'[Génération interrompue par l\'utilisateur]'**
  String get homeInterrupted;

  /// Info-bulle : conversion PDF en cours.
  ///
  /// In fr, this message translates to:
  /// **'Conversion PDF en cours…'**
  String get homePdfRunning;

  /// Info-bulle : génération en cours.
  ///
  /// In fr, this message translates to:
  /// **'Génération SBOM en cours…'**
  String get homeSbomRunning;

  /// Info-bulle : ouvrir le manuel utilisateur.
  ///
  /// In fr, this message translates to:
  /// **'Aide — Manuel utilisateur'**
  String get homeHelpTooltip;

  /// Info-bulle / titre : choix de la couleur du thème.
  ///
  /// In fr, this message translates to:
  /// **'Couleur du thème'**
  String get homeThemeColor;

  /// Info-bulle : passer en mode clair.
  ///
  /// In fr, this message translates to:
  /// **'Mode clair'**
  String get homeLightMode;

  /// Info-bulle : passer en mode sombre.
  ///
  /// In fr, this message translates to:
  /// **'Mode sombre'**
  String get homeDarkMode;

  /// Info-bulle : boîte « À propos ».
  ///
  /// In fr, this message translates to:
  /// **'À propos'**
  String get homeAbout;

  /// Boîte « À propos » : description de l'application.
  ///
  /// In fr, this message translates to:
  /// **'Interface graphique pour l\'outil sbom_generator.\n\nGénère des SBOM (Software Bill of Materials) depuis des listes de paquets RPM, .whl, .tar.gz, .deb, .zip, .jar, ou de manifestes (requirements.txt, go.sum, package-lock.json, pom.xml, pubspec.lock…) — fichier liste, paquet unique, ou dossier scanné récursivement.\n\nFormats supportés : CycloneDX 1.6/1.7, SPDX 2.3, SPDX 3.0 JSON-LD, JSON personnalisé, Markdown, AsciiDoc.'**
  String get homeAboutText;

  /// Bouton : annuler un dialogue.
  ///
  /// In fr, this message translates to:
  /// **'Annuler'**
  String get homeCancel;

  /// Nom d'une couleur de thème de l'application.
  ///
  /// In fr, this message translates to:
  /// **'Bleu'**
  String get themeBlue;

  /// Nom d'une couleur de thème de l'application.
  ///
  /// In fr, this message translates to:
  /// **'Violet'**
  String get themePurple;

  /// Nom d'une couleur de thème de l'application.
  ///
  /// In fr, this message translates to:
  /// **'Vert'**
  String get themeGreen;

  /// Nom d'une couleur de thème de l'application.
  ///
  /// In fr, this message translates to:
  /// **'Rouge'**
  String get themeRed;

  /// Nom d'une couleur de thème de l'application.
  ///
  /// In fr, this message translates to:
  /// **'Rose'**
  String get themePink;

  /// Nom d'une couleur de thème de l'application.
  ///
  /// In fr, this message translates to:
  /// **'Ardoise'**
  String get themeSlate;

  /// Nom d'une couleur de thème de l'application.
  ///
  /// In fr, this message translates to:
  /// **'Marron'**
  String get themeBrown;

  /// Journal : le CLI n'a pas pu être lancé.
  ///
  /// In fr, this message translates to:
  /// **'Erreur de lancement : {error}'**
  String svcLaunchError(String error);

  /// Erreur : grype n'est pas installé.
  ///
  /// In fr, this message translates to:
  /// **'grype introuvable. Installez-le : https://github.com/anchore/grype'**
  String get svcGrypeMissing;

  /// Erreur : osv-scanner n'est pas installé.
  ///
  /// In fr, this message translates to:
  /// **'osv-scanner introuvable — https://github.com/google/osv-scanner'**
  String get svcOsvMissing;

  /// Erreur : trivy n'est pas installé.
  ///
  /// In fr, this message translates to:
  /// **'trivy introuvable — https://github.com/aquasecurity/trivy'**
  String get svcTrivyMissing;

  /// Erreur : la génération du jeu de SBOM par couche a échoué.
  ///
  /// In fr, this message translates to:
  /// **'génération des SBOM de couche impossible (code {code}) : {detail}'**
  String svcLayerSbomFailed(int code, String detail);

  /// Erreur : l'image ne contient aucune couche.
  ///
  /// In fr, this message translates to:
  /// **'aucune couche trouvée dans {image}'**
  String svcNoLayer(String image);

  /// Version d'un outil : l'outil n'est pas installé.
  ///
  /// In fr, this message translates to:
  /// **'non installé'**
  String get svcNotInstalled;

  /// Info-bulle : une nouvelle version d'un outil existe.
  ///
  /// In fr, this message translates to:
  /// **'Mise à jour disponible — cliquez pour accéder à la release'**
  String get svcUpdateAvailable;

  /// CRA : aucun SBOM valide choisi.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionnez un fichier SBOM valide.'**
  String get craInvalidSbom;

  /// CRA : le CLI n'a pas produit de JSON.
  ///
  /// In fr, this message translates to:
  /// **'Sortie inattendue (code {code}).'**
  String craUnexpectedOutput(int code);

  /// CRA : le CLI n'a pas pu être lancé.
  ///
  /// In fr, this message translates to:
  /// **'Échec du lancement : {error}'**
  String craLaunchFailed(String error);

  /// Titre du dialogue d'export du rapport CRA.
  ///
  /// In fr, this message translates to:
  /// **'Exporter le rapport CRA (PDF)'**
  String get craExportTitle;

  /// Nom de fichier proposé pour le rapport CRA.
  ///
  /// In fr, this message translates to:
  /// **'rapport-cra.pdf'**
  String get craExportFileName;

  /// CRA : rapport PDF écrit.
  ///
  /// In fr, this message translates to:
  /// **'Rapport CRA écrit → {path}'**
  String craReportWritten(String path);

  /// CRA : échec de l'export.
  ///
  /// In fr, this message translates to:
  /// **'Échec : {detail}'**
  String craFailed(String detail);

  /// CRA : titre de l'onglet.
  ///
  /// In fr, this message translates to:
  /// **'Rapport de conformité — Cyber Resilience Act'**
  String get craTitle;

  /// CRA : aide sur le périmètre du rapport.
  ///
  /// In fr, this message translates to:
  /// **'Périmètre vérifiable automatiquement uniquement : format et complétude du SBOM (Annexe I §2 point 1, BSI TR-03183-2, éléments minimaux NTIA), inventaire des vulnérabilités connues et disponibilité des correctifs, vulnérabilités activement exploitées (art. 14). Les autres obligations du CRA relèvent du fabricant. Ce rapport n\'est pas une déclaration de conformité.'**
  String get craHelp;

  /// CRA : champ du fichier SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Fichier SBOM à évaluer'**
  String get craSbomField;

  /// CRA : section des métadonnées produit.
  ///
  /// In fr, this message translates to:
  /// **'Métadonnées produit (facultatif)'**
  String get craProductMeta;

  /// CRA : champ fabricant.
  ///
  /// In fr, this message translates to:
  /// **'Fabricant'**
  String get craManufacturer;

  /// CRA : champ produit.
  ///
  /// In fr, this message translates to:
  /// **'Produit'**
  String get craProduct;

  /// CRA : champ version du produit.
  ///
  /// In fr, this message translates to:
  /// **'Version du produit'**
  String get craProductVersion;

  /// CRA : champ fin de support.
  ///
  /// In fr, this message translates to:
  /// **'Fin de support (AAAA-MM-JJ)'**
  String get craSupportUntil;

  /// CRA : champ contact de signalement.
  ///
  /// In fr, this message translates to:
  /// **'Contact de signalement des vulnérabilités'**
  String get craVulnContact;

  /// CRA : champ URL de la politique de divulgation.
  ///
  /// In fr, this message translates to:
  /// **'URL de la politique de divulgation coordonnée'**
  String get craCvdUrl;

  /// CRA : bouton de chargement du fichier de configuration.
  ///
  /// In fr, this message translates to:
  /// **'Charger un cra.yaml'**
  String get craLoadConfig;

  /// CRA : fichier de configuration chargé.
  ///
  /// In fr, this message translates to:
  /// **'cra.yaml : {name}'**
  String craConfigLoaded(String name);

  /// CRA : case d'analyse des vulnérabilités.
  ///
  /// In fr, this message translates to:
  /// **'Analyser les vulnérabilités connues'**
  String get craScanVulns;

  /// CRA : choix des trois scanners.
  ///
  /// In fr, this message translates to:
  /// **'Les trois'**
  String get craScannerAll;

  /// CRA : bouton d'évaluation.
  ///
  /// In fr, this message translates to:
  /// **'Évaluer'**
  String get craEvaluate;

  /// CRA : bouton d'export PDF.
  ///
  /// In fr, this message translates to:
  /// **'Exporter le rapport PDF'**
  String get craExportPdf;

  /// CRA : statut conforme.
  ///
  /// In fr, this message translates to:
  /// **'Conforme'**
  String get craStatusOk;

  /// CRA : statut partiel.
  ///
  /// In fr, this message translates to:
  /// **'Partiel'**
  String get craStatusPartial;

  /// CRA : statut non conforme.
  ///
  /// In fr, this message translates to:
  /// **'Non conforme'**
  String get craStatusFail;

  /// CRA : statut non évalué.
  ///
  /// In fr, this message translates to:
  /// **'Non évalué'**
  String get craStatusNa;

  /// CRA : ligne de verdict.
  ///
  /// In fr, this message translates to:
  /// **'Verdict (périmètre vérifié) : {status}'**
  String craVerdict(String status);

  /// CRA : tuile du nombre de champs conformes.
  ///
  /// In fr, this message translates to:
  /// **'Champs SBOM conformes'**
  String get craTileFields;

  /// CRA : tuile des éléments NTIA.
  ///
  /// In fr, this message translates to:
  /// **'Éléments NTIA'**
  String get craTileNtia;

  /// CRA : tuile des vulnérabilités sans correctif.
  ///
  /// In fr, this message translates to:
  /// **'Vuln. sans correctif'**
  String get craTileNoFix;

  /// CRA : tuile des CVE exploitées.
  ///
  /// In fr, this message translates to:
  /// **'CVE exploitées (KEV)'**
  String get craTileKev;

  /// CRA : titre de la liste des points bloquants.
  ///
  /// In fr, this message translates to:
  /// **'Points bloquants'**
  String get craBlockers;

  /// CRA : titre du tableau des champs.
  ///
  /// In fr, this message translates to:
  /// **'Champs de données SBOM (BSI TR-03183-2)'**
  String get craFieldsTitle;

  /// CRA : en-tête de colonne champ.
  ///
  /// In fr, this message translates to:
  /// **'Champ'**
  String get craThField;

  /// CRA : en-tête de colonne couverture.
  ///
  /// In fr, this message translates to:
  /// **'Couverture'**
  String get craThCoverage;

  /// CRA : en-tête de colonne statut.
  ///
  /// In fr, this message translates to:
  /// **'Statut'**
  String get craThStatus;

  /// CRA : résumé du SBOM évalué.
  ///
  /// In fr, this message translates to:
  /// **'SBOM : {format} — {components} composants, {relations} relations de dépendance.'**
  String craSbomSummary(String format, String components, String relations);

  /// CRA : résumé des vulnérabilités.
  ///
  /// In fr, this message translates to:
  /// **'Vulnérabilités : {total} CVE — {critical} critiques, {high} élevées.'**
  String craVulnSummary(String total, String critical, String high);

  /// CRA : rappel de la notification ENISA.
  ///
  /// In fr, this message translates to:
  /// **' ⚠ Notification ENISA sous 24 h requise (art. 14).'**
  String get craEnisaNotice;

  /// Bouton : arrêter l'analyse en cours.
  ///
  /// In fr, this message translates to:
  /// **'Arrêter'**
  String get commonStopAction;

  /// Cible d'un scan (rapports) : une image.
  ///
  /// In fr, this message translates to:
  /// **'image « {target} »'**
  String scanTargetImage(String target);

  /// Cible d'un scan (rapports) : un fichier SBOM.
  ///
  /// In fr, this message translates to:
  /// **'SBOM {name}'**
  String scanTargetSbom(String name);

  /// Aperçu de commande : marque de remplacement du chemin d'un paquet.
  ///
  /// In fr, this message translates to:
  /// **'<paquet>'**
  String get cliPlaceholderPackage;

  /// Bannière de résultat : nombre de vulnérabilités (suivi des compteurs par sévérité).
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} vulnérabilité} other{{count} vulnérabilités}} — '**
  String scanBannerCount(int count);

  /// Onglet de résultats : tableau des vulnérabilités.
  ///
  /// In fr, this message translates to:
  /// **'Vulnérabilités'**
  String get scanTabVulns;

  /// Onglet de résultats : sortie JSON brute.
  ///
  /// In fr, this message translates to:
  /// **'JSON brut'**
  String get scanTabRawJson;

  /// Texte d'accueil des onglets de scan.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionnez un SBOM ou une image et lancez l\'analyse'**
  String get scanHintPick;

  /// Texte affiché pendant un scan.
  ///
  /// In fr, this message translates to:
  /// **'Analyse {tool} en cours…'**
  String scanRunningTool(String tool);

  /// Bouton : lancer un scan avec l'outil.
  ///
  /// In fr, this message translates to:
  /// **'Analyser avec {tool}'**
  String scanRunButton(String tool);

  /// Bannière : aucun résultat.
  ///
  /// In fr, this message translates to:
  /// **'Aucune vulnérabilité trouvée'**
  String get scanNoVulnFound;

  /// Aide : champ plateforme d'un scan d'image.
  ///
  /// In fr, this message translates to:
  /// **'Optionnel. Force la plateforme cible sur une\nimage multi-architecture, ex. linux/arm64.\nLaisser vide = détection automatique par {tool}.'**
  String scanPlatformHelp(String tool);

  /// Titre du sélecteur de fichier trivy.yaml.
  ///
  /// In fr, this message translates to:
  /// **'Choisir trivy.yaml'**
  String get trivyPickConfigTitle;

  /// Trivy : libellé du filtre de sévérité.
  ///
  /// In fr, this message translates to:
  /// **'--severity (laisser vide = tout)'**
  String get trivySeverityLabel;

  /// Trivy : aide du filtre de sévérité.
  ///
  /// In fr, this message translates to:
  /// **'Filtres de sévérité. Seules les vulnérabilités\ndont la sévérité est cochée sont affichées.\nLaisser vide = toutes les sévérités.'**
  String get trivySeverityHelp;

  /// Trivy : aide de --ignore-unfixed.
  ///
  /// In fr, this message translates to:
  /// **'Masque les vulnérabilités sans version\ncorrigée disponible. Réduit le bruit\ndans les résultats.'**
  String get trivyIgnoreUnfixedHelp;

  /// Trivy : aide de --skip-db-update.
  ///
  /// In fr, this message translates to:
  /// **'Utilise la base CVE locale sans la mettre\nà jour. Accélère les analyses successives,\nmais la base peut être obsolète.'**
  String get trivySkipDbHelp;

  /// Trivy : libellé du champ de configuration.
  ///
  /// In fr, this message translates to:
  /// **'trivy.yaml (optionnel)'**
  String get trivyConfigLabel;

  /// Trivy : aide du champ de configuration.
  ///
  /// In fr, this message translates to:
  /// **'Fichier de configuration Trivy (YAML).\nPermet de définir des politiques, des\nexceptions ou des sources personnalisées.'**
  String get trivyConfigHelp;

  /// Trivy : exemple de chemin du fichier de configuration.
  ///
  /// In fr, this message translates to:
  /// **'/chemin/vers/trivy.yaml'**
  String get trivyConfigHint;

  /// Aperçu de commande : option non transposable (fichier de configuration).
  ///
  /// In fr, this message translates to:
  /// **'fichier de config'**
  String get trivyCliConfigNote;

  /// Aperçu de commande : option non transposable (plateforme).
  ///
  /// In fr, this message translates to:
  /// **'plateforme'**
  String get trivyCliPlatformNote;

  /// Titre du sélecteur de fichier osv-scanner.toml.
  ///
  /// In fr, this message translates to:
  /// **'Choisir osv-scanner.toml'**
  String get osvPickConfigTitle;

  /// OSV-Scanner : libellé du champ de configuration.
  ///
  /// In fr, this message translates to:
  /// **'Fichier de config (optionnel)'**
  String get osvConfigLabel;

  /// OSV-Scanner : aide du champ de configuration.
  ///
  /// In fr, this message translates to:
  /// **'Fichier TOML de configuration osv-scanner.\nPermet d\'exclure des CVE, de configurer\ndes sources ou de définir des politiques.'**
  String get osvConfigHelp;

  /// Aperçu de commande : option non transposable (config toml).
  ///
  /// In fr, this message translates to:
  /// **'fichier de config (toml)'**
  String get osvCliConfigNote;

  /// OSV-Scanner : en-tête de la colonne écosystème.
  ///
  /// In fr, this message translates to:
  /// **'ÉCOSYSTÈME'**
  String get osvEcosystemColumn;

  /// En-tête CSV de l'export Grype.
  ///
  /// In fr, this message translates to:
  /// **'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Type,Emplacements'**
  String get vulnCsvHeaderGrype;

  /// En-tête CSV de l'export Trivy.
  ///
  /// In fr, this message translates to:
  /// **'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Titre,Emplacements'**
  String get vulnCsvHeaderTrivy;

  /// En-tête CSV de l'export OSV-Scanner.
  ///
  /// In fr, this message translates to:
  /// **'Sévérité,CVE / ID,Paquet,Version installée,Version corrigée,Écosystème,Emplacements'**
  String get vulnCsvHeaderOsv;

  /// Rapport : libellé de sévérité « autre » (badge, majuscules).
  ///
  /// In fr, this message translates to:
  /// **'AUTRE'**
  String get pdfSeverityOther;

  /// Rapport du tableau de bord (AsciiDoc) : titre du document.
  ///
  /// In fr, this message translates to:
  /// **'= Rapport de vulnérabilités: Synthèse inter-scanners'**
  String get repTitle;

  /// Rapport : titre du sommaire.
  ///
  /// In fr, this message translates to:
  /// **':toc-title: Sommaire'**
  String get repTocTitle;

  /// Rapport : titre de la section « résumé exécutif ».
  ///
  /// In fr, this message translates to:
  /// **'== Résumé exécutif'**
  String get repExecSummary;

  /// Rapport : une cible analysée.
  ///
  /// In fr, this message translates to:
  /// **'*Cible analysée* : {target} +'**
  String repTarget(String target);

  /// Rapport : plusieurs cibles analysées.
  ///
  /// In fr, this message translates to:
  /// **'*Cibles analysées* : {targets} +'**
  String repTargets(String targets);

  /// Rapport : nombre de scanners exécutés et de CVE uniques.
  ///
  /// In fr, this message translates to:
  /// **'*Scanners exécutés* : {run} / 3{names} — *{unique}* CVE uniques'**
  String repScannersRun(int run, String names, int unique);

  /// Rapport : note sur le filtre de sévérité.
  ///
  /// In fr, this message translates to:
  /// **'NOTE: Filtre de sévérité : *{label}* — {kept} CVE retenue(s){ofTotal}, d\'après la pire sévérité rapportée par les scanners. Les CVE au catalogue CISA KEV sont incluses quelle que soit leur sévérité. Tout le rapport (compteurs, répartition, couches, comparaison, détail) porte sur ce sous-ensemble.'**
  String repThresholdNote(String label, int kept, String ofTotal);

  /// Rapport : suite de la note de filtre (total avant filtrage).
  ///
  /// In fr, this message translates to:
  /// **' sur {total}'**
  String repThresholdOf(int total);

  /// Rapport : en-têtes du bandeau de chiffres clés.
  ///
  /// In fr, this message translates to:
  /// **'h| Critiques h| Élevées h| CISA KEV h| EPSS ≥ 10 %'**
  String get repStatsHeader;

  /// Rapport : verdict en présence de CVE KEV.
  ///
  /// In fr, this message translates to:
  /// **'Action immédiate requise. {kev, plural, one{{kev} CVE du catalogue CISA KEV est exploitée} other{{kev} CVE du catalogue CISA KEV sont exploitées}} activement dans la nature — appliquer les correctifs sans délai.'**
  String repVerdictKev(int kev);

  /// Rapport : verdict en présence de CVE critiques.
  ///
  /// In fr, this message translates to:
  /// **'Action prioritaire. {count, plural, one{{count} vulnérabilité critique à corriger} other{{count} vulnérabilités critiques à corriger}} en priorité.'**
  String repVerdictCritical(int count);

  /// Rapport : verdict en présence de CVE élevées.
  ///
  /// In fr, this message translates to:
  /// **'À traiter. {count, plural, one{{count} vulnérabilité de sévérité élevée identifiée} other{{count} vulnérabilités de sévérité élevée identifiées}}.'**
  String repVerdictHigh(int count);

  /// Rapport : verdict sans CVE critique ni élevée.
  ///
  /// In fr, this message translates to:
  /// **'Aucune vulnérabilité critique ni élevée détectée par les scanners exécutés.'**
  String get repVerdictOk;

  /// Rapport : section des outils.
  ///
  /// In fr, this message translates to:
  /// **'== Outils'**
  String get repTools;

  /// Rapport : en-tête du tableau des outils.
  ///
  /// In fr, this message translates to:
  /// **'| Outil | Version'**
  String get repToolHeader;

  /// Rapport : section de la répartition par scanner.
  ///
  /// In fr, this message translates to:
  /// **'== Répartition par scanner'**
  String get repBreakdown;

  /// Rapport : scanner non exécuté.
  ///
  /// In fr, this message translates to:
  /// **'_Non exécuté._'**
  String get repNotRun;

  /// Rapport : aucun résultat pour un scanner.
  ///
  /// In fr, this message translates to:
  /// **'Aucune vulnérabilité détectée.'**
  String get repNoVuln;

  /// Rapport : en-tête du tableau sévérité / nombre.
  ///
  /// In fr, this message translates to:
  /// **'| Sévérité | Nombre'**
  String get repSevCountHeader;

  /// Rapport : section des couches.
  ///
  /// In fr, this message translates to:
  /// **'== Couches de l\'image'**
  String get repLayersTitle;

  /// Rapport : méthode d'analyse par couche.
  ///
  /// In fr, this message translates to:
  /// **'Méthode : {methods}.'**
  String repMethod(String methods);

  /// Rapport : en-tête du tableau des couches.
  ///
  /// In fr, this message translates to:
  /// **'| Couche | Digest | Instruction | CVE | Critiques | Élevées'**
  String get repLayersHeader;

  /// Rapport : section de comparaison.
  ///
  /// In fr, this message translates to:
  /// **'== Comparaison inter-scanners'**
  String get repCompareTitle;

  /// Rapport : colonne des couches.
  ///
  /// In fr, this message translates to:
  /// **' | Couche(s)'**
  String get repLayersColumn;

  /// Rapport : comparaison vide.
  ///
  /// In fr, this message translates to:
  /// **'_Aucune CVE détectée par les scanners exécutés._'**
  String get repNoCve;

  /// Rapport : en-tête de la comparaison avec exploitabilité.
  ///
  /// In fr, this message translates to:
  /// **'| Sévérité | CVE / ID | KEV | EPSS | Grype | OSV | Trivy{layerHead}'**
  String repCompareHeaderExploit(String layerHead);

  /// Rapport : en-tête de la comparaison.
  ///
  /// In fr, this message translates to:
  /// **'| Sévérité | CVE / ID | Grype | OSV | Trivy{layerHead}'**
  String repCompareHeader(String layerHead);

  /// Rapport : encadré expliquant les écarts entre scanners.
  ///
  /// In fr, this message translates to:
  /// **'Des comptages très différents entre scanners sur les paquets système (Debian/Alpine/RPM) ne signalent pas forcément une erreur. OSV-Scanner peut ne trouver aucune CVE sur ces paquets lorsqu\'il est lancé en mode « scan de SBOM » : son API n\'indexe les avis Debian que sous une forme de purl précise, absente du SBOM standard produit par syft — scanner l\'image directement (`osv-scanner scan image`) donne une couverture fiable. Grype et Trivy n\'ont par ailleurs pas la même exhaustivité sur ces mêmes paquets : Grype reprend l\'intégralité du Debian Security Tracker (avis « won\'t fix » inclus) là où Trivy ne remonte qu\'un sous-ensemble plus restreint. Aucun des deux scanners n\'a tort — leurs chiffres bruts ne sont simplement pas directement comparables sur ce type de paquet. Détails et méthode de vérification dans la documentation utilisateur, section « Pourquoi Grype, OSV-Scanner et Trivy ne trouvent pas les mêmes CVE ».'**
  String get repScannerNote;

  /// Rapport : section de détail des CVE.
  ///
  /// In fr, this message translates to:
  /// **'== Détail des CVE'**
  String get repDetailTitle;

  /// Rapport : nombre de CVE détaillées (tout le jeu).
  ///
  /// In fr, this message translates to:
  /// **'{count} CVE.'**
  String repDetailAll(int count);

  /// Rapport : nombre de CVE détaillées avec seuil.
  ///
  /// In fr, this message translates to:
  /// **'{count} CVE retenue(s) : sévérité {label} ou au catalogue CISA KEV.'**
  String repDetailKept(int count, String label);

  /// Titre du dialogue d'export du tableau de bord.
  ///
  /// In fr, this message translates to:
  /// **'Exporter le tableau de bord (AsciiDoc + PDF)'**
  String get dashExportTitle;

  /// Nom de fichier proposé pour le rapport du tableau de bord.
  ///
  /// In fr, this message translates to:
  /// **'rapport-vulnerabilites.adoc'**
  String get dashExportFileAll;

  /// Nom de fichier proposé pour le rapport avec seuil de sévérité.
  ///
  /// In fr, this message translates to:
  /// **'rapport-vulnerabilites-{threshold}.adoc'**
  String dashExportFileThreshold(String threshold);

  /// Message : rapport exporté en AsciiDoc et PDF.
  ///
  /// In fr, this message translates to:
  /// **'Tableau de bord exporté → {path} et {pdf}'**
  String dashExported(String path, String pdf);

  /// Message : conversion PDF échouée.
  ///
  /// In fr, this message translates to:
  /// **'Tableau de bord exporté → {path} (échec conversion PDF, code {code})'**
  String dashExportedPdfFailed(String path, int code);

  /// Message : asciidoctor-pdf absent.
  ///
  /// In fr, this message translates to:
  /// **'Tableau de bord exporté → {path} (asciidoctor-pdf introuvable, PDF non généré)'**
  String dashExportedNoPdf(String path);

  /// Tableau de bord : titre.
  ///
  /// In fr, this message translates to:
  /// **'Tableau de bord des vulnérabilités'**
  String get dashTitle;

  /// Tableau de bord : aucun scan lancé.
  ///
  /// In fr, this message translates to:
  /// **'Aucun scanner exécuté — lancez un scan depuis les onglets Grype, OSV-Scanner ou Trivy.'**
  String get dashNoScan;

  /// Tableau de bord : résumé du nombre de scanners et de CVE.
  ///
  /// In fr, this message translates to:
  /// **'{scans, plural, one{{scans} scanner exécuté} other{{scans} scanners exécutés}} · {ids, plural, one{{ids} CVE unique détectée} other{{ids} CVE uniques détectées}}'**
  String dashScanSummary(int scans, int ids);

  /// Tableau de bord : badge du nombre de CVE uniques.
  ///
  /// In fr, this message translates to:
  /// **'CVE uniques'**
  String get dashUniqueCves;

  /// Info-bulle : seuil de sévérité du rapport.
  ///
  /// In fr, this message translates to:
  /// **'Sévérité minimale des CVE du rapport PDF (les CVE CISA KEV sont toujours incluses)'**
  String get dashThresholdTooltip;

  /// Carte scanner : scanner non exécuté.
  ///
  /// In fr, this message translates to:
  /// **'Non exécuté'**
  String get dashNotRun;

  /// Carte scanner : aucune vulnérabilité.
  ///
  /// In fr, this message translates to:
  /// **'✓ Aucune'**
  String get dashNone;

  /// Carte scanner : nombre de vulnérabilités.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, one{{count} vulnérabilité} other{{count} vulnérabilités}}'**
  String dashTotalVulns(int count);

  /// Carte scanner : invite à lancer le scan depuis l'onglet.
  ///
  /// In fr, this message translates to:
  /// **'Lancez le scan depuis\nl\'onglet {name}'**
  String dashRunScanFrom(String name);

  /// Carte scanner : sévérités regroupées « autre ».
  ///
  /// In fr, this message translates to:
  /// **'Autre'**
  String get dashOtherSeverity;

  /// Tableau de bord : titre de la comparaison (début, avant l'éventuel compteur KEV).
  ///
  /// In fr, this message translates to:
  /// **'Comparaison inter-scanners ({count} CVE'**
  String dashCompareTitle(int count);

  /// Tableau de bord : suite du titre de comparaison.
  ///
  /// In fr, this message translates to:
  /// **', dont {kev} CISA KEV'**
  String dashCompareKev(int kev);

  /// Comparaison : en-tête de colonne sévérité (abrégé).
  ///
  /// In fr, this message translates to:
  /// **'SÉV.'**
  String get dashHdrSeverity;

  /// Comparaison : en-tête de colonne couches.
  ///
  /// In fr, this message translates to:
  /// **'COUCHE(S)'**
  String get dashHdrLayers;

  /// Info-bulle : CVE vue par un seul scanner.
  ///
  /// In fr, this message translates to:
  /// **'Vu par un seul scanner sur {count}'**
  String dashSeenByOne(int count);

  /// Info-bulle : score EPSS.
  ///
  /// In fr, this message translates to:
  /// **'EPSS {score} — probabilité d\'exploitation à 30 jours (percentile {pct})'**
  String dashEpssTooltip(String score, int pct);

  /// Carte des couches : titre.
  ///
  /// In fr, this message translates to:
  /// **'Couches de l\'image ({count})'**
  String dashLayersCard(int count);

  /// Carte des couches : en-tête de colonne couche.
  ///
  /// In fr, this message translates to:
  /// **'COUCHE'**
  String get dashHdrLayer;

  /// Carte des couches : en-tête de colonne élevées.
  ///
  /// In fr, this message translates to:
  /// **'ÉLEV.'**
  String get dashHdrHigh;

  /// Titre du panneau de configuration.
  ///
  /// In fr, this message translates to:
  /// **'Configuration'**
  String get cfgTitle;

  /// Infobulle du bouton des profils.
  ///
  /// In fr, this message translates to:
  /// **'Profils de configuration'**
  String get cfgProfilesTooltip;

  /// Titre de section.
  ///
  /// In fr, this message translates to:
  /// **'Entrée'**
  String get cfgSectionInput;

  /// Titre de section.
  ///
  /// In fr, this message translates to:
  /// **'Sortie'**
  String get cfgSectionOutput;

  /// Titre de section.
  ///
  /// In fr, this message translates to:
  /// **'Options'**
  String get cfgSectionOptions;

  /// Libellé du champ d'entrée.
  ///
  /// In fr, this message translates to:
  /// **'Paquets à analyser (--input)'**
  String get cfgInputLabel;

  /// Indication pendant un glisser-déposer.
  ///
  /// In fr, this message translates to:
  /// **'Déposez un fichier ou un dossier ici…'**
  String get cfgInputHintDrop;

  /// Indication du champ d'entrée.
  ///
  /// In fr, this message translates to:
  /// **'rpm.lst, un .jar, ou un dossier…'**
  String get cfgInputHint;

  /// Aide du champ d'entrée.
  ///
  /// In fr, this message translates to:
  /// **'Fichier liste (une référence par ligne),\nune archive/un paquet unique (.rpm, .deb,\n.whl, .jar, .zip, .tar.gz…), ou un dossier\nscanné récursivement pour tous ces types.'**
  String get cfgInputHelp;

  /// Titre du sélecteur de fichier.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner le fichier d\'entrée'**
  String get cfgPickInputFile;

  /// Titre du sélecteur de dossier.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner un dossier de paquets'**
  String get cfgPickPackagesDir;

  /// Erreur de validation.
  ///
  /// In fr, this message translates to:
  /// **'Requis (ou spécifiez une image OCI / un binaire)'**
  String get cfgInputRequired;

  /// Indication de glisser-déposer.
  ///
  /// In fr, this message translates to:
  /// **'Glissez-déposez un fichier ou un dossier depuis votre gestionnaire'**
  String get cfgDragHint;

  /// Séparateur entre types d'entrée.
  ///
  /// In fr, this message translates to:
  /// **'OU'**
  String get cfgOr;

  /// Titre du sélecteur.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner une archive OCI'**
  String get cfgPickOciArchive;

  /// Titre du sélecteur.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner un répertoire OCI layout'**
  String get cfgPickOciDir;

  /// Titre du sélecteur.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionner un binaire'**
  String get cfgPickBinary;

  /// Note sous le champ binaire.
  ///
  /// In fr, this message translates to:
  /// **'Backend : syft (forcé — seul capable d\'analyser un binaire autonome)'**
  String get cfgBinarySyftForced;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Chemin de base (--output)'**
  String get cfgOutputBase;

  /// Indication.
  ///
  /// In fr, this message translates to:
  /// **'sbom  →  sbom.cdx.json, sbom.spdx.json…'**
  String get cfgOutputBaseHint;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Préfixe du chemin de sortie. Le suffixe de\nformat est ajouté automatiquement.\nEx : sbom → sbom.cdx.json, sbom.spdx.json…'**
  String get cfgOutputBaseHelp;

  /// Titre du dialogue d'enregistrement.
  ///
  /// In fr, this message translates to:
  /// **'Chemin de base du SBOM'**
  String get cfgOutputBaseTitle;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Formats (--format)'**
  String get cfgFormats;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Sélectionnez un ou plusieurs formats de sortie.\nCycloneDX (1.6 ou 1.7) et SPDX sont les standards industrie.\nMarkdown et AsciiDoc sont lisibles directement.'**
  String get cfgFormatsHelp;

  /// Case à cocher.
  ///
  /// In fr, this message translates to:
  /// **'Convertir en PDF (asciidoctor-pdf)'**
  String get cfgPdf;

  /// Sous-titre.
  ///
  /// In fr, this message translates to:
  /// **'Lance asciidoctor-pdf après la génération'**
  String get cfgPdfSub;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Chemin du PDF (optionnel)'**
  String get cfgPdfPath;

  /// Indication.
  ///
  /// In fr, this message translates to:
  /// **'Défaut : même dossier que .adoc'**
  String get cfgPdfPathHint;

  /// Titre du dialogue.
  ///
  /// In fr, this message translates to:
  /// **'Enregistrer le PDF sous…'**
  String get cfgPdfSaveTitle;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Nom du document SBOM (--name)'**
  String get cfgName;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Nom logique du document SBOM\n(champ metadata.component.name).\nEx : \"Mon Application 1.0\"'**
  String get cfgNameHelp;

  /// Indication.
  ///
  /// In fr, this message translates to:
  /// **'Mon Application 1.0'**
  String get cfgNameHint;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Répertoire RPM local (--rpm-dir)'**
  String get cfgRpmDir;

  /// Indication.
  ///
  /// In fr, this message translates to:
  /// **'Dossier contenant des fichiers .rpm'**
  String get cfgRpmDirHint;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Dossier contenant des fichiers .rpm.\nsbom_generator extrait les métadonnées\nsans installer les paquets (rpm -qp).'**
  String get cfgRpmDirHelp;

  /// Titre du sélecteur.
  ///
  /// In fr, this message translates to:
  /// **'Répertoire de fichiers RPM'**
  String get cfgRpmDirTitle;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Override licences (--license-map)'**
  String get cfgLicenseMap;

  /// Indication.
  ///
  /// In fr, this message translates to:
  /// **'Fichier \"paquet: SPDX-expression\"'**
  String get cfgLicenseMapHint;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Fichier de substitution de licences,\nformat \"paquet: SPDX-expression\" par ligne.\nEx : mon-paquet-interne: MIT'**
  String get cfgLicenseMapHelp;

  /// Titre du sélecteur.
  ///
  /// In fr, this message translates to:
  /// **'Fichier de map licences'**
  String get cfgLicenseMapTitle;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Concurrence (--concurrency)'**
  String get cfgConcurrency;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Nombre de paquets analysés simultanément.\n0 = illimité (tous en parallèle).\nRéduire si les outils externes nécessitent\ndes accès exclusifs ou si la machine est lente.'**
  String get cfgConcurrencyHelp;

  /// Valeur du curseur de concurrence.
  ///
  /// In fr, this message translates to:
  /// **'illimitée'**
  String get cfgUnlimited;

  /// Note.
  ///
  /// In fr, this message translates to:
  /// **'0 = tous les paquets en parallèle'**
  String get cfgConcurrencyZero;

  /// Note.
  ///
  /// In fr, this message translates to:
  /// **'1 = séquentiel  •  défaut : 4'**
  String get cfgConcurrencyNote;

  /// Case à cocher.
  ///
  /// In fr, this message translates to:
  /// **'Mode verbeux (--verbose)'**
  String get cfgVerbose;

  /// Sous-titre.
  ///
  /// In fr, this message translates to:
  /// **'Affiche les outils détectés et les statistiques'**
  String get cfgVerboseSub;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Affiche pour chaque paquet : outil utilisé,\nversion, durée de traitement.\nUtile pour déboguer les paquets dont la\nlicence n\'est pas reconnue.'**
  String get cfgVerboseHelp;

  /// Case à cocher.
  ///
  /// In fr, this message translates to:
  /// **'Score qualité sbomqs'**
  String get cfgSbomqs;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Exécute sbomqs (Interlynk) sur le SBOM généré\npour calculer un score de conformité (0–10).\nRequiert que sbomqs soit installé dans le PATH.'**
  String get cfgSbomqsHelp;

  /// Sous-titre.
  ///
  /// In fr, this message translates to:
  /// **'Analyse le SBOM généré avec sbomqs après génération'**
  String get cfgSbomqsSub;

  /// Bouton.
  ///
  /// In fr, this message translates to:
  /// **'Arrêter la génération'**
  String get cfgStop;

  /// Bouton.
  ///
  /// In fr, this message translates to:
  /// **'Générer le SBOM'**
  String get cfgGenerate;

  /// Infobulle.
  ///
  /// In fr, this message translates to:
  /// **'Copier la commande'**
  String get cfgCopyCommand;

  /// Infobulle des boutons de sélection.
  ///
  /// In fr, this message translates to:
  /// **'Parcourir…'**
  String get cfgBrowse;

  /// Entrée de menu.
  ///
  /// In fr, this message translates to:
  /// **'Type filtré ({filter})'**
  String cfgPickFiltered(String filter);

  /// Entrée de menu.
  ///
  /// In fr, this message translates to:
  /// **'Tous les fichiers'**
  String get cfgPickAny;

  /// Entrée de menu.
  ///
  /// In fr, this message translates to:
  /// **'Dossier (scan récursif)'**
  String get cfgPickDirRecursive;

  /// Titre.
  ///
  /// In fr, this message translates to:
  /// **'Fichiers qui seront générés :'**
  String get cfgFilesToGenerate;

  /// Titre du dialogue.
  ///
  /// In fr, this message translates to:
  /// **'Supprimer le profil'**
  String get cfgProfDeleteTitle;

  /// Confirmation.
  ///
  /// In fr, this message translates to:
  /// **'Supprimer « {name} » ?'**
  String cfgProfDeleteConfirm(String name);

  /// Bouton.
  ///
  /// In fr, this message translates to:
  /// **'Supprimer'**
  String get cfgDelete;

  /// Titre du dialogue.
  ///
  /// In fr, this message translates to:
  /// **'Profils de configuration'**
  String get cfgProfTitle;

  /// Titre.
  ///
  /// In fr, this message translates to:
  /// **'Enregistrer la configuration actuelle'**
  String get cfgProfSaveCurrent;

  /// Indication.
  ///
  /// In fr, this message translates to:
  /// **'Nom du profil…'**
  String get cfgProfNameHint;

  /// Bouton.
  ///
  /// In fr, this message translates to:
  /// **'Enregistrer'**
  String get cfgProfSave;

  /// Titre.
  ///
  /// In fr, this message translates to:
  /// **'Profils enregistrés'**
  String get cfgProfSaved;

  /// Liste vide.
  ///
  /// In fr, this message translates to:
  /// **'Aucun profil enregistré.'**
  String get cfgProfNone;

  /// Bouton.
  ///
  /// In fr, this message translates to:
  /// **'Charger'**
  String get cfgProfLoad;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Image OCI (--image)'**
  String get cfgOciLabel;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Référence d\'une image conteneur à analyser.\n• Registre : nginx:latest, ghcr.io/org/app:v1\n• Archive tar : ./image.tar / .tar.gz / .tgz (docker save)\n• Répertoire OCI layout : ./oci/ (index.json)'**
  String get cfgOciHelp;

  /// Indication.
  ///
  /// In fr, this message translates to:
  /// **'nginx:latest  •  ./image.tar(.gz)  •  ./oci_dir/'**
  String get cfgOciHint;

  /// Entrée de menu.
  ///
  /// In fr, this message translates to:
  /// **'Archive tar (.tar / .tar.gz / .tgz)'**
  String get cfgOciTar;

  /// Entrée de menu.
  ///
  /// In fr, this message translates to:
  /// **'Répertoire OCI layout'**
  String get cfgOciDir;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Binaire autonome (--binary)'**
  String get cfgBinaryLabel;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Exécutable local à analyser directement (pas une image de conteneur) — ex. un binaire Go lié statiquement.\nForce le backend syft : seul capable de lire les métadonnées embarquées dans un binaire (buildinfo Go via go-module-binary-cataloger ; classifieur générique syft pour quelques bibliothèques connues — OpenSSL, zlib, sqlite…).\nNe récupère pas les dépendances liées statiquement sans métadonnée embarquée (C/C++ « fait maison », Rust sans cargo-auditable).'**
  String get cfgBinaryHelp;

  /// Indication.
  ///
  /// In fr, this message translates to:
  /// **'/usr/local/bin/mon-app'**
  String get cfgBinaryHint;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Profondeur (--depth)'**
  String get cfgDepthLabel;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Descend dans les objets contenus dans l\'entrée : par exemple les jars d\'un RPM, les paquets ou archives d\'un tar.gz, les jars d\'un fat jar.\n• 0 : l\'objet seul (défaut)\n• N : N niveaux (1 = objets directs, 2 = ce qu\'ils contiennent…)\n• Illimitée : tous les niveaux (plafonnés à 10)\nLes manifestes rencontrés (package-lock.json, go.sum, pom.xml…) sont analysés. Le SBOM global fusionne tous les composants (propriétés location/depth, dépendances parent → enfant). Extraction bornée en taille.'**
  String get cfgDepthHelp;

  /// Option de profondeur.
  ///
  /// In fr, this message translates to:
  /// **'0 — objet seul'**
  String get cfgDepth0;

  /// Option de profondeur.
  ///
  /// In fr, this message translates to:
  /// **'Illimitée'**
  String get cfgDepthAll;

  /// Option de profondeur.
  ///
  /// In fr, this message translates to:
  /// **'1 niveau'**
  String get cfgDepth1;

  /// Option de profondeur.
  ///
  /// In fr, this message translates to:
  /// **'{n} niveaux'**
  String cfgDepthN(String n);

  /// Case à cocher.
  ///
  /// In fr, this message translates to:
  /// **'Un SBOM par objet imbriqué'**
  String get cfgNestedFiles;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'En plus du SBOM fusionné, écrit un SBOM par objet imbriqué (<sortie>.nested-NN-<objet>.<ext>, dans chaque format coché). Décocher = --no-nested-files : fusionné seulement.'**
  String get cfgNestedFilesHelp;

  /// Case à cocher.
  ///
  /// In fr, this message translates to:
  /// **'Un SBOM par couche (--per-layer)'**
  String get cfgPerLayer;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Génère, en plus du SBOM global, un SBOM par couche de l\'image (<sortie>.layer-NN-<digest>.<ext>, dans chaque format coché) décrivant le delta de la couche : composants ajoutés ou modifiés, composants supprimés listés à part. Le SBOM global indique la couche d\'origine de chaque composant.\n• Métadonnées : couche d\'origine indiquée par Syft/Trivy — rapide, ajouts seulement\n• Rootfs : couches appliquées une à une et réanalysées — ajouts, modifications, suppressions (seul mode possible avec Skopeo et cdxgen)'**
  String get cfgPerLayerHelp;

  /// Segment.
  ///
  /// In fr, this message translates to:
  /// **'Métadonnées'**
  String get cfgLayerMetadata;

  /// Infobulle.
  ///
  /// In fr, this message translates to:
  /// **'Couche d\'origine indiquée par le backend'**
  String get cfgLayerMetadataTip;

  /// Segment.
  ///
  /// In fr, this message translates to:
  /// **'Rootfs'**
  String get cfgLayerRootfs;

  /// Infobulle.
  ///
  /// In fr, this message translates to:
  /// **'Réanalyse du rootfs après chaque couche'**
  String get cfgLayerRootfsTip;

  /// Note.
  ///
  /// In fr, this message translates to:
  /// **'Mode rootfs forcé : {tool} n\'indique pas la couche d\'origine des paquets'**
  String cfgRootfsForced(String tool);

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Backend OCI (--oci-tool)'**
  String get cfgOciToolLabel;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'Outil utilisé pour extraire les paquets de l\'image :\n• Syft (Anchore) — le plus complet, tous écosystèmes\n• Trivy (Aqua) — rapide, CVE intégrées\n• Skopeo — extraction manuelle dpkg/rpm/apk\n• cdxgen (OWASP) — CycloneDX natif, tous écosystèmes'**
  String get cfgOciToolHelp;

  /// Infobulle.
  ///
  /// In fr, this message translates to:
  /// **'Anchore Syft — tous écosystèmes'**
  String get cfgSyftTip;

  /// Infobulle.
  ///
  /// In fr, this message translates to:
  /// **'Aqua Trivy — tous écosystèmes'**
  String get cfgTrivyTip;

  /// Infobulle.
  ///
  /// In fr, this message translates to:
  /// **'Skopeo + extraction manuelle (dpkg/rpm/apk)'**
  String get cfgSkopeoTip;

  /// Infobulle.
  ///
  /// In fr, this message translates to:
  /// **'OWASP cdxgen — CycloneDX natif, tous écosystèmes'**
  String get cfgCdxgenTip;

  /// Description du backend.
  ///
  /// In fr, this message translates to:
  /// **'Syft (recommandé) — supporte tous les écosystèmes'**
  String get cfgSyftDesc;

  /// Description du backend.
  ///
  /// In fr, this message translates to:
  /// **'Trivy — tous écosystèmes, déjà utilisé pour les CVE'**
  String get cfgTrivyDesc;

  /// Description du backend.
  ///
  /// In fr, this message translates to:
  /// **'Skopeo — extraction manuelle dpkg / rpm / apk'**
  String get cfgSkopeoDesc;

  /// Description du backend.
  ///
  /// In fr, this message translates to:
  /// **'cdxgen — SBOM CycloneDX natif, tous écosystèmes (nécessite Node.js)'**
  String get cfgCdxgenDesc;

  /// Libellé.
  ///
  /// In fr, this message translates to:
  /// **'Version (--cyclonedx-version)'**
  String get cfgCdxVersion;

  /// Aide.
  ///
  /// In fr, this message translates to:
  /// **'1.6 — la plus répandue chez les consommateurs actuels (défaut).\n1.7 — ajoute citations / patentAssertions / distributionConstraints\n(voir --tlp et --patent-map en ligne de commande).'**
  String get cfgCdxVersionHelp;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Types acceptés (fichier liste, paquet unique, ou dossier scanné) :'**
  String get cfgLegendAccepted;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'RPM installé'**
  String get cfgLegRpmInstalled;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Fichier .rpm'**
  String get cfgLegRpmFile;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Wheel Python'**
  String get cfgLegWheel;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Archive tar'**
  String get cfgLegTar;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Archive .zip'**
  String get cfgLegZip;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Paquet Debian'**
  String get cfgLegDeb;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Archive Java'**
  String get cfgLegJar;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Manifeste/lock'**
  String get cfgLegManifest;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Image OCI (champ --image) :'**
  String get cfgLegendImage;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Registre'**
  String get cfgLegRegistry;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'OCI layout'**
  String get cfgLegOciLayout;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'/path/oci_dir/  (index.json présent)'**
  String get cfgLegOciLayoutVal;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Binaire autonome (champ --binary) :'**
  String get cfgLegendBinary;

  /// Légende.
  ///
  /// In fr, this message translates to:
  /// **'Exécutable local (ex. binaire Go lié statiquement) — force le backend syft. Dépendances Go embarquées lues systématiquement ; seul un catalogue fixe de bibliothèques connues (OpenSSL, zlib, sqlite…) est détecté pour les autres langages.'**
  String get cfgLegendBinaryText;

  /// Mot de liaison dans la légende (« bash ou bash-5… »).
  ///
  /// In fr, this message translates to:
  /// **'ou'**
  String get cfgLegOr;

  /// Erreur sbomqs.
  ///
  /// In fr, this message translates to:
  /// **'Aucun résultat retourné par sbomqs'**
  String get qualitySbomqsNoResult;

  /// Libellé du format JSON propre à l'outil.
  ///
  /// In fr, this message translates to:
  /// **'JSON personnalisé'**
  String get formatJsonCustom;

  /// Titre de l'écran d'aide.
  ///
  /// In fr, this message translates to:
  /// **'Aide — Manuel utilisateur'**
  String get helpTitle;

  /// Champ de recherche.
  ///
  /// In fr, this message translates to:
  /// **'Rechercher dans le manuel…'**
  String get helpSearchHint;

  /// Infobulle.
  ///
  /// In fr, this message translates to:
  /// **'Effacer'**
  String get helpClear;

  /// Recherche sans résultat.
  ///
  /// In fr, this message translates to:
  /// **'Aucun chapitre ne contient « {query} ».'**
  String helpNoMatch(String query);

  /// Erreur de chargement.
  ///
  /// In fr, this message translates to:
  /// **'Aide indisponible : impossible de charger le manuel ({error}).'**
  String helpLoadError(String error);

  /// Titre du rapport AsciiDoc exporté depuis un onglet de scan.
  ///
  /// In fr, this message translates to:
  /// **'= Rapport de vulnérabilités: {tool}'**
  String vrTitle(String tool);

  /// Ligne du résumé exécutif.
  ///
  /// In fr, this message translates to:
  /// **'*Scanner* : {tool} — {count, plural, one{*{count}* vulnérabilité} other{*{count}* vulnérabilités}}{filtered}'**
  String vrScannerLine(String tool, int count, String filtered);

  /// Suffixe de la ligne du résumé quand un filtre de date est actif.
  ///
  /// In fr, this message translates to:
  /// **' après filtre de date'**
  String get vrAfterDateFilter;

  /// En-tête du tableau de chiffres clés.
  ///
  /// In fr, this message translates to:
  /// **'h| Critiques h| Élevées h| CISA KEV h| Total'**
  String get vrStatsHeader;

  /// Note sur le filtre de date.
  ///
  /// In fr, this message translates to:
  /// **'NOTE: Filtre de date appliqué — {summary}.'**
  String vrDateNote(String summary);

  /// Titre de la section du tableau détaillé.
  ///
  /// In fr, this message translates to:
  /// **'== Détail'**
  String get vrDetail;

  /// Ligne de méthode de la section des couches.
  ///
  /// In fr, this message translates to:
  /// **'Méthode : {mode}{extra}.'**
  String vrLayerMethod(String mode, String extra);

  /// Complément : vulnérabilités non rattachées à une couche.
  ///
  /// In fr, this message translates to:
  /// **' — {count, plural, one{{count} vulnérabilité sans couche connue} other{{count} vulnérabilités sans couche connue}}'**
  String vrLayerUnattr(int count);

  /// En-tête du tableau des couches.
  ///
  /// In fr, this message translates to:
  /// **'| Couche | Digest | Instruction | Vulnérabilités | Critiques | Élevées'**
  String get vrLayersHeader;

  /// En-tête de la colonne des couches (CSV et tableau).
  ///
  /// In fr, this message translates to:
  /// **'Couche(s)'**
  String get vrLayersCol;

  /// Champ de date utilisé dans la note du filtre.
  ///
  /// In fr, this message translates to:
  /// **'publication'**
  String get vrDatePublished;

  /// Champ de date utilisé dans la note du filtre.
  ///
  /// In fr, this message translates to:
  /// **'dernière modification'**
  String get vrDateModified;

  /// Champ de date utilisé dans la note du filtre.
  ///
  /// In fr, this message translates to:
  /// **'plus récente des deux'**
  String get vrDateLatest;

  /// Borne basse du filtre de date.
  ///
  /// In fr, this message translates to:
  /// **'après {date}'**
  String vrDateAfter(String date);

  /// Borne haute du filtre de date.
  ///
  /// In fr, this message translates to:
  /// **'avant {date}'**
  String vrDateBefore(String date);

  /// Filtre de date sans borne.
  ///
  /// In fr, this message translates to:
  /// **'aucune borne'**
  String get vrDateNoBound;

  /// Complément : CVE sans date incluses.
  ///
  /// In fr, this message translates to:
  /// **', dont sans date connue'**
  String get vrDateUndated;

  /// Titre de la section de remédiation du tableau de bord.
  ///
  /// In fr, this message translates to:
  /// **'Remédiation : quoi mettre à jour'**
  String get remedTitle;

  /// Sous-titre de la section de remédiation.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, =1{1 paquet à mettre à jour} other{{count} paquets à mettre à jour}}, classés par gain de risque (sévérité, exploitation active KEV, EPSS).'**
  String remedSubtitle(int count);

  /// Ligne de remédiation : paquet, version installée, version cible.
  ///
  /// In fr, this message translates to:
  /// **'{pkg} {from} → {to}'**
  String remedUpgrade(String pkg, String from, String to);

  /// Ligne de remédiation d'un paquet dont aucune CVE n'a de correctif.
  ///
  /// In fr, this message translates to:
  /// **'{pkg} {from} — aucun correctif connu'**
  String remedNoFixTitle(String pkg, String from);

  /// Nombre de CVE corrigées par la mise à jour.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, =1{1 CVE corrigée} other{{count} CVE corrigées}}'**
  String remedFixes(int count);

  /// Nombre de CVE corrigées présentes au catalogue CISA KEV.
  ///
  /// In fr, this message translates to:
  /// **'{count} exploitée(s) (KEV)'**
  String remedKev(int count);

  /// CVE d'un paquet sans correctif connu, restant après mise à jour.
  ///
  /// In fr, this message translates to:
  /// **'{count, plural, =1{1 CVE restera sans correctif} other{{count} CVE resteront sans correctif}}'**
  String remedRemaining(int count);

  /// Score de gain de risque d'une mise à jour.
  ///
  /// In fr, this message translates to:
  /// **'Gain de risque : {gain}'**
  String remedGain(String gain);

  /// Bouton : déplier la liste complète de remédiation.
  ///
  /// In fr, this message translates to:
  /// **'Afficher les {count} paquets'**
  String remedShowAll(int count);

  /// Bouton : replier la liste de remédiation.
  ///
  /// In fr, this message translates to:
  /// **'Réduire la liste'**
  String get remedShowLess;

  /// Bouton d'export CSV de la remédiation.
  ///
  /// In fr, this message translates to:
  /// **'Exporter en CSV'**
  String get remedExportCsv;

  /// Info-bulle : copier le plan de remédiation dans le presse-papiers.
  ///
  /// In fr, this message translates to:
  /// **'Copier la liste'**
  String get remedCopyCommand;

  /// Message : plan de remédiation copié.
  ///
  /// In fr, this message translates to:
  /// **'Plan de remédiation copié'**
  String get remedCopied;

  /// Titre du dialogue d'enregistrement du CSV de remédiation.
  ///
  /// In fr, this message translates to:
  /// **'Exporter le plan de remédiation'**
  String get remedCsvDialog;

  /// En-tête CSV du plan de remédiation (séparé par des virgules, sans retour à la ligne).
  ///
  /// In fr, this message translates to:
  /// **'paquet,version installée,version cible,CVE corrigées,dont KEV,CVE sans correctif,gain de risque'**
  String get remedCsvHeader;

  /// Message : CSV de remédiation enregistré.
  ///
  /// In fr, this message translates to:
  /// **'Plan de remédiation exporté → {path}'**
  String remedCsvSaved(String path);

  /// Avertissement sous la liste de remédiation.
  ///
  /// In fr, this message translates to:
  /// **'Heuristique : la version cible est la plus petite qui corrige toutes les CVE corrigeables du paquet ; vérifiez-la avec votre gestionnaire de paquets.'**
  String get remedHelpNote;

  /// Bouton du tableau de bord : enregistrer les résultats de scan dans un fichier.
  ///
  /// In fr, this message translates to:
  /// **'Enregistrer la session…'**
  String get sessSave;

  /// Bouton du tableau de bord : charger un fichier de session.
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir une session…'**
  String get sessOpen;

  /// Bouton du tableau de bord : ouvrir l'historique des analyses.
  ///
  /// In fr, this message translates to:
  /// **'Historique'**
  String get sessHistory;

  /// Message : session vide, rien à enregistrer.
  ///
  /// In fr, this message translates to:
  /// **'Aucun résultat de scan à enregistrer.'**
  String get sessNothingToSave;

  /// Titre du dialogue d'enregistrement d'une session.
  ///
  /// In fr, this message translates to:
  /// **'Enregistrer la session'**
  String get sessDialogSave;

  /// Titre du dialogue d'ouverture d'une session.
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir une session'**
  String get sessDialogOpen;

  /// Message : session enregistrée.
  ///
  /// In fr, this message translates to:
  /// **'Session enregistrée → {path}'**
  String sessSaved(String path);

  /// Message : session chargée.
  ///
  /// In fr, this message translates to:
  /// **'Session du {date} chargée dans le tableau de bord'**
  String sessLoaded(String date);

  /// Message : fichier de session invalide.
  ///
  /// In fr, this message translates to:
  /// **'Fichier de session illisible : {error}'**
  String sessInvalid(String error);

  /// Titre du dialogue d'historique.
  ///
  /// In fr, this message translates to:
  /// **'Historique des analyses'**
  String get sessHistoryTitle;

  /// Historique vide.
  ///
  /// In fr, this message translates to:
  /// **'Aucune analyse enregistrée. Les résultats des scans sont conservés automatiquement (une entrée par cible et par jour).'**
  String get sessHistoryEmpty;

  /// Nombre de CVE d'une session de l'historique.
  ///
  /// In fr, this message translates to:
  /// **'{count} CVE'**
  String sessHistoryItem(int count);

  /// Action : charger une session de l'historique dans le tableau de bord.
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir'**
  String get sessOpenAction;

  /// Action : comparer la session courante à une session de l'historique.
  ///
  /// In fr, this message translates to:
  /// **'Comparer'**
  String get sessCompareAction;

  /// Action : supprimer une session de l'historique.
  ///
  /// In fr, this message translates to:
  /// **'Supprimer'**
  String get sessDeleteAction;

  /// Bouton : supprimer toutes les sessions de l'historique.
  ///
  /// In fr, this message translates to:
  /// **'Vider l\'historique'**
  String get sessClearHistory;

  /// Confirmation de la suppression de l'historique.
  ///
  /// In fr, this message translates to:
  /// **'Supprimer toutes les analyses enregistrées ?'**
  String get sessClearConfirm;

  /// Titre de la carte de tendance (date de la session de référence).
  ///
  /// In fr, this message translates to:
  /// **'Tendance depuis le {date}'**
  String sessTrendTitle(String date);

  /// Tendance : nombre de CVE apparues.
  ///
  /// In fr, this message translates to:
  /// **'{count} nouvelle(s)'**
  String sessTrendNew(int count);

  /// Tendance : nombre de CVE disparues (corrigées ou plus détectées).
  ///
  /// In fr, this message translates to:
  /// **'{count} disparue(s)'**
  String sessTrendFixed(int count);

  /// Tendance : nombre de CVE inchangées.
  ///
  /// In fr, this message translates to:
  /// **'{count} inchangée(s)'**
  String sessTrendSame(int count);

  /// Tendance : total de CVE avant → après.
  ///
  /// In fr, this message translates to:
  /// **'Total : {before} → {after}'**
  String sessTrendTotals(int before, int after);

  /// Tendance : légende de la liste des nouvelles CVE.
  ///
  /// In fr, this message translates to:
  /// **'Nouvelles :'**
  String get sessTrendNewList;

  /// Bouton : retirer la session de référence de la tendance.
  ///
  /// In fr, this message translates to:
  /// **'Retirer la comparaison'**
  String get sessTrendClear;

  /// Tendance : aucune évolution.
  ///
  /// In fr, this message translates to:
  /// **'Aucune différence avec la session de référence.'**
  String get sessTrendNone;

  /// Libellé de l'onglet de la file d'attente des analyses.
  ///
  /// In fr, this message translates to:
  /// **'Tâches'**
  String get tabTasks;

  /// Introduction de l'onglet Tâches.
  ///
  /// In fr, this message translates to:
  /// **'Mettez en file des analyses de vulnérabilités : elles s\'exécutent une à une, peuvent être annulées ou relancées, et leurs résultats alimentent le tableau de bord.'**
  String get tasksIntro;

  /// Libellé du choix du fichier SBOM de l'onglet Tâches.
  ///
  /// In fr, this message translates to:
  /// **'SBOM à analyser'**
  String get tasksTargetLabel;

  /// Texte quand aucun SBOM n'est choisi.
  ///
  /// In fr, this message translates to:
  /// **'Aucun SBOM sélectionné'**
  String get tasksTargetNone;

  /// Bouton de choix d'un fichier SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Parcourir…'**
  String get tasksBrowse;

  /// Titre du dialogue de choix d'un SBOM.
  ///
  /// In fr, this message translates to:
  /// **'Choisir un SBOM à analyser'**
  String get tasksPickDialog;

  /// Bouton : mettre en file les analyses des scanners cochés.
  ///
  /// In fr, this message translates to:
  /// **'Ajouter à la file'**
  String get tasksEnqueue;

  /// Message : aucun SBOM choisi.
  ///
  /// In fr, this message translates to:
  /// **'Choisissez d\'abord un SBOM.'**
  String get tasksNeedTarget;

  /// Message : aucun scanner coché.
  ///
  /// In fr, this message translates to:
  /// **'Cochez au moins un scanner.'**
  String get tasksNeedScanner;

  /// Liste de tâches vide.
  ///
  /// In fr, this message translates to:
  /// **'Aucune analyse en file.'**
  String get tasksEmpty;

  /// Bouton : annuler toutes les analyses en attente ou en cours.
  ///
  /// In fr, this message translates to:
  /// **'Tout annuler'**
  String get tasksCancelAll;

  /// Bouton : retirer les analyses terminées de la liste.
  ///
  /// In fr, this message translates to:
  /// **'Retirer les terminées'**
  String get tasksClearFinished;

  /// Statut d'une analyse en attente.
  ///
  /// In fr, this message translates to:
  /// **'En attente'**
  String get tasksStatusQueued;

  /// Statut d'une analyse en cours.
  ///
  /// In fr, this message translates to:
  /// **'En cours…'**
  String get tasksStatusRunning;

  /// Statut d'une analyse terminée avec son nombre de vulnérabilités.
  ///
  /// In fr, this message translates to:
  /// **'Terminée — {count, plural, =1{{count} vulnérabilité} other{{count} vulnérabilités}}'**
  String tasksStatusDone(int count);

  /// Statut d'une analyse en échec.
  ///
  /// In fr, this message translates to:
  /// **'Échec : {error}'**
  String tasksStatusFailed(String error);

  /// Statut d'une analyse annulée.
  ///
  /// In fr, this message translates to:
  /// **'Annulée'**
  String get tasksStatusCancelled;

  /// Durée d'une analyse en secondes.
  ///
  /// In fr, this message translates to:
  /// **'{seconds} s'**
  String tasksDuration(int seconds);

  /// Info-bulle : annuler une analyse.
  ///
  /// In fr, this message translates to:
  /// **'Annuler'**
  String get tasksCancel;

  /// Info-bulle : relancer une analyse échouée ou annulée.
  ///
  /// In fr, this message translates to:
  /// **'Relancer'**
  String get tasksRetry;

  /// Info-bulle : retirer une analyse de la liste.
  ///
  /// In fr, this message translates to:
  /// **'Retirer de la liste'**
  String get tasksRemove;

  /// Erreur : outil de scan absent.
  ///
  /// In fr, this message translates to:
  /// **'{tool} introuvable (installez-le ou retirez-le de la sélection).'**
  String tasksToolMissing(String tool);

  /// Erreur : le scanner n'a rien renvoyé.
  ///
  /// In fr, this message translates to:
  /// **'{tool} n\'a produit aucun résultat (code {code}) : {detail}'**
  String tasksNoOutput(String tool, int code, String detail);

  /// Erreur : JSON du scanner invalide.
  ///
  /// In fr, this message translates to:
  /// **'Sortie de {tool} illisible : {error}'**
  String tasksParseFailed(String tool, String error);

  /// Titre de la section VEX de la fiche CVE et de la barre du tableau de bord.
  ///
  /// In fr, this message translates to:
  /// **'VEX (non affecté / corrigé)'**
  String get vexTitle;

  /// Bouton de la fiche CVE : créer une déclaration VEX.
  ///
  /// In fr, this message translates to:
  /// **'Déclarer via VEX…'**
  String get vexDeclare;

  /// Bouton : modifier une déclaration VEX.
  ///
  /// In fr, this message translates to:
  /// **'Modifier'**
  String get vexEdit;

  /// Bouton : retirer une déclaration VEX.
  ///
  /// In fr, this message translates to:
  /// **'Retirer'**
  String get vexRemove;

  /// Déclaration VEX existante d'une CVE (statut puis détail éventuel).
  ///
  /// In fr, this message translates to:
  /// **'VEX : {status}{detail}'**
  String vexCurrent(String status, String detail);

  /// Statut VEX not_affected.
  ///
  /// In fr, this message translates to:
  /// **'non affectée'**
  String get vexStatusNotAffected;

  /// Statut VEX affected.
  ///
  /// In fr, this message translates to:
  /// **'affectée'**
  String get vexStatusAffected;

  /// Statut VEX fixed.
  ///
  /// In fr, this message translates to:
  /// **'corrigée'**
  String get vexStatusFixed;

  /// Statut VEX under_investigation.
  ///
  /// In fr, this message translates to:
  /// **'à l\'étude'**
  String get vexStatusInvestigation;

  /// Justification VEX component_not_present.
  ///
  /// In fr, this message translates to:
  /// **'composant absent'**
  String get vexJustComponentNotPresent;

  /// Justification VEX vulnerable_code_not_present.
  ///
  /// In fr, this message translates to:
  /// **'code vulnérable absent'**
  String get vexJustCodeNotPresent;

  /// Justification VEX vulnerable_code_not_in_execute_path.
  ///
  /// In fr, this message translates to:
  /// **'code vulnérable jamais exécuté'**
  String get vexJustNotInExecutePath;

  /// Justification VEX vulnerable_code_cannot_be_controlled_by_adversary.
  ///
  /// In fr, this message translates to:
  /// **'code non contrôlable par un attaquant'**
  String get vexJustCannotBeControlled;

  /// Justification VEX inline_mitigations_already_exist.
  ///
  /// In fr, this message translates to:
  /// **'mesures d\'atténuation déjà en place'**
  String get vexJustInlineMitigations;

  /// Titre du dialogue de déclaration VEX.
  ///
  /// In fr, this message translates to:
  /// **'Déclaration VEX — {id}'**
  String vexDialogTitle(String id);

  /// Champ : état VEX.
  ///
  /// In fr, this message translates to:
  /// **'État'**
  String get vexFieldStatus;

  /// Champ : justification VEX.
  ///
  /// In fr, this message translates to:
  /// **'Justification'**
  String get vexFieldJustification;

  /// Champ : explication libre de la déclaration VEX.
  ///
  /// In fr, this message translates to:
  /// **'Explication (facultative)'**
  String get vexFieldImpact;

  /// Champ : paquets visés par la déclaration.
  ///
  /// In fr, this message translates to:
  /// **'Portée'**
  String get vexFieldScope;

  /// Portée : la déclaration vise tous les paquets.
  ///
  /// In fr, this message translates to:
  /// **'Tous les paquets'**
  String get vexScopeAll;

  /// Erreur : justification absente.
  ///
  /// In fr, this message translates to:
  /// **'Une justification est requise pour « non affectée ».'**
  String get vexNeedJustification;

  /// Bouton d'enregistrement du dialogue VEX.
  ///
  /// In fr, this message translates to:
  /// **'Enregistrer'**
  String get vexSave;

  /// Résumé de la barre VEX du tableau de bord.
  ///
  /// In fr, this message translates to:
  /// **'VEX : {count, plural, =1{{count} déclaration} other{{count} déclarations}}'**
  String vexBarSummary(int count);

  /// Case à cocher : masquer les CVE déclarées non affectées ou corrigées.
  ///
  /// In fr, this message translates to:
  /// **'Masquer les CVE couvertes par un VEX ({count})'**
  String vexHideSuppressed(int count);

  /// Bouton : importer un document VEX.
  ///
  /// In fr, this message translates to:
  /// **'Importer un VEX…'**
  String get vexImport;

  /// Menu : exporter les déclarations VEX.
  ///
  /// In fr, this message translates to:
  /// **'Exporter'**
  String get vexExport;

  /// Entrée de menu : export OpenVEX.
  ///
  /// In fr, this message translates to:
  /// **'OpenVEX (.json)'**
  String get vexExportOpenVex;

  /// Entrée de menu : export CycloneDX VEX.
  ///
  /// In fr, this message translates to:
  /// **'CycloneDX VEX (.json)'**
  String get vexExportCdx;

  /// Bouton : ouvrir la liste des déclarations VEX.
  ///
  /// In fr, this message translates to:
  /// **'Gérer'**
  String get vexManage;

  /// Titre de la liste des déclarations VEX.
  ///
  /// In fr, this message translates to:
  /// **'Déclarations VEX'**
  String get vexManageTitle;

  /// Titre du dialogue d'import VEX.
  ///
  /// In fr, this message translates to:
  /// **'Importer un document VEX'**
  String get vexDialogImport;

  /// Titre du dialogue d'export VEX.
  ///
  /// In fr, this message translates to:
  /// **'Exporter les déclarations VEX'**
  String get vexDialogExport;

  /// Message : déclarations importées.
  ///
  /// In fr, this message translates to:
  /// **'{count} déclaration(s) VEX importée(s)'**
  String vexImported(int count);

  /// Message : VEX exporté.
  ///
  /// In fr, this message translates to:
  /// **'VEX exporté → {path}'**
  String vexExported(String path);

  /// Message : import VEX échoué.
  ///
  /// In fr, this message translates to:
  /// **'Document VEX illisible : {error}'**
  String vexInvalid(String error);

  /// Message : rien à exporter.
  ///
  /// In fr, this message translates to:
  /// **'Aucune déclaration VEX à exporter.'**
  String get vexNothingToExport;

  /// Bouton : supprimer toutes les déclarations VEX.
  ///
  /// In fr, this message translates to:
  /// **'Tout retirer'**
  String get vexClearAll;

  /// Libellé d'une déclaration visant tous les paquets (liste VEX).
  ///
  /// In fr, this message translates to:
  /// **'tous les paquets'**
  String get vexAnyPackage;

  /// Info-bulle du bouton d'aide sur les raccourcis clavier.
  ///
  /// In fr, this message translates to:
  /// **'Raccourcis clavier'**
  String get shortcutsTooltip;

  /// Titre du dialogue des raccourcis clavier.
  ///
  /// In fr, this message translates to:
  /// **'Raccourcis clavier'**
  String get shortcutsTitle;

  /// Raccourci : lancer la génération.
  ///
  /// In fr, this message translates to:
  /// **'Lancer la génération'**
  String get shortcutRun;

  /// Raccourci : arrêter.
  ///
  /// In fr, this message translates to:
  /// **'Arrêter l\'exécution en cours'**
  String get shortcutStop;

  /// Raccourci : choisir un onglet par son numéro.
  ///
  /// In fr, this message translates to:
  /// **'Aller à l\'onglet 1 à 9'**
  String get shortcutTabs;

  /// Raccourci : changer d'onglet.
  ///
  /// In fr, this message translates to:
  /// **'Onglet suivant / précédent'**
  String get shortcutNextTab;

  /// Raccourci : aide.
  ///
  /// In fr, this message translates to:
  /// **'Ouvrir l\'aide'**
  String get shortcutHelp;

  /// Raccourci : liste des raccourcis.
  ///
  /// In fr, this message translates to:
  /// **'Afficher cette liste'**
  String get shortcutShortcuts;

  /// Rappel : navigation au clavier dans les tableaux.
  ///
  /// In fr, this message translates to:
  /// **'Parcourir : Tab / flèches ; ouvrir une ligne : Entrée ou Espace'**
  String get shortcutNavigate;
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) =>
      <String>['en', 'fr'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'en':
      return AppLocalizationsEn();
    case 'fr':
      return AppLocalizationsFr();
  }

  throw FlutterError(
    'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
