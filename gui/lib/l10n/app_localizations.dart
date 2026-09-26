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
