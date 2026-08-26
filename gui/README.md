# sbom_generator_gui

Interface graphique de bureau (Linux) pour **SBOM Generator**. Elle donne accès, sans ligne de commande, à l'ensemble du flux de travail autour de l'inventaire logiciel (SBOM) : configuration et lancement d'une génération, suivi de la progression, exploration des résultats, recherche de vulnérabilités connues, évaluation de la qualité du SBOM produit, comparaison entre deux inventaires, fusion de plusieurs inventaires, génération d'un rapport de licences, et consultation libre de tout fichier SBOM existant.

L'application n'effectue aucun traitement métier elle-même : elle orchestre des outils en ligne de commande externes (`sbom-generator`, `grype`, `osv-scanner`, `trivy`, `sbomqs`, `sbom-scorecard`, `asciidoctor-pdf`) et affiche leurs résultats.

---

## Aperçu de l'interface

Une fenêtre unique en deux zones :
- un panneau **Configuration** (gauche) : formulaire de génération d'un SBOM (source de paquets ou image de conteneur OCI, formats de sortie, options), avec prévisualisation en direct de la commande équivalente et gestion de profils nommés ;
- une zone **Résultats** (droite), organisée en 13 onglets : Progression, Résultats, Tableau de bord, Grype, OSV-Scanner, Trivy, Qualité SBOM, Arborescence, Comparaison, Fusion, Licences, Visionneuse, Aperçu.

Pour la description fonctionnelle complète de chaque onglet, voir `doc/user.adoc`.

---

## Prérequis

| Composant | Obligatoire | Rôle |
|-----------|:-----------:|------|
| Flutter SDK (channel stable, ≥ 3.44) | Oui | Compilation et exécution |
| `sbom-generator` (binaire CLI de ce dépôt) | Oui | Génération des fichiers SBOM |
| `syft` | Non | Analyse d'images OCI (backend par défaut) |
| `trivy` | Non | Analyse d'images OCI (backend alternatif) et/ou détection de vulnérabilités (onglet Trivy) |
| `skopeo` | Non | Analyse d'images OCI (backend alternatif) |
| `grype` | Non | Détection de vulnérabilités (onglet Grype) |
| `osv-scanner` | Non | Détection de vulnérabilités (onglet OSV-Scanner) |
| `sbomqs` | Non | Score de qualité du SBOM (onglet Qualité SBOM, ou option dans Configuration) |
| `sbom-scorecard` | Non | Score de qualité du SBOM, référentiel complémentaire (onglet Qualité SBOM) |
| `asciidoctor-pdf` | Non | Conversion du rapport AsciiDoc généré en PDF |

Tous les outils marqués « Non » sont optionnels : leur absence désactive uniquement la fonctionnalité correspondante, avec un message explicite dans l'interface, sans faire échouer le reste de l'application.

---

## Lancer en développement

```bash
cd gui/
flutter pub get
flutter run -d linux
```

`sbom-generator` doit être accessible dans le `PATH`, ou compilé et placé à côté du binaire du GUI (voir `SettingsService.cliBinary` dans `doc/developer.adoc` pour l'ordre de résolution) :

```bash
cd ..   # racine du projet
dart compile exe bin/sbom_generator.dart -o build/sbom-generator
export PATH="$PWD/build:$PATH"
```

## Compiler un binaire autonome

```bash
flutter build linux --release
# Binaire produit dans : build/linux/x64/release/bundle/sbom_generator_gui
```

Le script `../scripts/build-dist.sh` (à la racine du dépôt) automatise la compilation du CLI **et** de la GUI, et produit une archive de distribution complète.

## Vérifications

```bash
flutter analyze
flutter test -j 1   # -j 1 : plus déterministe que le parallélisme par défaut
                     #   sur des machines aux ressources limitées
```

Exécuté automatiquement par `../.github/workflows/ci.yml` sur chaque push/pull request vers `main`.

---

## Documentation

- `doc/user.adoc` — guide utilisateur complet : chaque onglet, chaque option, scénarios d'utilisation typiques, dépannage.
- `doc/developer.adoc` — architecture technique : rôle de chaque fichier, flux de données, conventions, pièges connus.
- `../Specifications/PRD_GUI.md` — spécification fonctionnelle du produit.
- `../Specifications/architecture_GUI.md` — stack technique, structure du projet, conventions.
