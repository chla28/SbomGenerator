/// Localisation FR / EN des messages du CLI, des rapports et de la GUI.
///
/// Le texte source est en français : `tr('texte français {param}', {...})`.
/// La version anglaise est cherchée dans `catalogEn` (`l10n/en.dart`, clé =
/// texte français) ; un texte absent du catalogue reste en français. La langue
/// est fixée une fois au démarrage (`initLang`) ; tout texte destiné à un
/// humain (aide, erreurs, progression, rapports) passe par `tr()`. Ne jamais
/// traduire un texte lu par un programme (clés JSON, valeurs de formats,
/// propriétés des SBOM, sortie des outils tiers).
library;

import 'dart:io';

import 'l10n/en.dart';

/// Langues prises en charge.
enum Lang { fr, en }

Lang _current = Lang.fr;

/// Langue courante des messages.
Lang get currentLang => _current;

/// Force la langue courante (tests, `--lang`).
set currentLang(Lang l) => _current = l;

/// Traductions demandées mais absentes du catalogue (utile aux tests).
final Set<String> missingTranslations = {};

/// Texte traduit. [fr] est le texte source (clé du catalogue) ; chaque
/// `{nom}` est remplacé par `args['nom']`.
String tr(String fr, [Map<String, Object?> args = const {}]) {
  var text = fr;
  if (_current == Lang.en) {
    final en = catalogEn[fr];
    if (en == null) {
      missingTranslations.add(fr);
    } else {
      text = en;
    }
  }
  if (args.isEmpty) return text;
  return text.replaceAllMapped(RegExp(r'\{(\w+)\}'), (m) {
    final key = m[1]!;
    return args.containsKey(key) ? '${args[key]}' : m[0]!;
  });
}

/// Pluriel : le français met 0 au singulier, l'anglais au pluriel.
bool isPlural(num n) => _current == Lang.fr ? n > 1 : n != 1;

/// Déduit une langue d'un code de locale (`fr_FR.UTF-8`, `en`, `C`…).
/// Renvoie `null` si le code n'est pas reconnu.
Lang? langFromLocale(String? locale) {
  if (locale == null) return null;
  final l = locale.trim().toLowerCase();
  if (l.startsWith('fr')) return Lang.fr;
  if (l.startsWith('en')) return Lang.en;
  return null;
}

/// Extrait `--lang <fr|en>` / `--lang=<fr|en>` de [args] (n'importe où, y
/// compris après une sous-commande) et renvoie la liste sans cette option.
/// [onValue] reçoit la valeur brute.
List<String> stripLangArg(List<String> args, void Function(String) onValue) {
  final out = <String>[];
  for (var i = 0; i < args.length; i++) {
    final a = args[i];
    if (a == '--lang' && i + 1 < args.length) {
      onValue(args[++i]);
    } else if (a.startsWith('--lang=')) {
      onValue(a.substring(7));
    } else {
      out.add(a);
    }
  }
  return out;
}

/// Détermine la langue : `--lang` > `SBOM_LANG` > `LC_ALL` > `LC_MESSAGES` >
/// `LANG` > français. Renvoie les arguments sans `--lang`.
List<String> initLang(List<String> args, {Map<String, String>? env}) {
  final e = env ?? Platform.environment;
  String? flag;
  final rest = stripLangArg(args, (v) => flag = v);
  Lang? lang = langFromLocale(flag);
  if (flag != null && lang == null) {
    stderr.writeln('--lang: valeur invalide "$flag" / invalid value "$flag" '
        '(fr | en).');
    exit(1);
  }
  lang ??= langFromLocale(e['SBOM_LANG']) ??
      langFromLocale(e['LC_ALL']) ??
      langFromLocale(e['LC_MESSAGES']) ??
      langFromLocale(e['LANG']) ??
      Lang.fr;
  _current = lang;
  return rest;
}
