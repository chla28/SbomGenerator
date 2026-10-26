// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 Christophe Lafaille

/// Localisation FR / EN de la GUI : `tr('texte français {param}', {...})`, la
/// version anglaise étant cherchée dans `catalogEn` (`l10n/en.dart`, clé =
/// texte français). Un texte absent du catalogue reste en français.
library;

import 'l10n/en.dart';

/// Langues de l'interface.
enum Lang { fr, en }

Lang _current = Lang.fr;

/// Langue courante des textes.
Lang get currentLang => _current;

/// Fixe la langue courante (démarrage, réglage, tests).
set currentLang(Lang l) => _current = l;

/// Traductions demandées mais absentes du catalogue (utile aux tests).
final Set<String> missingTranslations = {};

/// Texte traduit : chaque `{nom}` est remplacé par `args['nom']`.
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
