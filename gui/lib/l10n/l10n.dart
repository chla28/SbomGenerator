import 'package:flutter/widgets.dart';

import 'app_localizations.dart';

export 'app_localizations.dart';

/// Langues proposées par le réglage « Langue de l'interface ».
enum AppLanguage {
  /// Langue du système (repli sur le français si elle n'est pas prise en
  /// charge).
  system,
  fr,
  en;

  /// Locale imposée à `MaterialApp` (`null` : langue du système).
  Locale? get locale => this == system ? null : Locale(name);

  static AppLanguage parse(String? value) => values.firstWhere(
        (l) => l.name == value,
        orElse: () => AppLanguage.system,
      );
}

/// Langue de référence (textes sources, repli).
const fallbackLocale = Locale('fr');

/// Locale effective pour la langue du système [systemLocales] : la première
/// prise en charge, sinon [fallbackLocale].
Locale resolveAppLocale(List<Locale>? systemLocales) {
  for (final l in systemLocales ?? const <Locale>[]) {
    for (final s in AppLocalizations.supportedLocales) {
      if (s.languageCode == l.languageCode) return s;
    }
  }
  return fallbackLocale;
}

extension AppLocalizationsContext on BuildContext {
  /// Textes de l'interface dans la langue courante. Hors d'une application
  /// localisée (tests de widgets montés sans délégués, par exemple), repli
  /// sur la langue de référence plutôt qu'une exception.
  AppLocalizations get l10n =>
      AppLocalizations.of(this) ?? lookupAppLocalizations(fallbackLocale);
}
