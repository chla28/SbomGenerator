import 'package:flutter/widgets.dart';

import '../i18n.dart';

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

/// Locales prises en charge : les textes passent par `tr()`, les widgets
/// Material ont leurs propres traductions pour ces deux langues.
const supportedAppLocales = [Locale('fr'), Locale('en')];

/// Locale effective pour la langue du système [systemLocales] : la première
/// prise en charge, sinon [fallbackLocale].
Locale resolveAppLocale(List<Locale>? systemLocales) {
  for (final l in systemLocales ?? const <Locale>[]) {
    for (final s in supportedAppLocales) {
      if (s.languageCode == l.languageCode) return s;
    }
  }
  return fallbackLocale;
}

/// Locale effective de l'interface, mise à jour par `main.dart` ; la langue
/// des textes (`tr()`) la suit.
Locale _appLocale = fallbackLocale;

Locale get appLocale => _appLocale;

set appLocale(Locale locale) {
  _appLocale = locale;
  currentLang = locale.languageCode == 'en' ? Lang.en : Lang.fr;
}
