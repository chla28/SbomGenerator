import 'package:sbom_generator/i18n.dart';
import 'package:test/test.dart';

void main() {
  tearDown(() => currentLang = Lang.fr);

  group('langFromLocale', () {
    test('reconnaît fr et en, quel que soit le suffixe', () {
      expect(langFromLocale('fr_FR.UTF-8'), Lang.fr);
      expect(langFromLocale('en_US.UTF-8'), Lang.en);
      expect(langFromLocale('EN'), Lang.en);
    });
    test('renvoie null pour C, POSIX, vide ou inconnu', () {
      expect(langFromLocale('C'), isNull);
      expect(langFromLocale('POSIX'), isNull);
      expect(langFromLocale(''), isNull);
      expect(langFromLocale(null), isNull);
      expect(langFromLocale('de_DE'), isNull);
    });
  });

  group('initLang', () {
    test('--lang prime sur l\'environnement et est retiré des arguments', () {
      final rest = initLang(['scan', '--lang', 'en', '--sbom', 'x'],
          env: {'LANG': 'fr_FR.UTF-8'});
      expect(rest, ['scan', '--sbom', 'x']);
      expect(currentLang, Lang.en);
    });
    test('forme --lang=fr', () {
      final rest = initLang(['--lang=fr', '-i', 'x'], env: {'LANG': 'en_US'});
      expect(rest, ['-i', 'x']);
      expect(currentLang, Lang.fr);
    });
    test('ordre SBOM_LANG > LC_ALL > LC_MESSAGES > LANG', () {
      initLang([], env: {'SBOM_LANG': 'en', 'LC_ALL': 'fr', 'LANG': 'fr'});
      expect(currentLang, Lang.en);
      initLang([], env: {'LC_ALL': 'C', 'LC_MESSAGES': 'en_US', 'LANG': 'fr'});
      expect(currentLang, Lang.en);
      initLang([], env: {'LANG': 'en_GB.UTF-8'});
      expect(currentLang, Lang.en);
    });
    test('français par défaut', () {
      initLang([], env: {});
      expect(currentLang, Lang.fr);
      initLang([], env: {'LANG': 'C'});
      expect(currentLang, Lang.fr);
    });
  });

  group('tr / plural', () {
    test('tr suit la langue courante', () {
      currentLang = Lang.fr;
      expect(tr('bonjour', 'hello'), 'bonjour');
      currentLang = Lang.en;
      expect(tr('bonjour', 'hello'), 'hello');
    });
    test('plural : 0 et 1 singulier en français, 1 seul en anglais', () {
      currentLang = Lang.fr;
      expect(plural(0, 'paquet', 'paquets', 'package', 'packages'), 'paquet');
      expect(plural(1, 'paquet', 'paquets', 'package', 'packages'), 'paquet');
      expect(plural(2, 'paquet', 'paquets', 'package', 'packages'), 'paquets');
      currentLang = Lang.en;
      expect(plural(0, 'paquet', 'paquets', 'package', 'packages'), 'packages');
      expect(plural(1, 'paquet', 'paquets', 'package', 'packages'), 'package');
    });
  });
}
