import 'dart:io';

/// Lance un outil externe comme [Process.run], mais renvoie un résultat de
/// code 127 (« commande introuvable ») au lieu de lever une [ProcessException]
/// quand le binaire est absent du `PATH` : l'appelant n'a qu'un code de sortie
/// à tester, comme pour un outil présent qui échoue.
Future<ProcessResult> runTool(String executable, List<String> arguments) =>
    Process.run(executable, arguments).catchError(
      (Object e) => ProcessResult(0, 127, '', e.toString()),
      test: (e) => e is ProcessException,
    );
