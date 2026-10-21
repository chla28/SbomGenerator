import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';

/// Signature de [FilePicker.saveFile] restreinte aux paramètres utilisés ici
/// (permet d'injecter un faux dans les tests).
typedef SaveFileFn =
    Future<Uri?> Function({
      required String fileName,
      required Uint8List bytes,
      String? dialogTitle,
      FileType type,
      List<String>? allowedExtensions,
    });

/// Ouvre la boîte « Enregistrer sous » et renvoie le chemin choisi (ou null
/// si l'utilisateur annule).
///
/// Depuis file_picker 12, `saveFile` exige des octets et écrit lui-même le
/// fichier. Les appelants écrivent ensuite le vrai contenu (ou laissent la
/// CLI le produire) : on passe donc des octets vides, puis on supprime ce
/// fichier vide pour ne pas en laisser un si l'opération est abandonnée
/// ensuite (le chemin reste réservé par le choix de l'utilisateur).
Future<String?> pickSavePath({
  String? fileName,
  String? dialogTitle,
  FileType type = FileType.any,
  List<String>? allowedExtensions,
  @visibleForTesting SaveFileFn? saveFile,
}) async {
  final show = saveFile ?? FilePicker.saveFile;
  final uri = await show(
    fileName: fileName ?? '',
    bytes: Uint8List(0),
    dialogTitle: dialogTitle,
    type: type,
    allowedExtensions: allowedExtensions,
  );
  if (uri == null) return null;
  final path = uri.toFilePath();
  await _removeIfEmpty(path);
  return path;
}

Future<void> _removeIfEmpty(String path) async {
  try {
    final file = File(path);
    if (await file.exists() && await file.length() == 0) await file.delete();
  } on FileSystemException {
    // Sans importance : au pire, le fichier vide reste en place.
  }
}
