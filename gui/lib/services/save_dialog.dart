import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';

/// Ouvre la boîte « Enregistrer sous » et renvoie le chemin choisi (ou null
/// si l'utilisateur annule).
///
/// Depuis file_picker 12, `saveFile` exige des octets et écrit lui-même le
/// fichier ; les appelants écrivent ensuite le vrai contenu (ou laissent la
/// CLI le produire), on crée donc ici un fichier vide à l'emplacement choisi.
Future<String?> pickSavePath({
  String? fileName,
  String? dialogTitle,
  FileType type = FileType.any,
  List<String>? allowedExtensions,
}) async {
  final uri = await FilePicker.saveFile(
    fileName: fileName ?? '',
    bytes: Uint8List(0),
    dialogTitle: dialogTitle,
    type: type,
    allowedExtensions: allowedExtensions,
  );
  return uri?.toFilePath();
}
