import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/services/save_dialog.dart';

void main() {
  late Directory tmp;

  setUp(() => tmp = Directory.systemTemp.createTempSync('save_dialog_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  // Faux dialogue : comme file_picker 13, il écrit les octets reçus.
  SaveFileFn choose(String name, {List<String>? seen}) =>
      ({
        required String fileName,
        required Uint8List bytes,
        String? dialogTitle,
        FileType type = FileType.any,
        List<String>? allowedExtensions,
      }) async {
        seen?.add(fileName);
        final f = File('${tmp.path}/$name')..writeAsBytesSync(bytes);
        return f.uri;
      };

  test('renvoie le chemin choisi et ne laisse pas de fichier vide', () async {
    final seen = <String>[];
    final path = await pickSavePath(
      fileName: 'rapport.csv',
      saveFile: choose('rapport.csv', seen: seen),
    );
    expect(path, '${tmp.path}/rapport.csv');
    expect(seen, ['rapport.csv']);
    expect(File(path!).existsSync(), isFalse);
  });

  test('annulation : renvoie null', () async {
    final path = await pickSavePath(
      fileName: 'x',
      saveFile:
          ({
            required String fileName,
            required Uint8List bytes,
            String? dialogTitle,
            FileType type = FileType.any,
            List<String>? allowedExtensions,
          }) async => null,
    );
    expect(path, isNull);
  });

  test('nom de fichier absent : chaîne vide transmise au dialogue', () async {
    final seen = <String>[];
    await pickSavePath(saveFile: choose('a', seen: seen));
    expect(seen, ['']);
  });
}
