import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/services/osv_runner.dart';

void main() {
  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('osv_gz_test_'));
  tearDown(() => dir.deleteSync(recursive: true));

  test('une archive gzip est décompressée vers un tar temporaire', () async {
    final raw = List<int>.generate(2048, (i) => i % 251);
    final gz = File('${dir.path}/img.tar.gz')
      ..writeAsBytesSync(gzip.encode(raw));
    final p = await OsvRunner.prepareTarget(gz.path, true);
    expect(p.tmpDir, isNotNull);
    expect(p.target, endsWith('image.tar'));
    expect(File(p.target).readAsBytesSync(), raw);
    p.tmpDir!.deleteSync(recursive: true);
  });

  test('un tar non compressé ou un mode SBOM reste inchangé', () async {
    final tar = File('${dir.path}/img.tar')..writeAsBytesSync([1, 2, 3, 4]);
    final a = await OsvRunner.prepareTarget(tar.path, true);
    expect((a.target, a.tmpDir), (tar.path, null));
    final gz = File('${dir.path}/x.tar.gz')
      ..writeAsBytesSync(gzip.encode([1, 2, 3]));
    final b = await OsvRunner.prepareTarget(gz.path, false);
    expect((b.target, b.tmpDir), (gz.path, null));
    final c = await OsvRunner.prepareTarget('alpine:3.20', true);
    expect(c.tmpDir, isNull);
  });
}
