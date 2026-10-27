import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sbom_generator_gui/models/watch_history.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('gui_hist_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  void write(String name, List<Object> lines) =>
      File('${tmp.path}/$name').writeAsStringSync(
        '${lines.map((l) => l is String ? l : jsonEncode(l)).join('\n')}\n',
      );

  Map<String, Object> entry(String at, int total, {int added = 0}) => {
    'at': at,
    'total': total,
    'added': added,
    'resolved': 0,
    'bySeverity': {'high': total},
  };

  test('nom lisible : empreinte retirée', () {
    expect(
      historyDisplayName('/x/app.cdx.json-1a2b3c4d.history.jsonl'),
      'app.cdx.json',
    );
    expect(historyDisplayName('/x/seul.history.jsonl'), 'seul');
  });

  test('chargement : tri, lignes corrompues et fichiers vides ignorés', () {
    write('b.cdx.json-00000001.history.jsonl', [
      entry('2026-01-01T00:00:00Z', 3),
      'pas du json',
      entry('2026-01-02T00:00:00Z', 5, added: 2),
    ]);
    write('a.cdx.json-00000002.history.jsonl', [
      entry('2026-01-01T00:00:00Z', 1),
    ]);
    write('vide.history.jsonl', ['{"at":"invalide"}']);
    File('${tmp.path}/autre.json').writeAsStringSync('{}');

    final h = loadHistories(tmp);
    expect(h.map((e) => e.name), ['a.cdx.json', 'b.cdx.json']);
    final b = h.last;
    expect(b.points.map((p) => p.total), [3, 5]);
    expect(b.delta, 2);
    expect(b.last!.added, 2);
    expect(b.last!.bySeverity, {'high': 5});
    expect(h.first.delta, 0);
  });

  test('dossier absent : liste vide', () {
    expect(loadHistories(Directory('${tmp.path}/nope')), isEmpty);
  });

  test('verifyArgs : clé ou identité, champs vides omis', () {
    expect(verifyArgs(sbom: 's.json', key: 'k.pub', bundle: ''), [
      'verify',
      's.json',
      '--key',
      'k.pub',
    ]);
    expect(
      verifyArgs(
        sbom: 's.json',
        bundle: 'b',
        identity: 'me@x',
        issuer: 'https://i',
      ),
      [
        'verify',
        's.json',
        '--bundle',
        'b',
        '--certificate-identity',
        'me@x',
        '--certificate-oidc-issuer',
        'https://i',
      ],
    );
  });
}
