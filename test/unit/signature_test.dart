import 'dart:io';

import 'package:sbom_generator/signature.dart';
import 'package:test/test.dart';

void main() {
  group('cosignVerifyArgs', () {
    test('à clé : --key, bundle puis fichier en dernier', () {
      expect(
          cosignVerifyArgs(
              sbomPath: 'a.json', bundlePath: 'a.json.bundle', key: 'k.pub'),
          [
            'verify-blob',
            '--bundle',
            'a.json.bundle',
            '--key',
            'k.pub',
            'a.json'
          ]);
    });

    test('sans clé : identité et émetteur transmis', () {
      final args = cosignVerifyArgs(
        sbomPath: 'a.json',
        bundlePath: 'b',
        identity: 'moi@x.org',
        issuer: 'https://iss',
      );
      expect(args, containsAllInOrder(['--certificate-identity', 'moi@x.org']));
      expect(args,
          containsAllInOrder(['--certificate-oidc-issuer', 'https://iss']));
      expect(args.last, 'a.json');
      expect(args, isNot(contains('--key')));
    });

    test('variantes regexp', () {
      final args = cosignVerifyArgs(
        sbomPath: 's',
        bundlePath: 'b',
        identityRegexp: '.*@x.org',
        issuerRegexp: 'https://.*',
      );
      expect(args, contains('--certificate-identity-regexp'));
      expect(args, contains('--certificate-oidc-issuer-regexp'));
    });
  });

  group('verifySbomSignature', () {
    late Directory tmp;
    setUp(() => tmp = Directory.systemTemp.createTempSync('sig_'));
    tearDown(() => tmp.deleteSync(recursive: true));

    Future<SignatureResult> verify(
        {int exit = 0, String stderr = '', bool bundle = true}) {
      final sbom = File('${tmp.path}/s.json')..writeAsStringSync('{}');
      if (bundle) File('${sbom.path}.bundle').writeAsStringSync('{}');
      return verifySbomSignature(
        sbomPath: sbom.path,
        key: 'k.pub',
        verifyBlob: (_) async => ProcessResult(0, exit, '', stderr),
      );
    }

    test('code 0 : valide', () async {
      expect((await verify()).status, SignatureStatus.verified);
    });

    test('code non nul : invalide, message de cosign conservé', () async {
      final r = await verify(exit: 1, stderr: 'invalid signature\n');
      expect(r.status, SignatureStatus.invalid);
      expect(r.detail, 'invalid signature');
    });

    test('code 127 : cosign introuvable', () async {
      expect((await verify(exit: 127)).status, SignatureStatus.cosignMissing);
    });

    test('bundle absent : fichier manquant, cosign non lancé', () async {
      expect((await verify(bundle: false)).status, SignatureStatus.fileMissing);
    });
  });
}
