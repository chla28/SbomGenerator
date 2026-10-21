import 'dart:io';
import 'tool_runner.dart';

/// Issue d'une vérification de signature de SBOM.
enum SignatureStatus {
  /// La signature correspond au fichier (et à la clé / l'identité demandée).
  verified,

  /// cosign a rejeté la signature.
  invalid,

  /// Le SBOM ou son bundle est introuvable.
  fileMissing,

  /// cosign n'est pas installé.
  cosignMissing,
}

class SignatureResult {
  final SignatureStatus status;

  /// Sortie d'erreur de cosign, utile pour comprendre un rejet.
  final String detail;

  const SignatureResult(this.status, [this.detail = '']);

  bool get verified => status == SignatureStatus.verified;
}

/// Arguments de `cosign verify-blob` pour [sbomPath] et son [bundlePath].
///
/// Avec [key] (clé publique), la vérification est « à clé » ; sinon c'est une
/// vérification sans clé (Sigstore) qui exige une identité de certificat et un
/// émetteur OIDC — cosign refuse de vérifier sans l'un ou l'autre.
List<String> cosignVerifyArgs({
  required String sbomPath,
  required String bundlePath,
  String? key,
  String? identity,
  String? identityRegexp,
  String? issuer,
  String? issuerRegexp,
}) =>
    [
      'verify-blob',
      '--bundle',
      bundlePath,
      if (key != null) ...['--key', key],
      if (identity != null) ...['--certificate-identity', identity],
      if (identityRegexp != null) ...[
        '--certificate-identity-regexp',
        identityRegexp
      ],
      if (issuer != null) ...['--certificate-oidc-issuer', issuer],
      if (issuerRegexp != null) ...[
        '--certificate-oidc-issuer-regexp',
        issuerRegexp
      ],
      sbomPath,
    ];

/// Vérifie la signature cosign de [sbomPath] avec [verifyBlob] (injectable
/// pour les tests ; par défaut, le binaire `cosign` du `PATH`).
Future<SignatureResult> verifySbomSignature({
  required String sbomPath,
  String? bundlePath,
  String? key,
  String? identity,
  String? identityRegexp,
  String? issuer,
  String? issuerRegexp,
  Future<ProcessResult> Function(List<String> args)? verifyBlob,
}) async {
  final bundle = bundlePath ?? '$sbomPath.bundle';
  if (!File(sbomPath).existsSync() || !File(bundle).existsSync()) {
    return const SignatureResult(SignatureStatus.fileMissing);
  }
  final run = verifyBlob ?? (args) => runTool('cosign', args);
  final r = await run(cosignVerifyArgs(
    sbomPath: sbomPath,
    bundlePath: bundle,
    key: key,
    identity: identity,
    identityRegexp: identityRegexp,
    issuer: issuer,
    issuerRegexp: issuerRegexp,
  ));
  if (r.exitCode == 127)
    return const SignatureResult(SignatureStatus.cosignMissing);
  return SignatureResult(
    r.exitCode == 0 ? SignatureStatus.verified : SignatureStatus.invalid,
    '${r.stderr}'.trim(),
  );
}
