/// Helpers pour collecter et normaliser les empreintes cryptographiques
/// (`PackageHash`) des composants d'un SBOM.
///
/// Règle : seuls les condensats *hexadécimaux d'un artefact réel* sont
/// conservés. Les formats dérivés — dirhash Go `h1:`, checksum APK `Q1…`,
/// hash d'en-tête RPM — sont rejetés ici (ils tromperaient un consommateur
/// qui vérifie un téléchargement) et traités séparément comme métadonnée.
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import 'models.dart';

/// Libellés d'algorithmes acceptés (forme CycloneDX) → nombre de chiffres hex
/// attendus. Sert aussi de liste blanche.
const Map<String, int> _algHexLen = {
  'MD5': 32,
  'SHA-1': 40,
  'SHA-256': 64,
  'SHA-384': 96,
  'SHA-512': 128,
  'SHA3-256': 64,
  'SHA3-384': 96,
  'SHA3-512': 128,
};

final RegExp _hexRe = RegExp(r'^[0-9a-f]+$');

/// Normalise un nom d'algorithme (syft `sha256`, trivy `SHA-256`, SPDX
/// `SHA256`, SRI `sha512`…) vers le libellé CycloneDX. `null` si inconnu ou
/// non standard (`h1`, `Q1`, `sha1git`…).
String? normalizeHashAlg(String raw) {
  final s = raw.trim().toUpperCase().replaceAll('_', '-');
  switch (s) {
    case 'MD5':
      return 'MD5';
    case 'SHA1':
    case 'SHA-1':
      return 'SHA-1';
    case 'SHA224':
    case 'SHA-224':
      return null; // non porté par CycloneDX
    case 'SHA256':
    case 'SHA-256':
      return 'SHA-256';
    case 'SHA384':
    case 'SHA-384':
      return 'SHA-384';
    case 'SHA512':
    case 'SHA-512':
      return 'SHA-512';
    case 'SHA3-256':
      return 'SHA3-256';
    case 'SHA3-384':
      return 'SHA3-384';
    case 'SHA3-512':
      return 'SHA3-512';
    default:
      return null;
  }
}

/// Construit un `PackageHash` à partir d'un couple (algo, valeur). Rejette
/// (renvoie `null`) tout ce qui n'est pas un condensat hexadécimal de la
/// bonne longueur pour un algorithme connu.
PackageHash? packageHash(String alg, String value) {
  final a = normalizeHashAlg(alg);
  if (a == null) return null;
  final v = value.trim().toLowerCase();
  if (!_hexRe.hasMatch(v) || v.length != _algHexLen[a]) return null;
  return PackageHash(a, v);
}

/// Parse une chaîne `"<algo>:<hex>"` (champ `Digest` de Trivy, digests OCI).
PackageHash? packageHashFromDigestString(String? s) {
  if (s == null) return null;
  final i = s.indexOf(':');
  if (i <= 0) return null;
  return packageHash(s.substring(0, i), s.substring(i + 1));
}

/// Parse une entrée Subresource Integrity (`"sha512-<base64>"`, npm/yarn) et
/// convertit le condensat base64 en hexadécimal.
PackageHash? packageHashFromSri(String? sri) {
  if (sri == null || sri.isEmpty) return null;
  // Une SRI peut contenir plusieurs condensats séparés par des espaces.
  for (final token in sri.split(RegExp(r'\s+'))) {
    final dash = token.indexOf('-');
    if (dash <= 0) continue;
    final alg = token.substring(0, dash);
    try {
      final bytes = base64.decode(base64.normalize(token.substring(dash + 1)));
      final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      final h = packageHash(alg, hex);
      if (h != null) return h;
    } catch (_) {
      // token invalide → on essaie le suivant
    }
  }
  return null;
}

/// Extrait les empreintes d'un bloc `metadata` d'artefact syft (clés
/// `archiveDigests`, `digests`, `digest` — liste ou objet unique).
List<PackageHash> hashesFromSyftMetadata(Map<String, dynamic> metadata) {
  final out = <PackageHash>[];
  void consume(Object? node) {
    if (node is List) {
      for (final e in node) {
        consume(e);
      }
    } else if (node is Map) {
      final alg = (node['algorithm'] ?? node['Algorithm']) as String?;
      final val = (node['value'] ??
          node['Value'] ??
          node['digest'] ??
          node['hash']) as String?;
      if (alg != null && val != null) {
        final h = packageHash(alg, val);
        if (h != null && !out.contains(h)) out.add(h);
      }
    } else if (node is String) {
      final h = packageHashFromDigestString(node);
      if (h != null && !out.contains(h)) out.add(h);
    }
  }

  for (final key in const ['archiveDigests', 'digests', 'digest']) {
    if (metadata.containsKey(key)) consume(metadata[key]);
  }
  return out;
}

/// Parse un tableau CycloneDX `hashes` (`[{alg, content}]`, produit par
/// cdxgen) vers `List<PackageHash>`.
List<PackageHash> hashesFromCycloneDx(Object? hashesNode) {
  final out = <PackageHash>[];
  if (hashesNode is! List) return out;
  for (final h in hashesNode.whereType<Map>()) {
    final alg = h['alg'] as String?;
    final content = h['content'] as String?;
    if (alg == null || content == null) continue;
    final ph = packageHash(alg, content);
    if (ph != null && !out.contains(ph)) out.add(ph);
  }
  return out;
}

/// Calcule SHA-256 et SHA-512 d'un fichier local (artefact `.rpm` / `.deb` /
/// `.jar` / `.whl` fourni en entrée). Liste vide si le fichier est illisible.
List<PackageHash> hashLocalFile(String path) {
  try {
    final f = File(path);
    if (!f.existsSync()) return const [];
    final bytes = f.readAsBytesSync();
    return [
      PackageHash('SHA-256', sha256.convert(bytes).toString()),
      PackageHash('SHA-512', sha512.convert(bytes).toString()),
    ];
  } catch (_) {
    return const [];
  }
}

/// Libellé d'algorithme SPDX 2.3 (`checksums[].algorithm`) : `SHA-256` →
/// `SHA256`, `SHA3-256` conservé.
String spdx2Alg(String cdxAlg) {
  if (cdxAlg.startsWith('SHA3-') || cdxAlg.startsWith('BLAKE')) return cdxAlg;
  return cdxAlg.replaceFirst('-', '');
}

/// Libellé d'algorithme SPDX 3.0 (`Hash.algorithm`, vocabulaire
/// `HashAlgorithm`) : `SHA-256` → `sha256`, `SHA3-256` → `sha3_256`,
/// `BLAKE2b-256` → `blake2b256`.
String spdx3Alg(String cdxAlg) {
  final s = cdxAlg.toLowerCase();
  if (s.startsWith('sha3-')) return s.replaceFirst('-', '_');
  return s.replaceAll('-', '');
}
