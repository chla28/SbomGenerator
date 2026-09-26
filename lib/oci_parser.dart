import 'dart:convert';
import 'dart:io';
import 'hash_utils.dart'
    show hashesFromCycloneDx, hashesFromSyftMetadata, packageHashFromDigestString;
import 'image_layers.dart';
import 'models.dart';

/// Format de la référence OCI fournie par l'utilisateur.
enum OciRefType {
  /// Référence registre : `nginx:latest`, `ubuntu@sha256:…`
  registry,

  /// Archive tar exportée avec `docker save` ou `skopeo copy docker-archive:…`
  tar,

  /// Répertoire au format OCI Image Layout Specification (contient `index.json`)
  ociLayout,

  /// Fichier local existant, analysé directement comme un binaire (pas une
  /// image de conteneur) — ex. un exécutable Go lié statiquement, via
  /// `--binary` ou `--image` pointé sur un chemin de fichier. Seul syft sait
  /// exploiter ce cas (détection automatique de source fichier + lecture des
  /// métadonnées `buildinfo` embarquées).
  binary,
}

/// Résultat de [OciParser.parseImage] : les paquets détectés, et — si le
/// backend l'expose (syft, trivy, cdxgen ; pas skopeo, voir
/// [OciParser._parseSkopeo]) — l'OS de base de l'image, pour générer un
/// composant dédié dans les SBOM CycloneDX/SPDX (voir [OsInfo]).
typedef OciParseResult = ({List<Package> packages, OsInfo? os});

/// Parse les paquets présents dans une image OCI via syft, trivy, skopeo ou
/// cdxgen.
class OciParser {
  // ── Détection automatique du format ─────────────────────────────────────────

  static OciRefType detectRefType(String ref) {
    if (ref.endsWith('.tar') || ref.endsWith('.tar.gz') || ref.endsWith('.tgz'))
      return OciRefType.tar;
    if (Directory(ref).existsSync() && File('$ref/index.json').existsSync()) {
      return OciRefType.ociLayout;
    }
    // Un chemin de fichier local existant n'est pas une référence de
    // registre à résoudre : c'est un binaire à analyser directement (voir
    // `OciRefType.binary`).
    if (File(ref).existsSync()) return OciRefType.binary;
    return OciRefType.registry;
  }

  // ── Point d'entrée principal ─────────────────────────────────────────────────

  Future<OciParseResult> parseImage(
    String imageRef,
    String tool, {
    bool verbose = false,
  }) =>
      _withResolvedRef(imageRef, verbose, (resolvedRef) {
        switch (tool) {
          case 'syft':
            return _parseSyft(resolvedRef, verbose: verbose);
          case 'trivy':
            return _parseTrivy(resolvedRef, verbose: verbose);
          case 'skopeo':
            return _parseSkopeo(resolvedRef, verbose: verbose);
          case 'cdxgen':
            return _parseCdxgen(resolvedRef, verbose: verbose);
          default:
            throw ArgumentError('Outil OCI inconnu : $tool');
        }
      });

  /// Exécute [body] sur une référence utilisable par les backends.
  ///
  /// Les quatre backends (syft, trivy, skopeo, cdxgen) n'acceptent que des
  /// .tar non compressés en format docker-archive. Si l'entrée est .tar.gz
  /// ou .tgz, on la décompresse dans un répertoire temporaire, supprimé une
  /// fois [body] terminé.
  Future<T> _withResolvedRef<T>(String imageRef, bool verbose,
      Future<T> Function(String resolvedRef) body) async {
    final isCompressed =
        imageRef.endsWith('.tar.gz') || imageRef.endsWith('.tgz');
    if (!isCompressed) return body(imageRef);

    final decompDir = await Directory.systemTemp.createTemp('sbom_oci_decomp_');
    try {
      final resolvedRef = await _decompressDockerArchive(
          imageRef, decompDir.path,
          verbose: verbose);
      // await obligatoire : sans lui, le finally s'exécuterait dès le retour
      // de la Future, avant que le backend ait pu lire le fichier décompressé.
      return await body(resolvedRef);
    } finally {
      await Process.run('rm', ['-rf', decompDir.path]);
    }
  }

  // ── Analyse par couche (--per-layer) ─────────────────────────────────────────

  /// Mode `metadata` : couches de l'image et couche d'origine de chaque
  /// paquet (`bomRef` → index de couche), telles que les expose le backend.
  ///
  /// * trivy : `Layer.DiffID` de chaque paquet, couches depuis
  ///   `Metadata.DiffIDs` et `Metadata.ImageConfig.history`.
  /// * syft : seconde analyse en `--scope all-layers`, où chaque paquet porte
  ///   la liste des couches dans lesquelles syft l'a vu ; on retient la plus
  ///   basse. (L'analyse habituelle, « squashed », ne rattache un paquet
  ///   qu'à la dernière couche qui a réécrit la base rpm/dpkg/apk.)
  Future<({List<ImageLayer> layers, Map<String, int> layerOf})>
      layerAttribution(String imageRef, String tool, {bool verbose = false}) =>
          _withResolvedRef(imageRef, verbose, (ref) async {
            switch (tool) {
              case 'trivy':
                if (verbose) print('trivy : attribution des couches de $ref…');
                return _trivyLayerAttribution(
                    await _runTrivyJson(_trivyImageArgs(ref)), ref);
              case 'syft':
                if (verbose) {
                  print('syft : analyse de toutes les couches de $ref…');
                }
                return _syftLayerAttribution(
                    await _runSyftJson([_syftRef(ref), '--scope', 'all-layers']),
                    ref);
              default:
                throw ArgumentError(
                    '--layer-mode metadata non pris en charge par $tool');
            }
          });

  ({List<ImageLayer> layers, Map<String, int> layerOf}) _trivyLayerAttribution(
      Map<String, dynamic> data, String imageRef) {
    final meta = (data['Metadata'] as Map<String, dynamic>?) ?? const {};
    final diffIds = [
      for (final d in meta['DiffIDs'] as List? ?? const []) d.toString(),
    ];
    final layers = layersFromConfig(
        diffIds, (meta['ImageConfig'] as Map?)?['history']);
    final indexOf = {for (final l in layers) l.diffId: l.index};
    final layerOf = <String, int>{};
    for (final e in _trivyPackagesWithLayer(data, imageRef)) {
      final i = indexOf[e.diffId];
      if (i != null) layerOf[e.pkg.bomRef] = i;
    }
    return (layers: layers, layerOf: layerOf);
  }

  ({List<ImageLayer> layers, Map<String, int> layerOf}) _syftLayerAttribution(
      Map<String, dynamic> data, String imageRef) {
    final meta = ((data['source'] as Map?)?['metadata'] as Map?) ?? const {};
    final diffIds = [
      for (final l in meta['layers'] as List? ?? const [])
        if (l is Map && l['digest'] != null) l['digest'].toString(),
    ];
    Object? history;
    final rawConfig = meta['config'];
    if (rawConfig is String && rawConfig.isNotEmpty) {
      try {
        final cfg = jsonDecode(utf8.decode(base64.decode(rawConfig)));
        if (cfg is Map) history = cfg['history'];
      } on FormatException {
        // Config illisible : couches sans instruction de build.
      }
    }
    final layers = layersFromConfig(diffIds, history);
    final indexOf = {for (final l in layers) l.diffId: l.index};

    final codename =
        ((data['distro'] as Map?)?['versionCodename'] as String?)?.trim();
    final layerOf = <String, int>{};
    void attribute(String bomRef, int index) {
      final prev = layerOf[bomRef];
      if (prev == null || index < prev) layerOf[bomRef] = index;
    }

    for (final raw in (data['artifacts'] as List?) ?? const []) {
      final a = raw as Map<String, dynamic>;
      int? lowest;
      for (final loc in a['locations'] as List? ?? const []) {
        final i = indexOf[(loc as Map)['layerID']];
        if (i != null && (lowest == null || i < lowest)) lowest = i;
      }
      if (lowest == null) continue;
      final pkg = _syftArtifactToPackage(a, imageRef, distroCodename: codename);
      if (pkg != null) attribute(pkg.bomRef, lowest);
      // Paquet source dérivé (voir _parseSyft) : couche de son premier binaire.
      final src = _syftSourcePackage(a, codename, imageRef, const {});
      if (src != null) attribute(src.bomRef, lowest);
    }
    return (layers: layers, layerOf: layerOf);
  }

  /// Mode `rootfs` : les couches de l'image sont appliquées une à une sur un
  /// rootfs cumulé, analysé après chaque couche avec [tool] (voir
  /// [analyzeRootfsLayers]). Les couches sont lues directement dans une
  /// archive `docker save` ou un layout OCI ; une référence de registre est
  /// d'abord copiée localement via skopeo.
  Future<LayerAnalysis> rootfsLayerAnalysis(String imageRef, String tool,
      {bool verbose = false, void Function(String message)? log}) async {
    final work = await Directory.systemTemp.createTemp('sbom_layers_');
    try {
      final layers = await _materializeLayers(imageRef, work.path,
          verbose: verbose);
      if (layers.isEmpty) {
        throw StateError('aucune couche trouvée dans $imageRef');
      }
      return await analyzeRootfsLayers(
        layers: layers,
        workDir: work.path,
        scan: (dir) => scanRootfs(dir, tool, imageRef, verbose: verbose),
        log: log,
      );
    } finally {
      await Process.run('chmod', ['-R', 'u+rwX', work.path]);
      await Process.run('rm', ['-rf', work.path]);
    }
  }

  /// Rend les tar des couches de [imageRef] accessibles sous [workDir] et
  /// renvoie la liste ordonnée des couches.
  Future<List<ImageLayer>> _materializeLayers(String imageRef, String workDir,
      {bool verbose = false}) async {
    var ref = imageRef;
    if (ref.endsWith('.tar.gz') || ref.endsWith('.tgz')) {
      final d = Directory('$workDir/decomp')..createSync();
      ref = await _decompressDockerArchive(ref, d.path, verbose: verbose);
    }
    switch (detectRefType(ref)) {
      case OciRefType.tar:
        // docker-archive (`manifest.json`) ou oci-archive (`index.json`).
        final save = Directory('$workDir/save')..createSync();
        final x = await Process.run(
            'tar', ['-C', save.path, '--warning=none', '-xf', ref]);
        if (x.exitCode != 0) {
          throw Exception('extraction de $ref échouée : ${x.stderr}');
        }
        if (File('${save.path}/manifest.json').existsSync()) {
          return readDockerArchiveLayers(save.path);
        }
        if (File('${save.path}/index.json').existsSync()) {
          return readOciLayoutLayers(save.path);
        }
        throw Exception('$ref : ni manifest.json ni index.json — '
            'archive d\'image non reconnue');
      case OciRefType.ociLayout:
        return readOciLayoutLayers(ref);
      case OciRefType.registry:
        return readOciLayoutLayers(await _copyToOciLayout(
            ref, '$workDir/oci_layout',
            verbose: verbose));
      case OciRefType.binary:
        throw ArgumentError('un binaire autonome n\'a pas de couches');
    }
  }

  /// Analyse un rootfs déjà extrait ([dir]) avec [tool]. [imageRef] sert de
  /// référence d'origine des paquets produits.
  Future<List<Package>> scanRootfs(String dir, String tool, String imageRef,
      {bool verbose = false}) async {
    switch (tool) {
      case 'syft':
        // Catalogueurs « image » (paquets installés) plutôt que ceux d'un
        // répertoire source (manifestes déclarés) : même inventaire que
        // l'analyse de l'image elle-même. --base-path : les liens absolus du
        // rootfs sont résolus sous [dir], jamais sur l'hôte.
        return _syftJsonToResult(
                await _runSyftJson([
                  'dir:$dir',
                  '--base-path', dir,
                  '--override-default-catalogers', 'image',
                ]),
                imageRef)
            .packages;
      case 'trivy':
        return _trivyJsonToResult(
                await _runTrivyJson([
                  'rootfs', '--format', 'json', '--quiet', '--list-all-pkgs',
                  dir,
                ]),
                imageRef)
            .packages;
      case 'skopeo':
        return _scanExtractedRootfs(dir, imageRef, verbose: verbose);
      case 'cdxgen':
        return (await _cdxgenRun([
          '--type', 'rootfs',
          '--output', '-',
          '--no-progress',
          dir,
        ], imageRef))
            .packages;
      default:
        throw ArgumentError('Outil OCI inconnu : $tool');
    }
  }

  // ── Décompression archive .tar.gz / .tgz ─────────────────────────────────────
  //
  // Gère deux variantes :
  //  • gzip direct  : docker save redis | gzip > redis.tar.gz
  //    → manifest.json présent à la racine du tar décompressé
  //  • tar-de-tar   : tar czf image.tgz image.tar
  //    → le tar décompressé contient un seul .tar qui est le vrai docker-archive

  Future<String> _decompressDockerArchive(
    String imageRef,
    String workDir, {
    bool verbose = false,
  }) async {
    if (verbose) print('OCI : décompression de $imageRef…');

    final step1 = '$workDir/image.tar';
    final zcatRes = await Process.run(
        'sh', ['-c', 'zcat "\$1" > "\$2"', '--', imageRef, step1]);
    if (zcatRes.exitCode != 0) {
      throw Exception('Décompression de $imageRef échouée : ${zcatRes.stderr}');
    }

    // Cas 1 : gzip direct → manifest.json est à la racine
    final listRes = await Process.run('tar', ['-tf', step1]);
    final entries = (listRes.stdout as String)
        .split('\n')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toSet();

    if (entries.contains('manifest.json')) {
      if (verbose) print('OCI : gzip direct détecté, utilisation de $step1');
      return step1;
    }

    // Cas 2 : tar-de-tar → chercher un .tar à la racine
    final inner = entries.firstWhere(
      (e) => e.endsWith('.tar') && !e.contains('/'),
      orElse: () => '',
    );
    if (inner.isEmpty) {
      throw Exception(
          'Format .tgz non reconnu : manifest.json absent et aucun .tar '
          'imbriqué trouvé. Contenu : ${entries.take(5).join(', ')}');
    }

    if (verbose) print('OCI : tar-de-tar détecté, extraction de $inner…');
    final step2 = '$workDir/inner.tar';
    final extractRes = await Process.run(
        'sh', ['-c', 'tar -xOf "\$1" "\$2" > "\$3"', '--', step1, inner, step2]);
    if (extractRes.exitCode != 0) {
      throw Exception(
          'Extraction du tar imbriqué ($inner) échouée : ${extractRes.stderr}');
    }

    return step2;
  }

  // ── Backend Syft ─────────────────────────────────────────────────────────────

  Future<OciParseResult> _parseSyft(String imageRef,
      {bool verbose = false}) async {
    final syftRef = _syftRef(imageRef);
    if (verbose) print('syft : analyse de $syftRef…');
    return _syftJsonToResult(await _runSyftJson([syftRef]), imageRef);
  }

  String _syftRef(String imageRef) => switch (detectRefType(imageRef)) {
        OciRefType.tar => 'docker-archive:$imageRef',
        OciRefType.ociLayout => 'oci-dir:$imageRef',
        // Chemin de fichier local : syft détecte lui-même une source `file:`
        // et applique ses catalogueurs de binaires (buildinfo Go, classifieur
        // générique…) — c'est ce mécanisme qui rend `--binary` possible.
        OciRefType.registry || OciRefType.binary => imageRef,
      };

  Future<Map<String, dynamic>> _runSyftJson(List<String> args) async {
    final result = await Process.run('syft', [...args, '--output', 'json']);
    if (result.exitCode != 0) {
      throw Exception(
          'syft a échoué (code ${result.exitCode}) : ${result.stderr}');
    }
    try {
      return jsonDecode(result.stdout as String) as Map<String, dynamic>;
    } catch (e) {
      throw Exception('syft : impossible de parser le JSON : $e');
    }
  }

  OciParseResult _syftJsonToResult(
      Map<String, dynamic> data, String imageRef) {
    final distro = data['distro'] as Map<String, dynamic>?;
    final codename = (distro?['versionCodename'] as String?)?.trim();

    final artifacts = (data['artifacts'] as List?) ?? [];
    final packages = <Package>[];
    for (final a in artifacts) {
      final pkg = _syftArtifactToPackage(a as Map<String, dynamic>, imageRef,
          distroCodename: codename);
      if (pkg != null) packages.add(pkg);
    }

    // Paquets source. OSV.dev indexe les avis Debian/Ubuntu par paquet
    // *source* (`zlib`, `perl`), pas par paquet binaire (`zlib1g`,
    // `perl-base`) : syft n'émet que le binaire (avec un qualifiant
    // `upstream=`), qu'OSV-Scanner ne sait pas rattacher à un avis. On ajoute
    // donc un composant par paquet source distinct — comme le fait cdxgen —
    // sinon OSV-Scanner ne matche quasiment aucun paquet système. Grype et
    // Trivy résolvent déjà binaire→source en interne et ne double-comptent
    // pas (vérifié sur un SBOM cdxgen réel : 0 CVE dupliquée entre binaire et
    // source).
    final existingNames = {for (final p in packages) p.name};
    final sourcePkgs = <String, Package>{};
    for (final a in artifacts) {
      final src = _syftSourcePackage(
          a as Map<String, dynamic>, codename, imageRef, existingNames);
      if (src != null) sourcePkgs.putIfAbsent(src.name, () => src);
    }
    packages.addAll(sourcePkgs.values);

    return (packages: packages, os: _syftDistroToOsInfo(data));
  }

  /// Composant du paquet *source* dérivé d'un artefact syft de paquet système,
  /// quand syft indique une `metadata.source` différente du nom binaire.
  /// Renvoie `null` si l'artefact n'est pas un paquet `deb`/`rpm`/`apk`, s'il
  /// n'a pas de source distincte, ou si un composant porte déjà ce nom.
  OciPackage? _syftSourcePackage(Map<String, dynamic> a, String? codename,
      String imageRef, Set<String> existingNames) {
    final type = _normalizeSyftType((a['type'] as String?) ?? 'generic');
    if (type != 'deb' && type != 'rpm' && type != 'apk') return null;

    final meta = (a['metadata'] as Map<String, dynamic>?) ?? const {};
    final src = ((meta['source'] as String?) ?? '').trim();
    final binName = (a['name'] as String?) ?? '';
    if (src.isEmpty || src == binName || existingNames.contains(src)) {
      return null;
    }

    final srcVer = ((meta['sourceVersion'] as String?) ?? '').trim();
    final ver = srcVer.isNotEmpty ? srcVer : ((a['version'] as String?) ?? '');

    // PURL source = PURL binaire normalisé, sans `upstream=`, avec le nom et
    // la version du paquet source.
    final rawPurl = (a['purl'] as String?) ?? '';
    var purl = _normalizeSyftSystemPurl(rawPurl, codename)
        .replaceAll(RegExp(r'&upstream=[^&]*'), '')
        .replaceAll(RegExp(r'\?upstream=[^&]*&'), '?')
        .replaceFirstMapped(
          RegExp(r'^(pkg:(?:deb|rpm|apk)/[^/]+/)[^@?]+(?:@[^?]*)?'),
          (m) =>
              '${m[1]}${Uri.encodeComponent(src)}@${Uri.encodeComponent(ver)}',
        );
    if (!purl.startsWith('pkg:')) purl = '';

    final vendor = _firstNonEmpty(meta, const [
      'Vendor', 'vendor', 'maintainer', 'Maintainer', 'author', 'Author',
    ]);

    return OciPackage(
      name: src,
      version: ver,
      license: '',
      vendor: vendor,
      url: '',
      summary: '',
      arch: _purlQualifier(rawPurl, 'arch'),
      sourceRef: imageRef,
      imageRef: imageRef,
      requires: [],
      provides: [src],
      packageType: type,
      purlOverride: purl,
    );
  }

  /// Extrait l'OS de base depuis le champ racine `distro` de syft (absent si
  /// syft n'a pas pu détecter de base OS, ex. image `scratch`/distroless).
  ///
  /// L'`id` de syft suit la convention `/etc/os-release` (`rhel`, `ol`,
  /// `almalinux`…) — traduit vers la famille interne attendue par Trivy pour
  /// reconnaître le composant `operating-system` d'un SBOM CycloneDX/SPDX,
  /// voir [_toTrivyOsFamily].
  OsInfo? _syftDistroToOsInfo(Map<String, dynamic> data) {
    final distro = data['distro'] as Map<String, dynamic>?;
    if (distro == null) return null;
    final id = (distro['id'] as String?) ?? '';
    var version = (distro['versionID'] as String?) ?? '';
    if (id.isEmpty || version.isEmpty) return null;
    // Debian expose une release à deux niveaux : `13` (majeur, tel que le
    // porte `VERSION_ID` d'os-release et qu'attendent Grype/OSV-Scanner) et
    // `13.6` (point release, `/etc/debian_version`). syft renseigne le second
    // dans `versionID` ; on ne garde que le majeur pour rester compatible
    // avec les bases CVE Debian (voir aussi _normalizeSyftSystemPurl).
    if (id.toLowerCase() == 'debian' && version.contains('.')) {
      version = version.split('.').first;
    }
    return OsInfo(
      id: _toTrivyOsFamily(id),
      version: version,
      prettyName: distro['prettyName'] as String?,
      cpe: distro['cpeName'] as String?,
    );
  }

  /// Table de correspondance entre l'`id` de distribution façon os-release
  /// (utilisé par syft, ex. `rhel`, `ol`, `almalinux`) et le nom de famille
  /// interne attendu par Trivy pour reconnaître un composant CycloneDX/SPDX
  /// `operating-system` (ex. `redhat`, `oracle`, `alma`) — sans cette
  /// traduction, Trivy en mode `trivy sbom` n'associe le composant à aucune
  /// base CVE connue et ignore silencieusement toute la classe "os-pkgs"
  /// (vérifié empiriquement : `name: "rhel"` → 0 CVE os-pkgs détectée,
  /// `name: "redhat"` → détection correcte).
  ///
  /// Source : `pkg/fanal/analyzer/os/release/release.go` (`idToOSFamily`)
  /// du dépôt aquasecurity/trivy. Les identifiants absents de cette table
  /// (`debian`, `ubuntu`…) sont déjà identiques à la famille Trivy attendue
  /// et passent inchangés ; `amzn` (Amazon Linux) n'a pas d'équivalent
  /// documenté dans cette table côté Trivy (détection version-dépendante
  /// propre à ce backend) et reste donc lui aussi inchangé, en best-effort.
  static const _trivyOsFamilyById = {
    'rhel': 'redhat',
    'centos': 'centos',
    'rocky': 'rocky',
    'almalinux': 'alma',
    'ol': 'oracle',
    'fedora': 'fedora',
    'alpine': 'alpine',
    'bottlerocket': 'bottlerocket',
    'opensuse-tumbleweed': 'opensuse-tumbleweed',
    'opensuse-leap': 'opensuse-leap',
    'opensuse': 'opensuse-leap',
    'sles': 'sles',
    'sle-micro': 'slem',
    'sl-micro': 'slem',
    'sle-micro-rancher': 'slem',
    'photon': 'photon',
    'wolfi': 'wolfi',
    'chainguard': 'chainguard',
    'azurelinux': 'azurelinux',
    'mariner': 'cbl-mariner',
    'echo': 'echo',
    'minimos': 'minimos',
    'coreos': 'coreos',
    'activestate': 'activestate',
  };

  String _toTrivyOsFamily(String id) =>
      _trivyOsFamilyById[id.toLowerCase()] ?? id.toLowerCase();

  OciPackage? _syftArtifactToPackage(
      Map<String, dynamic> a, String imageRef,
      {String? distroCodename}) {
    final name = (a['name'] as String?) ?? '';
    final version = (a['version'] as String?) ?? '';
    if (name.isEmpty) return null;

    final type = _normalizeSyftType((a['type'] as String?) ?? 'generic');
    var purlStr =
        _normalizeSyftSystemPurl((a['purl'] as String?) ?? '', distroCodename);

    final metadata = (a['metadata'] as Map<String, dynamic>?) ?? {};
    final srcName = ((metadata['source'] as String?) ?? '').trim();
    // Quand syft indique un paquet source distinct, `_parseSyft` émet ce
    // paquet source comme composant à part (pour OSV-Scanner). On retire donc
    // le qualifiant `upstream=` du binaire : sinon Grype résout binaire→source
    // ET matche le composant source explicite → même CVE comptée deux fois
    // (cdxgen, qui n'émet pas `upstream=`, ne double-compte pas).
    if (srcName.isNotEmpty && srcName != name) {
      purlStr = purlStr
          .replaceAll(RegExp(r'&upstream=[^&]*'), '')
          .replaceAll(RegExp(r'\?upstream=[^&]*&'), '?')
          .replaceAll(RegExp(r'\?upstream=[^&]*$'), '');
    }

    // Licences : tableau d'objets {value, spdxExpression, …} ou de chaînes
    final licenses = (a['licenses'] as List?) ?? [];
    final licenseStr = licenses
        .map((l) {
          if (l is Map) {
            return (l['spdxExpression'] as String?)?.isNotEmpty == true
                ? l['spdxExpression'] as String
                : (l['value'] as String?) ?? '';
          }
          return l.toString();
        })
        .where((s) => s.isNotEmpty)
        .join(' AND ');

    // Les noms de champs varient selon le catalogueur syft : dpkg/apk
    // exposent des clés en minuscules (`architecture`, `maintainer`), rpm
    // `arch`/`vendor`, d'autres la casse Pascal.
    final arch = _firstNonEmpty(metadata, const [
      'Architecture', 'architecture', 'Arch', 'arch',
    ]);
    // `supplier`/`vendor` du composant : le mainteneur dpkg/apk fait un
    // fournisseur tout à fait valable à défaut d'un champ Vendor rpm.
    final vendor = _firstNonEmpty(metadata, const [
      'Vendor', 'vendor', 'maintainer', 'Maintainer', 'author', 'Author',
    ]);
    final metaSummary = _firstNonEmpty(metadata, const [
      'Summary', 'summary', 'Description', 'description',
    ]);
    final summary =
        metaSummary.isNotEmpty ? metaSummary : ((a['description'] as String?) ?? '');
    final url = _firstNonEmpty(metadata, const [
      'URL', 'url', 'HomePageURL', 'homepage', 'Homepage',
    ]);

    return OciPackage(
      name: name,
      version: version,
      license: licenseStr,
      vendor: vendor,
      url: url,
      summary: summary,
      arch: arch,
      sourceRef: imageRef,
      imageRef: imageRef,
      hashes: hashesFromSyftMetadata(metadata),
      requires: [],
      provides: [name],
      packageType: type,
      purlOverride: purlStr,
    );
  }

  /// Aligne le qualifiant `distro` des PURL système produits par syft sur ce
  /// qu'attendent les scanners.
  ///
  /// syft renseigne pour Debian `distro=debian-13.6` (point release lue dans
  /// `/etc/debian_version`). Grype tolère cette forme, mais OSV-Scanner ne
  /// rattache le paquet à l'écosystème `Debian:13` que si `distro` vaut
  /// `debian-<majeur>` **ou** si `distro_name` porte un nom de code connu —
  /// avec `debian-13.6` il ne trouve silencieusement rien.
  ///
  /// On ramène donc `debian-X.Y` à `debian-X` et on ajoute
  /// `distro_name=<codename>` (aligné sur ce que produit cdxgen), quand syft
  /// a fourni `versionCodename`. Les autres distributions (alpine 3.19,
  /// rhel 9…) où le mineur porte une information sont laissées intactes.
  String _normalizeSyftSystemPurl(String purl, String? codename) {
    if (!purl.contains('distro=debian-')) return purl;
    var out = purl.replaceAllMapped(
      RegExp(r'distro=debian-(\d+)(?:\.\d+)+'),
      (m) => 'distro=debian-${m[1]}',
    );
    if (codename != null &&
        codename.isNotEmpty &&
        !out.contains('distro_name=')) {
      out = '$out&distro_name=${Uri.encodeComponent(codename)}';
    }
    return out;
  }

  String _normalizeSyftType(String type) => switch (type.toLowerCase()) {
        'python' => 'pypi',
        'javascript' || 'node-module-package' => 'npm',
        'golang' || 'go-module' => 'go',
        'java-archive' || 'java' => 'java',
        _ => type.toLowerCase(),
      };

  /// Première valeur `String` non vide parmi [keys] dans [map] (les
  /// catalogueurs syft n'emploient pas tous la même casse de clé).
  static String _firstNonEmpty(Map<String, dynamic> map, List<String> keys) {
    for (final k in keys) {
      final v = map[k];
      if (v is String && v.isNotEmpty) return v;
    }
    return '';
  }

  // ── Backend Trivy ─────────────────────────────────────────────────────────────

  Future<OciParseResult> _parseTrivy(String imageRef,
      {bool verbose = false}) async {
    if (verbose) print('trivy : analyse de $imageRef…');
    return _trivyJsonToResult(
        await _runTrivyJson(_trivyImageArgs(imageRef)), imageRef);
  }

  Future<Map<String, dynamic>> _runTrivyJson(List<String> args) async {
    ProcessResult result = await Process.run('trivy', args);
    // --list-all-pkgs non supporté sur les vieilles versions → réessai sans
    if (result.exitCode > 1 &&
        (result.stderr as String).contains('--list-all-pkgs')) {
      args.remove('--list-all-pkgs');
      result = await Process.run('trivy', args);
    }
    if (result.exitCode > 1) {
      throw Exception(
          'trivy a échoué (code ${result.exitCode}) : ${result.stderr}');
    }
    try {
      return jsonDecode(result.stdout as String) as Map<String, dynamic>;
    } catch (e) {
      throw Exception('trivy : impossible de parser le JSON : $e');
    }
  }

  /// Arguments `trivy image` désignant [imageRef] selon son type.
  List<String> _trivyImageArgs(String imageRef) {
    final args = ['image', '--format', 'json', '--quiet', '--list-all-pkgs'];
    switch (detectRefType(imageRef)) {
      case OciRefType.tar:
        args.addAll(['--input', imageRef]);
      case OciRefType.ociLayout:
        args.add('oci-layout://$imageRef');
      // `trivy image` ne sait pas analyser un binaire autonome (ce n'est pas
      // une référence d'image) ; passé tel quel, l'échec est signalé par
      // trivy lui-même. `--binary` restreint le backend à syft en amont.
      case OciRefType.registry:
      case OciRefType.binary:
        args.add(imageRef);
    }
    return args;
  }

  /// Paquets d'un rapport trivy, chacun accompagné du `Layer.DiffID` de la
  /// couche qui l'a introduit (vide si trivy ne l'indique pas).
  List<({OciPackage pkg, String diffId})> _trivyPackagesWithLayer(
      Map<String, dynamic> data, String imageRef) {
    final out = <({OciPackage pkg, String diffId})>[];
    for (final res in (data['Results'] as List?) ?? []) {
      final r = res as Map<String, dynamic>;
      final ecosystemType = (r['Type'] as String?) ?? '';
      for (final pkg in (r['Packages'] as List?) ?? []) {
        final json = pkg as Map<String, dynamic>;
        final p = _trivyPkgToPackage(json, ecosystemType, imageRef);
        if (p == null) continue;
        final layer = json['Layer'];
        out.add((
          pkg: p,
          diffId: layer is Map ? (layer['DiffID'] as String?) ?? '' : '',
        ));
      }
    }
    return out;
  }

  OciParseResult _trivyJsonToResult(
          Map<String, dynamic> data, String imageRef) =>
      (
        packages: [
          for (final e in _trivyPackagesWithLayer(data, imageRef)) e.pkg,
        ],
        os: _trivyMetadataToOsInfo(data),
      );

  /// Extrait l'OS de base depuis `Metadata.OS` de trivy (absent si trivy n'a
  /// pas pu détecter de base OS, ex. image `scratch`/distroless).
  OsInfo? _trivyMetadataToOsInfo(Map<String, dynamic> data) {
    final os = (data['Metadata'] as Map<String, dynamic>?)?['OS']
        as Map<String, dynamic>?;
    if (os == null) return null;
    final id = (os['Family'] as String?) ?? '';
    final version = (os['Name'] as String?) ?? '';
    if (id.isEmpty || version.isEmpty) return null;
    return OsInfo(id: id, version: version);
  }

  OciPackage? _trivyPkgToPackage(
      Map<String, dynamic> p, String ecosystemType, String imageRef) {
    final name = (p['Name'] as String?) ?? '';
    if (name.isEmpty) return null;

    // Trivy sépare version/release/epoch en champs distincts (contrairement à
    // syft qui rend directement "1:2.41-5"). Reconstituer la version complète
    // est indispensable : le comparateur de versions de grype se base sur le
    // champ `version` du composant CycloneDX, pas sur le PURL. Une version
    // tronquée (release/epoch manquants) le fait comparer par ex. "1.8.12" à
    // la place de "2:1.8.12-1", ce qui la fait paraître bien plus ancienne
    // qu'elle ne l'est et remonte des CVE en réalité déjà corrigées.
    final version = _debFullVersion(
        (p['Version'] as String?) ?? '', (p['Release'] as String?) ?? '', p['Epoch']);
    if (version.isEmpty) return null;

    final licenses = (p['Licenses'] as List?) ?? [];
    final licenseStr =
        licenses.map((l) => l.toString()).where((s) => s.isNotEmpty).join(' AND ');

    final arch = (p['Arch'] as String?) ?? '';
    final vendor = (p['Maintainer'] as String?) ?? '';
    final summary = (p['Summary'] as String?) ?? '';

    final packageType = _normalizeTrivyType(ecosystemType);

    // PURL depuis le champ Identifier (trivy >= 0.38)
    final identifier = p['Identifier'] as Map<String, dynamic>?;
    var purlStr = (identifier?['PURL'] as String?) ?? '';

    // Contrairement à syft, le PURL de trivy n'inclut jamais le qualifiant
    // `upstream` du paquet source Debian/Ubuntu, alors que le security-tracker
    // Debian (utilisé par grype) indexe les CVE par paquet SOURCE et non par
    // paquet binaire (ex : les CVE de "bsdutils" sont classées sous
    // "util-linux", celles de "libc6" sous "glibc"). Sans ce qualifiant, grype
    // ignore silencieusement la vulnérabilité pour tout paquet binaire dont le
    // nom ou la version diffère de son paquet source — trivy expose pourtant
    // cette info via SrcName/SrcVersion/SrcRelease/SrcEpoch.
    if (packageType == 'deb' && purlStr.isNotEmpty && !purlStr.contains('upstream=')) {
      final upstream = _debUpstreamQualifier(p, name, version);
      if (upstream != null) {
        final sep = purlStr.contains('?') ? '&' : '?';
        purlStr = '$purlStr${sep}upstream=${Uri.encodeComponent(upstream)}';
      }
    }

    final deps = (p['DependsOn'] as List?) ?? [];
    final requires = deps.map((d) => d.toString()).toList();

    // Champ `Digest` de trivy (`"<algo>:<hex>"`) — présent pour une partie des
    // paquets système (RPM surtout).
    final digest = packageHashFromDigestString(p['Digest'] as String?);

    return OciPackage(
      name: name,
      version: version,
      license: licenseStr,
      vendor: vendor,
      url: '',
      summary: summary,
      arch: arch,
      sourceRef: imageRef,
      imageRef: imageRef,
      hashes: [if (digest != null) digest],
      requires: requires,
      provides: [name],
      packageType: packageType,
      purlOverride: purlStr,
    );
  }

  /// Construit la valeur du qualifiant `upstream=` (nom [+ version] du paquet
  /// source Debian/Ubuntu), à la manière de syft, à partir des champs Src*
  /// fournis par trivy. Retourne `null` si le paquet binaire et le paquet
  /// source sont identiques (même nom, même version complète) — auquel cas
  /// le qualifiant serait redondant. [binFullVersion] est déjà la version
  /// complète reconstruite (epoch:version-release) du paquet binaire.
  String? _debUpstreamQualifier(
      Map<String, dynamic> p, String name, String binFullVersion) {
    final srcName = (p['SrcName'] as String?) ?? '';
    if (srcName.isEmpty) return null;

    final srcFull = _debFullVersion((p['SrcVersion'] as String?) ?? '',
        (p['SrcRelease'] as String?) ?? '', p['SrcEpoch']);

    if (srcName == name && srcFull == binFullVersion) return null;
    return srcFull != binFullVersion ? '$srcName@$srcFull' : srcName;
  }

  /// Reconstruit la version complète `[epoch:]version[-release]` (convention
  /// Debian/RPM commune) à partir des champs séparés de trivy.
  String _debFullVersion(String version, String release, dynamic epoch) {
    final epochNum =
        epoch is int ? epoch : int.tryParse(epoch?.toString() ?? '');
    final epochPrefix = (epochNum != null && epochNum != 0) ? '$epochNum:' : '';
    final releaseSuffix = release.isNotEmpty ? '-$release' : '';
    return '$epochPrefix$version$releaseSuffix';
  }

  String _normalizeTrivyType(String type) => switch (type.toLowerCase()) {
        'debian' || 'ubuntu' => 'deb',
        'centos' || 'redhat' || 'fedora' || 'rhel' || 'rocky' || 'alma' ||
            'sles' || 'opensuse' =>
          'rpm',
        'alpine' => 'apk',
        'pip' || 'python-pkg' || 'pipenv' || 'poetry' || 'python-pkg' => 'pypi',
        'npm' || 'yarn' || 'node-pkg' || 'pnpm' => 'npm',
        'gobinary' || 'gomod' || 'go' => 'go',
        'jar' || 'gradle' || 'maven' || 'java-archive' => 'java',
        'nuget' || 'dotnet-core' => 'nuget',
        'cargo' || 'rust' => 'cargo',
        _ => type.isEmpty ? 'generic' : type.toLowerCase(),
      };

  // ── Backend Skopeo ────────────────────────────────────────────────────────────
  //
  // Stratégie :
  //  1. Copier l'image en OCI layout local via skopeo
  //  2. Extraire les layers tar dans un répertoire rootfs temporaire
  //  3. Détecter et parser les bases de paquets : dpkg/status, rpm --root, APK
  //
  // L'extraction des layers est séquentielle (base → final) ; chaque layer
  // écrase les fichiers précédents, ce qui donne l'état final du système.

  // Contrairement à syft/trivy, ce backend n'identifie pas l'OS de base
  // (parsing manuel dpkg/rpm/apk sans lecture d'/etc/os-release) : os: null
  // dans le résultat — le SBOM produit n'aura donc pas de composant OS dédié.
  Future<OciParseResult> _parseSkopeo(String imageRef,
      {bool verbose = false}) async {
    final refType = detectRefType(imageRef);

    final tempDir = await Directory.systemTemp.createTemp('sbom_oci_');
    try {
      final ociLayoutDir = refType == OciRefType.ociLayout
          ? imageRef
          : await _copyToOciLayout(
              imageRef, '${tempDir.path}/oci_layout',
              verbose: verbose);

      final fsDir = '${tempDir.path}/rootfs';
      await Directory(fsDir).create();
      await _extractOciLayers(ociLayoutDir, fsDir, verbose: verbose);

      final packages =
          await _scanExtractedRootfs(fsDir, imageRef, verbose: verbose);
      if (packages.isEmpty && verbose) {
        stderr.writeln(
            'skopeo : aucune base de paquets reconnue dans les layers.');
      }

      return (packages: packages, os: null);
    } finally {
      // Certains fichiers extraits des layers OCI peuvent avoir des permissions
      // restrictives (chmod 000) qui font échouer Directory.delete(recursive).
      // On réinitialise les droits avant de supprimer.
      await Process.run('chmod', ['-R', 'u+rwX', tempDir.path]);
      await Process.run('rm', ['-rf', tempDir.path]);
    }
  }

  /// Copie [imageRef] (archive `docker save` ou référence de registre) en
  /// layout OCI dans [destDir] via skopeo, et renvoie [destDir].
  ///
  /// Une référence de registre introuvable à distance est ensuite cherchée
  /// dans le stockage local de podman (`containers-storage:`) puis de Docker
  /// (`docker-daemon:`) — cas des images construites localement
  /// (`localhost/mon-app:1.0`).
  Future<String> _copyToOciLayout(String imageRef, String destDir,
      {bool verbose = false}) async {
    final refType = detectRefType(imageRef);
    final sources = switch (refType) {
      OciRefType.tar => ['docker-archive:$imageRef'],
      OciRefType.registry => [
          'docker://$imageRef',
          'containers-storage:$imageRef',
          'docker-daemon:$imageRef',
        ],
      _ => [imageRef],
    };
    final errors = <String>[];
    for (final src in sources) {
      if (verbose) print('skopeo : copie de $src…');
      final copyResult = await Process.run('skopeo', [
        'copy',
        '--insecure-policy',
        src,
        'oci:$destDir:image',
      ]);
      if (copyResult.exitCode == 0) return destDir;
      errors.add('$src : ${(copyResult.stderr as String).trim()}');
    }
    throw Exception('skopeo copy a échoué :\n  ${errors.join('\n  ')}');
  }

  /// Paquets d'un rootfs déjà extrait dans [fsDir] (backend skopeo) : bases
  /// dpkg, RPM et APK, puis JARs Maven, paquets Python et npm.
  Future<List<Package>> _scanExtractedRootfs(String fsDir, String imageRef,
      {bool verbose = false}) async {
    final packages = <Package>[];

    final dpkgStatus = File('$fsDir/var/lib/dpkg/status');
    if (await dpkgStatus.exists()) {
      if (verbose) print('skopeo : base dpkg trouvée');
      packages.addAll(await _parseDpkgStatus(dpkgStatus, imageRef, fsDir));
    }

    // Vérifier les deux emplacements RPM : traditionnel (/var/lib/rpm) et
    // nouveau (/usr/lib/sysimage/rpm, RHEL 8.4+ / Fedora 33+).
    final rpmDb = Directory('$fsDir/var/lib/rpm');
    final rpmDbNew = Directory('$fsDir/usr/lib/sysimage/rpm');
    if (await rpmDb.exists() || await rpmDbNew.exists()) {
      if (verbose) print('skopeo : base RPM trouvée');
      packages.addAll(await _parseRpmRoot(fsDir, imageRef, verbose: verbose));
    }

    final apkDb = File('$fsDir/lib/apk/db/installed');
    if (await apkDb.exists()) {
      if (verbose) print('skopeo : base APK trouvée');
      packages.addAll(await _parseApkInstalled(apkDb, imageRef));
    }

    packages.addAll(await _parseMavenJars(fsDir, imageRef, verbose: verbose));
    packages
        .addAll(await _parsePythonPackages(fsDir, imageRef, verbose: verbose));
    packages.addAll(await _parseNpmPackages(fsDir, imageRef, verbose: verbose));
    return packages;
  }

  Future<void> _extractOciLayers(String ociDir, String destDir,
      {bool verbose = false}) async {
    final indexData = jsonDecode(
            await File('$ociDir/index.json').readAsString())
        as Map<String, dynamic>;

    final manifests = (indexData['manifests'] as List?) ?? [];
    if (manifests.isEmpty) {
      throw Exception('skopeo : aucun manifest dans le layout OCI');
    }

    // Premier manifest (on prend la première plateforme disponible)
    final manifestRef = manifests.first as Map<String, dynamic>;
    final manifestDigestPath =
        (manifestRef['digest'] as String).replaceFirst(':', '/');

    final manifestData = jsonDecode(
            await File('$ociDir/blobs/$manifestDigestPath').readAsString())
        as Map<String, dynamic>;

    final layers = (manifestData['layers'] as List?) ?? [];
    for (int i = 0; i < layers.length; i++) {
      final layer = layers[i] as Map<String, dynamic>;
      final layerDigestPath =
          (layer['digest'] as String).replaceFirst(':', '/');
      final layerFile = '$ociDir/blobs/$layerDigestPath';

      if (verbose) {
        print(
            '  layer ${i + 1}/${layers.length} : ${layerDigestPath.split('/').last.substring(0, 12)}…');
      }

      final result = await Process.run('tar', [
        '--extract',
        '--file', layerFile,
        '--directory', destDir,
        '--overwrite',
        '--ignore-zeros',
        '--exclude=.wh.*',
        '--no-same-owner',
        '--no-same-permissions',
      ]);
      // Les erreurs tar (fichiers spéciaux, whiteouts) sont non bloquantes
      if (result.exitCode != 0 && verbose) {
        final firstErr =
            (result.stderr as String).split('\n').first.trim();
        if (firstErr.isNotEmpty) {
          stderr.writeln('  Warning (tar layer $i) : $firstErr');
        }
      }
    }
  }

  Future<List<Package>> _parseDpkgStatus(
      File statusFile, String imageRef, String fsDir) async {
    final packages = <Package>[];
    final fields = <String, String>{};
    String? currentKey;
    final buf = StringBuffer();

    void flushPackage() {
      final name = fields['package'] ?? '';
      if (name.isEmpty) {
        fields.clear();
        return;
      }
      final status = fields['status'] ?? '';
      // N'inclure que les paquets effectivement installés
      if (!status.contains('installed')) {
        fields.clear();
        return;
      }
      final description = fields['description'] ?? '';
      final summary = description.split('\n').first.trim();
      packages.add(OciPackage(
        name: name,
        version: fields['version'] ?? '',
        license: _readDebianCopyrightLicense(fsDir, name),
        vendor: fields['maintainer'] ?? '',
        url: fields['homepage'] ?? '',
        summary: summary,
        arch: fields['architecture'] ?? '',
        sourceRef: imageRef,
        imageRef: imageRef,
        requires: _dpkgDepends(fields['depends'] ?? ''),
        provides: [name],
        packageType: 'deb',
      ));
      fields.clear();
    }

    for (final line in await statusFile.readAsLines()) {
      if (line.isEmpty) {
        if (currentKey != null) {
          fields[currentKey] = buf.toString();
          currentKey = null;
        }
        flushPackage();
        continue;
      }
      if (line.startsWith(' ') || line.startsWith('\t')) {
        if (currentKey != null) buf.write('\n${line.trim()}');
      } else {
        if (currentKey != null) fields[currentKey] = buf.toString();
        final colon = line.indexOf(':');
        if (colon > 0) {
          currentKey = line.substring(0, colon).trim().toLowerCase();
          buf
            ..clear()
            ..write(line.substring(colon + 1).trim());
        } else {
          currentKey = null;
        }
      }
    }
    if (currentKey != null) fields[currentKey] = buf.toString();
    flushPackage();

    return packages;
  }

  // Contrairement à RPM, /var/lib/dpkg/status n'a pas de champ Licence —
  // la seule source fiable est /usr/share/doc/<pkg>/copyright, présent pour
  // (quasiment) tout paquet Debian/Ubuntu. On ne l'exploite que lorsqu'il
  // suit le format DEP-5 machine-readable (identifiable par son en-tête
  // Format:) : les champs License: y sont des identifiants courts fiables
  // (ex. "GPL-2.0-or-later", parfois une expression "GPL-2 or Artistic"),
  // que LicenseNormalizer sait déjà normaliser en aval. Les copyright files
  // en texte libre (l'autre convention, plus ancienne) ne sont pas
  // interprétés : deviner une licence dans du texte libre serait trop
  // sujet à erreur pour une donnée censée être fiable.
  static final RegExp _dep5FormatRe =
      RegExp(r'^Format:\s*https?://.*copyright-format', multiLine: true);

  String _readDebianCopyrightLicense(String fsDir, String pkgName) {
    final file = File('$fsDir/usr/share/doc/$pkgName/copyright');
    if (!file.existsSync()) return '';
    final String content;
    try {
      content = file.readAsStringSync();
    } catch (_) {
      return '';
    }
    if (!_dep5FormatRe.hasMatch(content)) return '';

    // Stanzas séparées par une ligne vide ; on retient le champ License:
    // (première ligne seulement — le corps qui suit, indenté, est le texte
    // complet de la licence, pas l'identifiant) de chaque stanza, en
    // priorisant celle qui couvre tout le paquet (Files: *).
    final stanzas = content.split(RegExp(r'\n\s*\n'));
    String? wholePackageLicense;
    final allLicenses = <String>[];
    for (final stanza in stanzas) {
      final filesMatch =
          RegExp(r'^Files:\s*(.+)$', multiLine: true).firstMatch(stanza);
      final licenseMatch =
          RegExp(r'^License:\s*(.+)$', multiLine: true).firstMatch(stanza);
      final license = licenseMatch?.group(1)?.trim();
      if (license == null || license.isEmpty) continue;
      if (!allLicenses.contains(license)) allLicenses.add(license);
      if (filesMatch?.group(1)?.trim() == '*') {
        wholePackageLicense ??= license;
      }
    }
    if (wholePackageLicense != null) return wholePackageLicense;
    return allLicenses.join(' and ');
  }

  List<String> _dpkgDepends(String depends) {
    if (depends.isEmpty) return [];
    return depends
        .split(RegExp(r'[,|]'))
        .map((s) => s.trim().split(RegExp(r'[\s(]')).first.trim())
        .where((s) => s.isNotEmpty)
        .toList();
  }

  Future<List<Package>> _parseRpmRoot(String rootDir, String imageRef,
      {bool verbose = false}) async {
    const queryFormat =
        r'%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{LICENSE}|%{VENDOR}|%{URL}|%{SUMMARY}\n';

    // Détecter l'emplacement exact de la base RPM.
    // IMPORTANT : rpm --root + --dbpath absolu combine les deux chemins (bug),
    // donc on utilise uniquement --dbpath avec le chemin absolu complet.
    String? dbPath;
    for (final candidate in ['var/lib/rpm', 'usr/lib/sysimage/rpm']) {
      final dir = Directory('$rootDir/$candidate');
      if (!await dir.exists()) continue;
      if (await File('$rootDir/$candidate/rpmdb.sqlite').exists() ||
          await File('$rootDir/$candidate/Packages').exists()) {
        dbPath = '$rootDir/$candidate';
        break;
      }
    }
    if (dbPath == null) {
      if (verbose) {
        stderr.writeln('skopeo/rpm : base RPM trouvée mais vide dans $rootDir');
      }
      return [];
    }

    if (verbose) print('skopeo : requête RPM sur $dbPath');

    final result = await Process.run('rpm', [
      '--dbpath', dbPath,
      '-qa',
      '--queryformat', queryFormat,
    ]);

    if (result.exitCode != 0) {
      stderr.writeln(
          'skopeo/rpm : échec (code ${result.exitCode}) : '
          '${(result.stderr as String).split('\n').first.trim()}');
      return [];
    }

    final packages = <Package>[];
    for (final line in (result.stdout as String).split('\n')) {
      final parts = line.split('|');
      if (parts.length < 8) continue;
      final name = parts[0].trim();
      if (name.isEmpty || name == 'gpg-pubkey') continue;
      packages.add(OciPackage(
        name: name,
        version: parts[1].trim(),
        license: parts[4].trim(),
        vendor: parts[5].trim(),
        url: parts[6].trim(),
        summary: parts[7].trim(),
        arch: parts[3].trim(),
        sourceRef: imageRef,
        imageRef: imageRef,
        requires: [],
        provides: [name],
        packageType: 'rpm',
      ));
    }
    return packages;
  }

  Future<List<Package>> _parseMavenJars(String rootDir, String imageRef,
      {bool verbose = false}) async {
    final findResult =
        await Process.run('find', [rootDir, '-name', '*.jar', '-type', 'f']);
    if (findResult.exitCode != 0) return [];

    final jarFiles = (findResult.stdout as String)
        .split('\n')
        .where((l) => l.isNotEmpty)
        .toList();
    if (jarFiles.isEmpty) return [];

    if (verbose) {
      print('skopeo : ${jarFiles.length} JARs trouvés, extraction Maven…');
    }

    final packages = <Package>[];
    final seen = <String>{};

    // Regex : premier tiret suivi d'un chiffre dans le nom de fichier → début de version.
    // Format Quarkus/Red Hat : <groupId>.<artifactId>-<version>.jar
    final _versionSep = RegExp(r'-(\d)');

    for (final jarPath in jarFiles) {
      bool foundViaPom = false;

      final result = await Process.run(
          'unzip', ['-p', jarPath, 'META-INF/maven/*/*/pom.properties']);

      if (result.exitCode == 0) {
        final content = result.stdout as String;
        if (content.trim().isNotEmpty) {
          foundViaPom = true;
          String? groupId, artifactId, version;

          void flush() {
            if (groupId == null || artifactId == null || version == null) return;
            if (groupId!.isEmpty || artifactId!.isEmpty || version!.isEmpty) return;
            final key = '$groupId:$artifactId:$version';
            if (!seen.add(key)) return;
            packages.add(OciPackage(
              name: artifactId!,
              version: version!,
              license: '',
              vendor: '',
              url: '',
              summary: '',
              arch: '',
              sourceRef: imageRef,
              imageRef: imageRef,
              requires: [],
              provides: [artifactId!],
              packageType: 'java',
              purlOverride:
                  'pkg:maven/${Uri.encodeComponent(groupId!)}/${Uri.encodeComponent(artifactId!)}@${Uri.encodeComponent(version!)}',
            ));
            groupId = artifactId = version = null;
          }

          for (final rawLine in content.split('\n')) {
            final line = rawLine.trim();
            if (line.startsWith('#')) continue;
            if (line.isEmpty) {
              flush();
              continue;
            }
            final eq = line.indexOf('=');
            if (eq <= 0) continue;
            final key = line.substring(0, eq).trim();
            final value = line.substring(eq + 1).trim();
            switch (key) {
              case 'groupId':
                groupId = value;
              case 'artifactId':
                artifactId = value;
              case 'version':
                version = value;
            }
          }
          flush();
        }
      }

      // Fallback : pas de pom.properties → déduire les coordonnées depuis le nom
      // de fichier (convention <groupId>.<artifactId>-<version>.jar).
      if (!foundViaPom) {
        final basename = jarPath.split('/').last.replaceAll(RegExp(r'\.jar$'), '');
        final match = _versionSep.firstMatch(basename);
        if (match != null) {
          final prefix = basename.substring(0, match.start);
          final version = basename.substring(match.start + 1);
          final lastDot = prefix.lastIndexOf('.');
          if (lastDot > 0) {
            final groupId = prefix.substring(0, lastDot);
            final artifactId = prefix.substring(lastDot + 1);
            final key = '$groupId:$artifactId:$version';
            if (seen.add(key)) {
              packages.add(OciPackage(
                name: artifactId,
                version: version,
                license: '',
                vendor: '',
                url: '',
                summary: '',
                arch: '',
                sourceRef: imageRef,
                imageRef: imageRef,
                requires: [],
                provides: [artifactId],
                packageType: 'java',
                purlOverride:
                    'pkg:maven/${Uri.encodeComponent(groupId)}/${Uri.encodeComponent(artifactId)}@${Uri.encodeComponent(version)}',
              ));
            }
          }
        }
      }
    }

    if (verbose && packages.isNotEmpty) {
      print('skopeo : ${packages.length} paquets Maven extraits');
    }
    return packages;
  }

  Future<List<Package>> _parsePythonPackages(String rootDir, String imageRef,
      {bool verbose = false}) async {
    final findResult = await Process.run('find', [
      rootDir, '-type', 'f',
      '(', '-path', '*.dist-info/METADATA', '-o', '-path', '*.egg-info/PKG-INFO', ')',
    ]);
    if (findResult.exitCode != 0) return [];

    final metaFiles = (findResult.stdout as String)
        .split('\n')
        .where((l) => l.isNotEmpty)
        .toList();
    if (metaFiles.isEmpty) return [];

    if (verbose) print('skopeo : ${metaFiles.length} métadonnées Python trouvées…');

    final packages = <Package>[];
    final seen = <String>{};

    for (final filePath in metaFiles) {
      String content;
      try {
        content = await File(filePath).readAsString();
      } catch (_) {
        continue;
      }

      String? name, version, summary, license_, url;
      for (final rawLine in content.split('\n')) {
        if (rawLine.isEmpty) break; // En-têtes RFC 822 — fin à la première ligne vide
        final colon = rawLine.indexOf(':');
        if (colon <= 0) continue;
        final key = rawLine.substring(0, colon).trim().toLowerCase();
        final value = rawLine.substring(colon + 1).trim();
        switch (key) {
          case 'name': name = value;
          case 'version': version = value;
          case 'summary': summary = value;
          case 'license': license_ = value;
          case 'home-page': url = value;
        }
      }

      if (name == null || name.isEmpty || version == null || version.isEmpty) continue;
      final normName = name.toLowerCase().replaceAll(RegExp(r'[-_.]+'), '-');
      if (!seen.add('pypi:$normName:$version')) continue;

      packages.add(OciPackage(
        name: name,
        version: version,
        license: license_ ?? '',
        vendor: '',
        url: url ?? '',
        summary: summary ?? '',
        arch: '',
        sourceRef: imageRef,
        imageRef: imageRef,
        requires: [],
        provides: [name],
        packageType: 'pypi',
      ));
    }

    if (verbose && packages.isNotEmpty) {
      print('skopeo : ${packages.length} paquets Python extraits');
    }
    return packages;
  }

  Future<List<Package>> _parseNpmPackages(String rootDir, String imageRef,
      {bool verbose = false}) async {
    // Cherche package.json dans node_modules, un seul niveau de profondeur
    // (évite les node_modules imbriqués qui sont des dépendances de dépendances).
    final findResult = await Process.run('find', [
      rootDir, '-type', 'f', '-name', 'package.json',
      '-path', '*/node_modules/*',
      '-not', '-path', '*/node_modules/*/node_modules/*',
    ]);
    if (findResult.exitCode != 0) return [];

    final pkgFiles = (findResult.stdout as String)
        .split('\n')
        .where((l) => l.isNotEmpty)
        .toList();
    if (pkgFiles.isEmpty) return [];

    if (verbose) print('skopeo : ${pkgFiles.length} package.json npm trouvés…');

    final packages = <Package>[];
    final seen = <String>{};

    for (final filePath in pkgFiles) {
      String content;
      try {
        content = await File(filePath).readAsString();
      } catch (_) {
        continue;
      }

      Map<String, dynamic> json;
      try {
        json = jsonDecode(content) as Map<String, dynamic>;
      } catch (_) {
        continue;
      }

      final name = (json['name'] as String?) ?? '';
      final version = (json['version'] as String?) ?? '';
      if (name.isEmpty || version.isEmpty) continue;
      if (json['private'] == true) continue;

      if (!seen.add('npm:$name:$version')) continue;

      final license_ = switch (json['license']) {
        final String s => s,
        final Map<dynamic, dynamic> m => (m['type'] as String?) ?? '',
        _ => '',
      };
      final description = (json['description'] as String?) ?? '';
      final homepage = (json['homepage'] as String?) ?? '';
      final author = switch (json['author']) {
        final String s => s,
        final Map<dynamic, dynamic> m => (m['name'] as String?) ?? '',
        _ => '',
      };

      packages.add(OciPackage(
        name: name,
        version: version,
        license: license_,
        vendor: author,
        url: homepage,
        summary: description,
        arch: '',
        sourceRef: imageRef,
        imageRef: imageRef,
        requires: [],
        provides: [name],
        packageType: 'npm',
      ));
    }

    if (verbose && packages.isNotEmpty) {
      print('skopeo : ${packages.length} paquets npm extraits');
    }
    return packages;
  }

  Future<List<Package>> _parseApkInstalled(
      File apkDb, String imageRef) async {
    final packages = <Package>[];
    var name = '';
    var version = '';
    var arch = '';
    var license = '';
    var url = '';
    var summary = '';
    final requires = <String>[];

    void flush() {
      if (name.isEmpty) return;
      final a = arch.isNotEmpty ? arch : '';
      packages.add(OciPackage(
        name: name,
        version: version,
        license: license,
        vendor: '',
        url: url,
        summary: summary,
        arch: a,
        sourceRef: imageRef,
        imageRef: imageRef,
        requires: List.from(requires),
        provides: [name],
        packageType: 'apk',
        purlOverride: 'pkg:apk/alpine/${Uri.encodeComponent(name)}'
            '@${Uri.encodeComponent(version)}'
            '${a.isNotEmpty ? "?arch=${Uri.encodeComponent(a)}" : ""}',
      ));
      name = '';
      version = '';
      arch = '';
      license = '';
      url = '';
      summary = '';
      requires.clear();
    }

    for (final line in await apkDb.readAsLines()) {
      if (line.isEmpty) {
        flush();
        continue;
      }
      if (line.length < 2 || line[1] != ':') continue;
      final value = line.substring(2);
      switch (line[0]) {
        case 'P':
          name = value;
        case 'V':
          version = value;
        case 'A':
          arch = value;
        case 'L':
          license = value;
        case 'U':
          url = value;
        case 'T':
          summary = value;
        case 'D':
          requires.addAll(value
              .split(' ')
              .where((s) => s.isNotEmpty && !s.startsWith('!')));
      }
    }
    flush();

    return packages;
  }

  // ── Backend cdxgen ───────────────────────────────────────────────────────────
  //
  // cdxgen (OWASP CycloneDX Generator) produit directement un SBOM CycloneDX
  // complet de l'image (`cdxgen --type docker`). On ne conserve que les
  // composants porteurs d'un PURL d'écosystème de paquets réel (pkg:deb,
  // pkg:rpm, pkg:apk, pkg:pypi, pkg:npm, pkg:golang, pkg:maven…) : cdxgen
  // inventorie aussi chaque fichier/binaire de l'image sous forme de composants
  // `pkg:generic/…` de type `file`, ainsi que des actifs cryptographiques et
  // des dépôts APT, tous écartés pour rester cohérent avec syft/trivy.
  //
  // cdxgen n'émet pas de composant `operating-system` dédié : l'OS de base est
  // reconstitué depuis le qualifiant `distro=` des PURL de paquets système.

  Future<OciParseResult> _parseCdxgen(String imageRef,
      {bool verbose = false}) async {
    final refType = detectRefType(imageRef);
    final target = switch (refType) {
      OciRefType.tar => File(imageRef).absolute.path,
      OciRefType.ociLayout => Directory(imageRef).absolute.path,
      OciRefType.binary => File(imageRef).absolute.path,
      OciRefType.registry => imageRef,
    };

    if (verbose) print('cdxgen : analyse de $target…');

    return _cdxgenRun([
      '--type', 'docker',
      '--output', '-',
      '--no-progress',
      target,
    ], imageRef);
  }

  Future<OciParseResult> _cdxgenRun(List<String> args, String imageRef) async {
    final result = await Process.run('cdxgen', args);
    if (result.exitCode != 0) {
      throw Exception(
          'cdxgen a échoué (code ${result.exitCode}) : ${result.stderr}');
    }

    // cdxgen écrit le BOM sur stdout (--output -) et ses logs sur stderr ;
    // selon la version quelques lignes peuvent tout de même précéder le JSON,
    // on repart donc du premier '{'.
    final out = result.stdout as String;
    final start = out.indexOf('{');
    if (start < 0) {
      throw Exception('cdxgen : aucune sortie JSON reçue.');
    }

    final Map<String, dynamic> data;
    try {
      data = jsonDecode(out.substring(start)) as Map<String, dynamic>;
    } catch (e) {
      throw Exception('cdxgen : impossible de parser le JSON : $e');
    }

    final components = (data['components'] as List?) ?? [];
    final packages = <Package>[];
    var distro = '';
    for (final c in components.whereType<Map<String, dynamic>>()) {
      final pkg = _cdxgenComponentToPackage(c, imageRef);
      if (pkg == null) continue;
      packages.add(pkg);
      if (distro.isEmpty) distro = _purlQualifier(pkg.purl, 'distro');
    }

    return (packages: packages, os: _cdxgenOsInfo(distro));
  }

  /// Correspondance préfixe d'écosystème PURL → [OciPackage.packageType].
  /// Les préfixes absents (`generic`, `oci`, `container`…) sont écartés.
  static const _cdxgenPurlEcosystem = {
    'deb': 'deb',
    'rpm': 'rpm',
    'apk': 'apk',
    'pypi': 'pypi',
    'npm': 'npm',
    'golang': 'go',
    'maven': 'java',
    'gem': 'gem',
    'cargo': 'cargo',
    'nuget': 'nuget',
    'composer': 'composer',
    'pub': 'pub',
    'hex': 'hex',
    'conan': 'conan',
    'swift': 'swift',
  };

  OciPackage? _cdxgenComponentToPackage(
      Map<String, dynamic> c, String imageRef) {
    final type = (c['type'] as String?) ?? '';
    if (type == 'file' ||
        type == 'cryptographic-asset' ||
        type == 'data' ||
        type == 'operating-system' ||
        type == 'container' ||
        type == 'platform') {
      return null;
    }

    final purl = (c['purl'] as String?) ?? '';
    if (!purl.startsWith('pkg:')) return null;
    final eco = purl.substring(4).split(RegExp(r'[/@?]')).first;
    final pkgType = _cdxgenPurlEcosystem[eco];
    if (pkgType == null) return null;

    final rawName = (c['name'] as String?) ?? '';
    if (rawName.isEmpty) return null;
    final group = (c['group'] as String?) ?? '';
    final name =
        (pkgType == 'java' && group.isNotEmpty) ? '$group:$rawName' : rawName;

    // Licences au format CycloneDX : [{expression}] ou [{license:{id|name}}].
    final licenseStr = ((c['licenses'] as List?) ?? [])
        .whereType<Map<String, dynamic>>()
        .map((l) {
          final expr = l['expression'] as String?;
          if (expr != null && expr.isNotEmpty) return expr;
          final lic = l['license'] as Map<String, dynamic>?;
          return (lic?['id'] as String?) ?? (lic?['name'] as String?) ?? '';
        })
        .where((s) => s.isNotEmpty)
        .join(' AND ');

    final vendor = ((c['supplier'] as Map<String, dynamic>?)?['name']
            as String?) ??
        (c['publisher'] as String?) ??
        '';

    var url = '';
    for (final r in ((c['externalReferences'] as List?) ?? const [])
        .whereType<Map<String, dynamic>>()) {
      final t = r['type'];
      if (t == 'website' || t == 'vcs' || t == 'distribution') {
        url = (r['url'] as String?) ?? '';
        if (t == 'website') break;
      }
    }

    return OciPackage(
      name: name,
      version: (c['version'] as String?) ?? '',
      license: licenseStr,
      vendor: vendor,
      url: url,
      summary: (c['description'] as String?) ?? '',
      arch: _purlQualifier(purl, 'arch'),
      sourceRef: imageRef,
      imageRef: imageRef,
      hashes: hashesFromCycloneDx(c['hashes']),
      requires: const [],
      provides: [name],
      packageType: pkgType,
      purlOverride: purl,
    );
  }

  /// Valeur (décodée) d'un qualifiant de PURL (`…?k=v&k2=v2`) ; chaîne vide si
  /// le qualifiant est absent.
  String _purlQualifier(String purl, String key) {
    final q = purl.indexOf('?');
    if (q < 0) return '';
    for (final part in purl.substring(q + 1).split('&')) {
      final eq = part.indexOf('=');
      if (eq > 0 && part.substring(0, eq) == key) {
        return Uri.decodeComponent(part.substring(eq + 1));
      }
    }
    return '';
  }

  /// Reconstitue l'OS de base depuis un qualifiant `distro` de cdxgen
  /// (ex. `debian-12`, `alpine-3.19`, `redhat-9`, `opensuse-leap-15.5`).
  /// La version est le segment après le dernier `-`.
  OsInfo? _cdxgenOsInfo(String? distro) {
    if (distro == null || distro.isEmpty) return null;
    // Certains PURL cdxgen portent `distro_name` (bookworm) en plus de
    // `distro` (debian-12) ; seul `distro` nous intéresse ici.
    final dash = distro.lastIndexOf('-');
    if (dash <= 0 || dash == distro.length - 1) return null;
    return OsInfo(
      id: _toTrivyOsFamily(distro.substring(0, dash)),
      version: distro.substring(dash + 1),
    );
  }
}

// ── Helpers exposés pour les tests du paquet ──────────────────────────────────

/// Appelle [OciParser._parseRpmRoot] depuis les tests sans passer par skopeo.
Future<List<Package>> ociParserParseRpmRoot(
        String rootDir, String imageRef, {bool verbose = false}) =>
    OciParser()._parseRpmRoot(rootDir, imageRef, verbose: verbose);

/// Appelle [OciParser._trivyPkgToPackage] depuis les tests sans passer par
/// l'exécutable trivy, pour vérifier la reconstruction de version et du
/// qualifiant PURL `upstream`.
OciPackage? ociParserTrivyPkgToPackage(
        Map<String, dynamic> pkgJson, String ecosystemType, String imageRef) =>
    OciParser()._trivyPkgToPackage(pkgJson, ecosystemType, imageRef);

/// Appelle [OciParser._parseDpkgStatus] depuis les tests sur un fichier
/// `status` (et un `fsDir` racine, pour `usr/share/doc/<pkg>/copyright`)
/// déjà présents sur disque, sans passer par skopeo.
Future<List<Package>> ociParserParseDpkgStatus(
        File statusFile, String imageRef, String fsDir) =>
    OciParser()._parseDpkgStatus(statusFile, imageRef, fsDir);

/// Appelle [OciParser._syftDistroToOsInfo] depuis les tests, sur un objet
/// JSON syft (racine `syft <image> --output json`) déjà décodé, sans
/// lancer syft.
OsInfo? ociParserSyftDistroToOsInfo(Map<String, dynamic> syftJson) =>
    OciParser()._syftDistroToOsInfo(syftJson);

/// Appelle [OciParser._trivyMetadataToOsInfo] depuis les tests, sur un
/// objet JSON trivy (racine `trivy image --format json`) déjà décodé, sans
/// lancer trivy.
OsInfo? ociParserTrivyMetadataToOsInfo(Map<String, dynamic> trivyJson) =>
    OciParser()._trivyMetadataToOsInfo(trivyJson);

/// Appelle [OciParser._syftArtifactToPackage] depuis les tests, sur un
/// artefact syft (élément de `artifacts[]`) déjà décodé, sans lancer syft.
OciPackage? ociParserSyftArtifactToPackage(
        Map<String, dynamic> artifact, String imageRef,
        {String? distroCodename}) =>
    OciParser()._syftArtifactToPackage(artifact, imageRef,
        distroCodename: distroCodename);

/// Appelle [OciParser._syftSourcePackage] depuis les tests, sur un artefact
/// syft de paquet système déjà décodé.
OciPackage? ociParserSyftSourcePackage(
        Map<String, dynamic> artifact, String? distroCodename, String imageRef,
        {Set<String> existingNames = const {}}) =>
    OciParser()._syftSourcePackage(
        artifact, distroCodename, imageRef, existingNames);

/// Appelle [OciParser._cdxgenComponentToPackage] depuis les tests, sur un
/// composant CycloneDX (élément de `components[]`) déjà décodé, sans lancer
/// cdxgen.
OciPackage? ociParserCdxgenComponentToPackage(
        Map<String, dynamic> component, String imageRef) =>
    OciParser()._cdxgenComponentToPackage(component, imageRef);

/// Appelle [OciParser._cdxgenOsInfo] depuis les tests, sur un qualifiant
/// `distro` de PURL cdxgen (ex. `debian-12`).
OsInfo? ociParserCdxgenOsInfo(String? distroQualifier) =>
    OciParser()._cdxgenOsInfo(distroQualifier);

/// Appelle [OciParser._syftLayerAttribution] depuis les tests, sur une sortie
/// JSON `syft --scope all-layers` déjà décodée, sans lancer syft.
({List<ImageLayer> layers, Map<String, int> layerOf})
    ociParserSyftLayerAttribution(
            Map<String, dynamic> syftJson, String imageRef) =>
        OciParser()._syftLayerAttribution(syftJson, imageRef);

/// Appelle [OciParser._trivyLayerAttribution] depuis les tests, sur une
/// sortie JSON `trivy image` déjà décodée, sans lancer trivy.
({List<ImageLayer> layers, Map<String, int> layerOf})
    ociParserTrivyLayerAttribution(
            Map<String, dynamic> trivyJson, String imageRef) =>
        OciParser()._trivyLayerAttribution(trivyJson, imageRef);
