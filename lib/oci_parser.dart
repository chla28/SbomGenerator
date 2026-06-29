import 'dart:convert';
import 'dart:io';
import 'models.dart';

/// Format de la référence OCI fournie par l'utilisateur.
enum OciRefType {
  /// Référence registre : `nginx:latest`, `ubuntu@sha256:…`
  registry,

  /// Archive tar exportée avec `docker save` ou `skopeo copy docker-archive:…`
  tar,

  /// Répertoire au format OCI Image Layout Specification (contient `index.json`)
  ociLayout,
}

/// Parse les paquets présents dans une image OCI via syft, trivy ou skopeo.
class OciParser {
  // ── Détection automatique du format ─────────────────────────────────────────

  static OciRefType detectRefType(String ref) {
    if (ref.endsWith('.tar') || ref.endsWith('.tar.gz')) return OciRefType.tar;
    if (Directory(ref).existsSync() && File('$ref/index.json').existsSync()) {
      return OciRefType.ociLayout;
    }
    return OciRefType.registry;
  }

  // ── Point d'entrée principal ─────────────────────────────────────────────────

  Future<List<Package>> parseImage(
    String imageRef,
    String tool, {
    bool verbose = false,
  }) async {
    switch (tool) {
      case 'syft':
        return _parseSyft(imageRef, verbose: verbose);
      case 'trivy':
        return _parseTrivy(imageRef, verbose: verbose);
      case 'skopeo':
        return _parseSkopeo(imageRef, verbose: verbose);
      default:
        throw ArgumentError('Outil OCI inconnu : $tool');
    }
  }

  // ── Backend Syft ─────────────────────────────────────────────────────────────

  Future<List<Package>> _parseSyft(String imageRef,
      {bool verbose = false}) async {
    final refType = detectRefType(imageRef);
    final syftRef = switch (refType) {
      OciRefType.tar => 'docker-archive:$imageRef',
      OciRefType.ociLayout => 'oci-dir:$imageRef',
      OciRefType.registry => imageRef,
    };

    if (verbose) print('syft : analyse de $syftRef…');

    final result = await Process.run('syft', [syftRef, '--output', 'json']);
    if (result.exitCode != 0) {
      throw Exception(
          'syft a échoué (code ${result.exitCode}) : ${result.stderr}');
    }

    final Map<String, dynamic> data;
    try {
      data =
          jsonDecode(result.stdout as String) as Map<String, dynamic>;
    } catch (e) {
      throw Exception('syft : impossible de parser le JSON : $e');
    }

    final artifacts = (data['artifacts'] as List?) ?? [];
    final packages = <Package>[];
    for (final a in artifacts) {
      final pkg =
          _syftArtifactToPackage(a as Map<String, dynamic>, imageRef);
      if (pkg != null) packages.add(pkg);
    }
    return packages;
  }

  OciPackage? _syftArtifactToPackage(
      Map<String, dynamic> a, String imageRef) {
    final name = (a['name'] as String?) ?? '';
    final version = (a['version'] as String?) ?? '';
    if (name.isEmpty) return null;

    final type = _normalizeSyftType((a['type'] as String?) ?? 'generic');
    final purlStr = (a['purl'] as String?) ?? '';

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

    final metadata = (a['metadata'] as Map<String, dynamic>?) ?? {};
    final arch = (metadata['Architecture'] as String?) ??
        (metadata['Arch'] as String?) ??
        '';
    final vendor = (metadata['Vendor'] as String?) ?? '';
    final summary = (metadata['Summary'] as String?) ??
        (metadata['Description'] as String?) ??
        (a['description'] as String?) ??
        '';
    final url = (metadata['URL'] as String?) ??
        (metadata['HomePageURL'] as String?) ??
        '';

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
      requires: [],
      provides: [name],
      packageType: type,
      purlOverride: purlStr,
    );
  }

  String _normalizeSyftType(String type) => switch (type.toLowerCase()) {
        'python' => 'pypi',
        'javascript' || 'node-module-package' => 'npm',
        'golang' || 'go-module' => 'go',
        'java-archive' || 'java' => 'java',
        _ => type.toLowerCase(),
      };

  // ── Backend Trivy ─────────────────────────────────────────────────────────────

  Future<List<Package>> _parseTrivy(String imageRef,
      {bool verbose = false}) async {
    final refType = detectRefType(imageRef);

    if (verbose) print('trivy : analyse de $imageRef…');

    final args = ['image', '--format', 'json', '--quiet', '--list-all-pkgs'];
    switch (refType) {
      case OciRefType.tar:
        args.addAll(['--input', imageRef]);
      case OciRefType.ociLayout:
        args.add('oci-layout://$imageRef');
      case OciRefType.registry:
        args.add(imageRef);
    }

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

    final Map<String, dynamic> data;
    try {
      data =
          jsonDecode(result.stdout as String) as Map<String, dynamic>;
    } catch (e) {
      throw Exception('trivy : impossible de parser le JSON : $e');
    }

    final packages = <Package>[];
    for (final res in (data['Results'] as List?) ?? []) {
      final r = res as Map<String, dynamic>;
      final ecosystemType = (r['Type'] as String?) ?? '';
      for (final pkg in (r['Packages'] as List?) ?? []) {
        final p =
            _trivyPkgToPackage(pkg as Map<String, dynamic>, ecosystemType, imageRef);
        if (p != null) packages.add(p);
      }
    }
    return packages;
  }

  OciPackage? _trivyPkgToPackage(
      Map<String, dynamic> p, String ecosystemType, String imageRef) {
    final name = (p['Name'] as String?) ?? '';
    final version = (p['Version'] as String?) ?? '';
    if (name.isEmpty) return null;

    final licenses = (p['Licenses'] as List?) ?? [];
    final licenseStr =
        licenses.map((l) => l.toString()).where((s) => s.isNotEmpty).join(' AND ');

    final arch = (p['Arch'] as String?) ?? '';
    final vendor = (p['Maintainer'] as String?) ?? '';
    final summary = (p['Summary'] as String?) ?? '';

    // PURL depuis le champ Identifier (trivy >= 0.38)
    final identifier = p['Identifier'] as Map<String, dynamic>?;
    final purlStr = (identifier?['PURL'] as String?) ?? '';

    final deps = (p['DependsOn'] as List?) ?? [];
    final requires = deps.map((d) => d.toString()).toList();

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
      requires: requires,
      provides: [name],
      packageType: _normalizeTrivyType(ecosystemType),
      purlOverride: purlStr,
    );
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

  Future<List<Package>> _parseSkopeo(String imageRef,
      {bool verbose = false}) async {
    final refType = detectRefType(imageRef);

    final tempDir = await Directory.systemTemp.createTemp('sbom_oci_');
    try {
      String ociLayoutDir;

      if (refType == OciRefType.ociLayout) {
        ociLayoutDir = imageRef;
      } else {
        ociLayoutDir = '${tempDir.path}/oci_layout';

        final skopeoDst = 'oci:$ociLayoutDir:image';
        final skopeoSrc = switch (refType) {
          OciRefType.tar => 'docker-archive:$imageRef',
          OciRefType.registry => 'docker://$imageRef',
          _ => imageRef,
        };

        if (verbose) print('skopeo : copie de $skopeoSrc…');

        final copyResult = await Process.run('skopeo', [
          'copy',
          '--insecure-policy',
          skopeoSrc,
          skopeoDst,
        ]);
        if (copyResult.exitCode != 0) {
          throw Exception(
              'skopeo copy a échoué (code ${copyResult.exitCode}) : '
              '${copyResult.stderr}');
        }
      }

      final fsDir = '${tempDir.path}/rootfs';
      await Directory(fsDir).create();
      await _extractOciLayers(ociLayoutDir, fsDir, verbose: verbose);

      final packages = <Package>[];

      final dpkgStatus = File('$fsDir/var/lib/dpkg/status');
      if (await dpkgStatus.exists()) {
        if (verbose) print('skopeo : base dpkg trouvée');
        packages.addAll(await _parseDpkgStatus(dpkgStatus, imageRef));
      }

      // Vérifier les deux emplacements RPM : traditionnel (/var/lib/rpm) et
      // nouveau (/usr/lib/sysimage/rpm, RHEL 8.4+ / Fedora 33+).
      final rpmDb = Directory('$fsDir/var/lib/rpm');
      final rpmDbNew = Directory('$fsDir/usr/lib/sysimage/rpm');
      if (await rpmDb.exists() || await rpmDbNew.exists()) {
        if (verbose) print('skopeo : base RPM trouvée');
        packages.addAll(
            await _parseRpmRoot(fsDir, imageRef, verbose: verbose));
      }

      final apkDb = File('$fsDir/lib/apk/db/installed');
      if (await apkDb.exists()) {
        if (verbose) print('skopeo : base APK trouvée');
        packages.addAll(await _parseApkInstalled(apkDb, imageRef));
      }

      final mavenPkgs = await _parseMavenJars(fsDir, imageRef, verbose: verbose);
      packages.addAll(mavenPkgs);

      if (packages.isEmpty && verbose) {
        stderr.writeln(
            'skopeo : aucune base de paquets reconnue dans les layers.');
      }

      return packages;
    } finally {
      // Certains fichiers extraits des layers OCI peuvent avoir des permissions
      // restrictives (chmod 000) qui font échouer Directory.delete(recursive).
      // On réinitialise les droits avant de supprimer.
      await Process.run('chmod', ['-R', 'u+rwX', tempDir.path]);
      await Process.run('rm', ['-rf', tempDir.path]);
    }
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
      File statusFile, String imageRef) async {
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
        license: '',
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
}

// ── Helpers exposés pour les tests du paquet ──────────────────────────────────

/// Appelle [OciParser._parseRpmRoot] depuis les tests sans passer par skopeo.
Future<List<Package>> ociParserParseRpmRoot(
        String rootDir, String imageRef, {bool verbose = false}) =>
    OciParser()._parseRpmRoot(rootDir, imageRef, verbose: verbose);
