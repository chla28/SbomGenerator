import '../l10n/l10n.dart';

const _formatExtensions = {
  'cyclonedx': '.cdx.json',
  'spdx': '.spdx.json',
  'spdx3': '.spdx3.jsonld',
  'json': '.custom.json',
  'markdown': '.md',
  'asciidoc': '.adoc',
  'html': '.html',
  'csv': '.csv',
};

const _knownExtensions = [
  '.cdx.json',
  '.spdx.json',
  '.spdx3.jsonld',
  '.custom.json',
  '.jsonld',
  '.json',
  '.md',
  '.adoc',
  '.html',
  '.csv',
];

String _stripKnownExtension(String path) {
  for (final ext in _knownExtensions) {
    if (path.endsWith(ext)) return path.substring(0, path.length - ext.length);
  }
  return path;
}

String formatExtension(String fmt) => _formatExtensions[fmt] ?? '.json';

const allFormats = [
  'cyclonedx',
  'spdx',
  'spdx3',
  'json',
  'markdown',
  'asciidoc',
  'html',
  'csv',
];

const formatLabels = {
  'cyclonedx': 'CycloneDX',
  'spdx': 'SPDX 2.3',
  'spdx3': 'SPDX 3.0 JSON-LD',
  'json': 'JSON',
  'markdown': 'Markdown',
  'asciidoc': 'AsciiDoc',
  'html': 'HTML',
  'csv': 'CSV',
};

/// Libellé affiché d'un format : [formatLabels], sauf `json` qui est traduit.
String formatLabel(String fmt, AppLocalizations l) =>
    fmt == 'json' ? l.formatJsonCustom : formatLabels[fmt] ?? fmt;

const allOciTools = ['syft', 'trivy', 'skopeo', 'cdxgen'];

const ociToolLabels = {
  'syft': 'Syft',
  'trivy': 'Trivy',
  'skopeo': 'Skopeo',
  'cdxgen': 'cdxgen',
};

/// Backends capables de `--layer-mode metadata` (ils indiquent la couche
/// d'origine de chaque paquet) ; les autres n'acceptent que `rootfs`.
const metadataLayerTools = {'syft', 'trivy'};

/// Profondeurs de descente acceptées par --depth (0 = l'objet seul, N
/// niveaux, `all` = sans limite).
const allNestedDepths = ['0', '1', '2', '3', 'all'];

/// Versions CycloneDX supportées par --cyclonedx-version.
const allCycloneDxVersions = ['1.6', '1.7'];

class SbomConfig {
  String inputFile;
  String outputBase;
  Set<String> formats;
  String documentName;
  String rpmDir;
  String licenseMapFile;

  /// Versions réelles des SDK Dart/Flutter (`--sdk-version`), au format
  /// `flutter=3.47.5 dart=3.13.4` (espaces ou virgules). Vide : détection
  /// automatique de Flutter par le CLI.
  String sdkVersions;
  int concurrency;
  bool verbose;
  bool generatePdf;
  String pdfOutputPath; // vide = même répertoire que .adoc, extension .pdf
  bool enableSbomqs;

  /// Référence à une image OCI (--image). Vide = non utilisé.
  String imageRef;

  /// Backend OCI choisi (--oci-tool) : 'syft', 'trivy', 'skopeo' ou 'cdxgen'.
  String ociTool;

  /// Binaire local à analyser directement (--binary). Vide = non utilisé.
  /// Mutuellement exclusif avec [inputFile] et [imageRef] (voir --binary côté
  /// CLI) ; force le backend syft, seul capable d'exploiter les métadonnées
  /// embarquées dans un binaire autonome.
  String binaryPath;

  /// Version CycloneDX générée (--cyclonedx-version) : '1.6' ou '1.7'.
  String cycloneDxVersion;

  /// Un SBOM par couche de l'image en plus du global (--per-layer). Sans
  /// effet sans [imageRef].
  bool perLayer;

  /// Méthode de --per-layer (--layer-mode) : 'metadata' ou 'rootfs'. Voir
  /// [effectiveLayerMode] pour la valeur réellement transmise.
  String layerMode;

  /// Profondeur de descente dans les objets imbriqués de [inputFile]
  /// (--depth) : '0' (défaut, l'objet seul), '1'…'3' ou 'all'. Sans effet
  /// pour une image ou un binaire.
  String nestedDepth;

  /// Avec une profondeur > 0 : un SBOM par objet imbriqué en plus du SBOM
  /// fusionné (désactivé : --no-nested-files).
  bool nestedFiles;

  SbomConfig({
    this.inputFile = '',
    this.outputBase = 'sbom',
    Set<String>? formats,
    this.documentName = '',
    this.rpmDir = '',
    this.licenseMapFile = '',
    this.sdkVersions = '',
    this.concurrency = 4,
    this.verbose = false,
    this.generatePdf = false,
    this.pdfOutputPath = '',
    this.enableSbomqs = false,
    this.imageRef = '',
    this.ociTool = 'syft',
    this.binaryPath = '',
    this.cycloneDxVersion = '1.6',
    this.perLayer = false,
    this.layerMode = 'metadata',
    this.nestedDepth = '0',
    this.nestedFiles = true,
  }) : formats = formats ?? {'cyclonedx'};

  Map<String, dynamic> toJson() => {
    'outputBase': outputBase,
    'formats': formats.toList(),
    'documentName': documentName,
    'rpmDir': rpmDir,
    'licenseMapFile': licenseMapFile,
    'sdkVersions': sdkVersions,
    'concurrency': concurrency,
    'verbose': verbose,
    'generatePdf': generatePdf,
    'enableSbomqs': enableSbomqs,
    'imageRef': imageRef,
    'ociTool': ociTool,
    'binaryPath': binaryPath,
    'cycloneDxVersion': cycloneDxVersion,
    'perLayer': perLayer,
    'layerMode': layerMode,
    'nestedDepth': nestedDepth,
    'nestedFiles': nestedFiles,
  };

  factory SbomConfig.fromJson(Map<String, dynamic> j) => SbomConfig(
    outputBase: j['outputBase'] as String? ?? 'sbom',
    formats: (j['formats'] as List?)?.cast<String>().toSet() ?? {'cyclonedx'},
    documentName: j['documentName'] as String? ?? '',
    rpmDir: j['rpmDir'] as String? ?? '',
    licenseMapFile: j['licenseMapFile'] as String? ?? '',
    sdkVersions: j['sdkVersions'] as String? ?? '',
    concurrency: j['concurrency'] as int? ?? 4,
    verbose: j['verbose'] as bool? ?? false,
    generatePdf: j['generatePdf'] as bool? ?? false,
    enableSbomqs: j['enableSbomqs'] as bool? ?? false,
    imageRef: j['imageRef'] as String? ?? '',
    ociTool: j['ociTool'] as String? ?? 'syft',
    binaryPath: j['binaryPath'] as String? ?? '',
    cycloneDxVersion: j['cycloneDxVersion'] as String? ?? '1.6',
    perLayer: j['perLayer'] as bool? ?? false,
    layerMode: j['layerMode'] as String? ?? 'metadata',
    nestedDepth: j['nestedDepth'] as String? ?? '0',
    nestedFiles: j['nestedFiles'] as bool? ?? true,
  );

  /// Mode --layer-mode transmis au CLI : 'rootfs' pour les backends qui
  /// n'indiquent pas la couche d'origine des paquets (skopeo, cdxgen), quel
  /// que soit le choix mémorisé.
  String get effectiveLayerMode =>
      metadataLayerTools.contains(ociTool) ? layerMode : 'rootfs';

  List<String> toArgs() {
    final args = <String>[];
    if (inputFile.isNotEmpty) {
      args.addAll(['--input', inputFile]);
      // --depth s'applique aux objets de --input (le CLI le refuse sans lui).
      if (nestedDepth != '0') {
        args.addAll(['--depth', nestedDepth]);
        if (!nestedFiles) args.add('--no-nested-files');
      }
    }
    if (binaryPath.isNotEmpty) {
      // --binary est exclusif de --image côté CLI et force --oci-tool syft :
      // pas de --oci-tool ici, la valeur choisie par l'utilisateur (ociTool)
      // ne s'applique qu'à --image.
      args.addAll(['--binary', binaryPath]);
    } else if (imageRef.isNotEmpty) {
      args.addAll(['--image', imageRef]);
      args.addAll(['--oci-tool', ociTool]);
      if (perLayer) {
        args.addAll(['--per-layer', '--layer-mode', effectiveLayerMode]);
      }
    }
    if (outputBase.isNotEmpty) {
      args.addAll(['--output', outputBase]);
    }
    if (formats.isNotEmpty) {
      args.addAll(['--format', formats.join(',')]);
    }
    if (documentName.isNotEmpty) {
      args.addAll(['--name', documentName]);
    }
    if (rpmDir.isNotEmpty) {
      args.addAll(['--rpm-dir', rpmDir]);
    }
    if (licenseMapFile.isNotEmpty) {
      args.addAll(['--license-map', licenseMapFile]);
    }
    for (final entry in sdkVersions.split(RegExp(r'[\s,]+'))) {
      if (entry.contains('=')) args.addAll(['--sdk-version', entry]);
    }
    if (formats.contains('cyclonedx') && cycloneDxVersion != '1.6') {
      args.addAll(['--cyclonedx-version', cycloneDxVersion]);
    }
    args.addAll(['--concurrency', concurrency.toString()]);
    if (verbose) args.add('--verbose');
    return args;
  }

  /// Ligne de commande équivalente (affichage uniquement).
  String toCommandLine(String binary) {
    return [
      binary,
      ...toArgs(),
    ].map((s) => s.contains(' ') ? '"$s"' : s).join(' ');
  }

  /// Chemins de sortie attendus (prévisualisation avant exécution).
  List<String> expectedOutputPaths() {
    final base = outputBase.isEmpty ? 'sbom' : outputBase;
    // Même règle que le CLI (`_outputPathFor`) : avec un seul format, un
    // chemin déjà muni d'une extension SBOM connue est conservé tel quel.
    final stripped = _stripKnownExtension(base);
    if (formats.length == 1 && stripped != base) return [base];
    return formats.map((f) => '$stripped${formatExtension(f)}').toList();
  }
}
