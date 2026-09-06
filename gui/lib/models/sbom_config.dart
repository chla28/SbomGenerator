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

String formatExtension(String fmt) => _formatExtensions[fmt] ?? '.json';

const allFormats = ['cyclonedx', 'spdx', 'spdx3', 'json', 'markdown', 'asciidoc', 'html', 'csv'];

const formatLabels = {
  'cyclonedx': 'CycloneDX',
  'spdx': 'SPDX 2.3',
  'spdx3': 'SPDX 3.0 JSON-LD',
  'json': 'JSON personnalisé',
  'markdown': 'Markdown',
  'asciidoc': 'AsciiDoc',
  'html': 'HTML',
  'csv': 'CSV',
};

const allOciTools = ['syft', 'trivy', 'skopeo', 'cdxgen'];

const ociToolLabels = {
  'syft': 'Syft',
  'trivy': 'Trivy',
  'skopeo': 'Skopeo',
  'cdxgen': 'cdxgen',
};

/// Versions CycloneDX supportées par --cyclonedx-version.
const allCycloneDxVersions = ['1.6', '1.7'];

class SbomConfig {
  String inputFile;
  String outputBase;
  Set<String> formats;
  String documentName;
  String rpmDir;
  String licenseMapFile;
  int concurrency;
  bool verbose;
  bool generatePdf;
  String pdfOutputPath; // vide = même répertoire que .adoc, extension .pdf
  bool enableSbomqs;

  /// Référence à une image OCI (--image). Vide = non utilisé.
  String imageRef;

  /// Backend OCI choisi (--oci-tool) : 'syft', 'trivy', 'skopeo' ou 'cdxgen'.
  String ociTool;

  /// Version CycloneDX générée (--cyclonedx-version) : '1.6' ou '1.7'.
  String cycloneDxVersion;

  SbomConfig({
    this.inputFile = '',
    this.outputBase = 'sbom',
    Set<String>? formats,
    this.documentName = '',
    this.rpmDir = '',
    this.licenseMapFile = '',
    this.concurrency = 4,
    this.verbose = false,
    this.generatePdf = false,
    this.pdfOutputPath = '',
    this.enableSbomqs = false,
    this.imageRef = '',
    this.ociTool = 'syft',
    this.cycloneDxVersion = '1.6',
  }) : formats = formats ?? {'cyclonedx'};

  Map<String, dynamic> toJson() => {
    'outputBase': outputBase,
    'formats': formats.toList(),
    'documentName': documentName,
    'rpmDir': rpmDir,
    'licenseMapFile': licenseMapFile,
    'concurrency': concurrency,
    'verbose': verbose,
    'generatePdf': generatePdf,
    'enableSbomqs': enableSbomqs,
    'imageRef': imageRef,
    'ociTool': ociTool,
    'cycloneDxVersion': cycloneDxVersion,
  };

  factory SbomConfig.fromJson(Map<String, dynamic> j) => SbomConfig(
    outputBase: j['outputBase'] as String? ?? 'sbom',
    formats: (j['formats'] as List?)?.cast<String>().toSet() ?? {'cyclonedx'},
    documentName: j['documentName'] as String? ?? '',
    rpmDir: j['rpmDir'] as String? ?? '',
    licenseMapFile: j['licenseMapFile'] as String? ?? '',
    concurrency: j['concurrency'] as int? ?? 4,
    verbose: j['verbose'] as bool? ?? false,
    generatePdf: j['generatePdf'] as bool? ?? false,
    enableSbomqs: j['enableSbomqs'] as bool? ?? false,
    imageRef: j['imageRef'] as String? ?? '',
    ociTool: j['ociTool'] as String? ?? 'syft',
    cycloneDxVersion: j['cycloneDxVersion'] as String? ?? '1.6',
  );

  List<String> toArgs() {
    final args = <String>[];
    if (inputFile.isNotEmpty) args.addAll(['--input', inputFile]);
    if (imageRef.isNotEmpty) {
      args.addAll(['--image', imageRef]);
      args.addAll(['--oci-tool', ociTool]);
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
    if (formats.contains('cyclonedx') && cycloneDxVersion != '1.6') {
      args.addAll(['--cyclonedx-version', cycloneDxVersion]);
    }
    args.addAll(['--concurrency', concurrency.toString()]);
    if (verbose) args.add('--verbose');
    return args;
  }

  /// Ligne de commande équivalente (affichage uniquement).
  String toCommandLine(String binary) {
    return [binary, ...toArgs()]
        .map((s) => s.contains(' ') ? '"$s"' : s)
        .join(' ');
  }

  /// Chemins de sortie attendus (prévisualisation avant exécution).
  List<String> expectedOutputPaths() {
    final base = outputBase.isEmpty ? 'sbom' : outputBase;
    if (formats.length == 1) {
      return ['$base${formatExtension(formats.first)}'];
    }
    return formats.map((f) => '$base${formatExtension(f)}').toList();
  }
}
