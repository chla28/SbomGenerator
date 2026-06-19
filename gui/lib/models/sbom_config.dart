const _formatExtensions = {
  'cyclonedx': '.cdx.json',
  'spdx': '.spdx.json',
  'spdx3': '.spdx3.jsonld',
  'json': '.custom.json',
  'markdown': '.md',
  'asciidoc': '.adoc',
};

String formatExtension(String fmt) => _formatExtensions[fmt] ?? '.json';

const allFormats = ['cyclonedx', 'spdx', 'spdx3', 'json', 'markdown', 'asciidoc'];

const formatLabels = {
  'cyclonedx': 'CycloneDX 1.6',
  'spdx': 'SPDX 2.3',
  'spdx3': 'SPDX 3.0 JSON-LD',
  'json': 'JSON personnalisé',
  'markdown': 'Markdown',
  'asciidoc': 'AsciiDoc',
};

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
  }) : formats = formats ?? {'cyclonedx'};

  List<String> toArgs() {
    final args = <String>['--input', inputFile];
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
    args.addAll(['--concurrency', concurrency.toString()]);
    if (verbose) args.add('--verbose');
    return args;
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
