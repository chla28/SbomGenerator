class OutputFile {
  final String path;
  final String size;

  const OutputFile({required this.path, required this.size});
}

class SbomStats {
  final int packageCount;
  final int dependencyCount;

  const SbomStats({required this.packageCount, required this.dependencyCount});
}

class SbomResult {
  final List<OutputFile> outputFiles;
  final List<String> warnings;
  final String? error;
  final int exitCode;
  final SbomStats? stats;

  const SbomResult({
    required this.outputFiles,
    required this.warnings,
    required this.exitCode,
    this.error,
    this.stats,
  });
}
