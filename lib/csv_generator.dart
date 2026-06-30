import 'dart:io';
import 'models.dart';

/// Generates a CSV file with one row per package (RFC 4180 compliant).
class CsvGenerator {
  static const _headers = [
    'name',
    'version',
    'architecture',
    'license',
    'type',
    'purl',
    'url',
    'vendor',
  ];

  Future<void> writeToFile(
    List<Package> packages,
    String outputPath, {
    String? documentName,
  }) async {
    final buf = StringBuffer();
    buf.writeln(_headers.join(','));

    final sorted = List<Package>.from(packages)
      ..sort((a, b) => a.name.compareTo(b.name));

    for (final pkg in sorted) {
      buf.writeln([
        _cell(pkg.name),
        _cell(pkg.fullVersion),
        _cell(pkg.arch),
        _cell(pkg.license),
        _cell(pkg.packageType),
        _cell(pkg.purl),
        _cell(pkg.url),
        _cell(pkg.vendor),
      ].join(','));
    }

    await File(outputPath).writeAsString(buf.toString());
  }

  String _cell(String value) {
    if (value.contains(',') || value.contains('"') || value.contains('\n')) {
      return '"${value.replaceAll('"', '""')}"';
    }
    return value;
  }
}
