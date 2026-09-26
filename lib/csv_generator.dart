import 'dart:io';
import 'image_layers.dart';
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

    /// `--per-layer` : colonnes `layer`/`layer_modified_by` (SBOM global) ou
    /// `change`/`previous_version` (SBOM de couche, composants supprimés
    /// compris, avec `change=removed`).
    LayerAnnotations? layers,
  }) async {
    final buf = StringBuffer();
    final layerDoc = layers?.isLayerDocument == true;
    buf.writeln([
      ..._headers,
      if (layers != null && !layerDoc) ...['layer', 'layer_modified_by'],
      if (layerDoc) ...['change', 'previous_version'],
    ].join(','));

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
        if (layers != null) ..._layerCells(pkg, layers),
      ].join(','));
    }
    if (layerDoc) {
      for (final pkg in layers!.removed) {
        buf.writeln([
          _cell(pkg.name),
          _cell(pkg.fullVersion),
          _cell(pkg.arch),
          _cell(pkg.license),
          _cell(pkg.packageType),
          _cell(pkg.purl),
          _cell(pkg.url),
          _cell(pkg.vendor),
          'removed',
          '',
        ].join(','));
      }
    }

    await File(outputPath).writeAsString(buf.toString());
  }

  List<String> _layerCells(Package pkg, LayerAnnotations layers) {
    final f = layers.componentFields(pkg);
    return layers.isLayerDocument
        ? [_cell(f['change'] ?? ''), _cell(f['previousVersion'] ?? '')]
        : [_cell(f['index'] ?? ''), _cell(f['modifiedBy'] ?? '')];
  }

  String _cell(String value) {
    if (value.contains(',') || value.contains('"') || value.contains('\n')) {
      return '"${value.replaceAll('"', '""')}"';
    }
    return value;
  }
}
