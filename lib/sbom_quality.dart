import 'cra_report.dart';
import 'i18n.dart';

/// Un critère évalué : [score] de 0 (absent) à 1 (présent partout).
class QualityItem {
  final String id;
  final String label;
  final double score;

  /// Critère des éléments minimaux NTIA (2021) ; sinon complément de qualité.
  final bool ntia;

  /// Composants concernés (tronqué) ; vide pour un critère de document.
  final List<String> offenders;

  const QualityItem(this.id, this.label, this.score,
      {required this.ntia, this.offenders = const []});
}

/// Note de qualité d'un SBOM : éléments minimaux NTIA (70 %) et
/// empreintes/licences (30 %).
class QualityReport {
  final List<QualityItem> items;

  const QualityReport(this.items);

  static const _ntiaWeight = 0.7;

  double _mean(Iterable<QualityItem> it) => it.isEmpty
      ? 0
      : it.map((i) => i.score).reduce((a, b) => a + b) / it.length;

  /// Note sur 100, arrondie.
  int get score => (100 *
          (_ntiaWeight * _mean(items.where((i) => i.ntia)) +
              (1 - _ntiaWeight) * _mean(items.where((i) => !i.ntia))))
      .round();

  String get grade => switch (score) {
        >= 90 => 'A',
        >= 75 => 'B',
        >= 60 => 'C',
        >= 40 => 'D',
        _ => 'E',
      };

  Map<String, dynamic> toJson() => {
        'score': score,
        'grade': grade,
        'criteria': [
          for (final i in items)
            {
              'id': i.id,
              'ntia': i.ntia,
              'score': double.parse(i.score.toStringAsFixed(3)),
              if (i.offenders.isNotEmpty) 'components': i.offenders,
            },
        ],
      };

  String toText() {
    final b = StringBuffer()
      ..writeln(tr('Qualité du SBOM : {score}/100 (note {grade})',
          {'score': score, 'grade': grade}))
      ..writeln();
    for (final i in items) {
      final pct = (i.score * 100).round().toString().padLeft(3);
      b.writeln('  $pct %  ${i.ntia ? 'NTIA ' : '     '} ${i.label}');
      if (i.offenders.isNotEmpty) {
        b.writeln('            ' +
            tr('manquant sur : {list}', {'list': i.offenders.join(', ')}));
      }
    }
    return b.toString();
  }
}

/// Évalue [sbom] avec les contrôles de [CraReportGenerator] (même logique que
/// l'onglet NTIA du rapport CRA, pour que les deux notes ne divergent pas).
QualityReport assessQuality(String path, Map<String, dynamic> sbom) {
  final gen =
      CraReportGenerator(sbomPath: path, sbom: sbom, meta: const CraMetadata());
  final fields = {for (final f in gen.fieldChecks) f.id: f};
  const fieldOfNtia = {
    'supplierName': 'supplier',
    'componentName': 'name',
    'componentVersion': 'version',
    'otherUniqueIdentifiers': 'identifier',
  };
  final items = <QualityItem>[];
  for (final (id, label, status) in gen.ntiaById) {
    final f = fields[fieldOfNtia[id]];
    items.add(QualityItem(
      id,
      label,
      f != null ? f.ratio : (status == CraStatus.ok ? 1 : 0),
      ntia: true,
      offenders: f?.offenders ?? const [],
    ));
  }
  for (final id in const ['hash', 'license']) {
    final f = fields[id];
    if (f == null) continue;
    items.add(
        QualityItem(id, f.label, f.ratio, ntia: false, offenders: f.offenders));
  }
  return QualityReport(items);
}
