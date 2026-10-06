import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../models/vex.dart';
import 'scan_enrichment.dart' show normalizeCveId;

/// Déclarations VEX de l'utilisateur : « cette CVE ne m'affecte pas ». Servent
/// à masquer des CVE du tableau de bord et s'exportent en OpenVEX / CycloneDX.
class VexController extends ChangeNotifier {
  final List<VexStatement> _statements = [];

  /// Rappel de persistance (appelé après chaque changement).
  final Future<void> Function(String json)? persist;

  VexController({this.persist});

  List<VexStatement> get statements => List.unmodifiable(_statements);
  bool get isEmpty => _statements.isEmpty;

  /// Charge l'état sérialisé par [encode] (ignore un contenu illisible).
  void restore(String? json) {
    if (json == null || json.isEmpty) return;
    try {
      _statements
        ..clear()
        ..addAll(parseVex(jsonDecode(json) as Map<String, dynamic>));
      notifyListeners();
    } catch (_) {}
  }

  String encode() => encodeVex(
    buildOpenVex(_statements, author: 'sbom-generator-gui', toolVersion: ''),
  );

  /// Déclaration qui s'applique à (CVE, paquet, version), la plus récente
  /// d'abord.
  VexStatement? find(String vulnId, String name, String version) {
    final id = normalizeCveId(vulnId).toUpperCase();
    for (final s in _statements.reversed) {
      if (normalizeCveId(s.vulnId).toUpperCase() == id &&
          s.appliesTo(name, version)) {
        return s;
      }
    }
    return null;
  }

  /// La CVE doit-elle être masquée pour ce paquet ?
  bool suppresses(String vulnId, String name, String version) =>
      find(vulnId, name, version)?.suppresses ?? false;

  /// Ajoute ou remplace la déclaration visant les mêmes CVE et produits.
  void set(VexStatement s) {
    _statements
      ..removeWhere(s.sameTarget)
      ..add(s);
    _changed();
  }

  void remove(VexStatement s) {
    _statements.remove(s);
    _changed();
  }

  /// Fusionne des déclarations importées (elles remplacent les existantes de
  /// même cible) ; retourne leur nombre.
  int merge(Iterable<VexStatement> imported) {
    var n = 0;
    for (final s in imported) {
      _statements.removeWhere(s.sameTarget);
      _statements.add(s);
      n++;
    }
    if (n > 0) _changed();
    return n;
  }

  void clear() {
    _statements.clear();
    _changed();
  }

  Map<String, dynamic> toOpenVex(String author, String version) =>
      buildOpenVex(_statements, author: author, toolVersion: version);

  Map<String, dynamic> toCycloneDx(String author, String version) =>
      buildCycloneDxVex(_statements, author: author, toolVersion: version);

  void _changed() {
    notifyListeners();
    persist?.call(encode());
  }
}

/// Filtre [vulns] : retire celles que le VEX déclare non affectées/corrigées.
List<T>? filterByVex<T>(
  List<T>? vulns,
  VexController? vex,
  ({String id, String name, String version}) Function(T) key,
) {
  if (vulns == null || vex == null || vex.isEmpty) return vulns;
  return [
    for (final v in vulns)
      if (!vex.suppresses(key(v).id, key(v).name, key(v).version)) v,
  ];
}
