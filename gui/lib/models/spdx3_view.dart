/// Lecture d'un graphe SPDX 3.0 JSON-LD sous une forme interne normalisée.
///
/// Le schéma officiel (types `software_Package`, licences portées par des
/// relations `hasDeclaredLicense`, annotations en éléments distincts…) est
/// éloigné de ce dont les consommateurs (diff, CRA, GUI…) ont besoin. Plutôt
/// que de dupliquer cette logique, [spdx3Packages] renvoie pour chaque paquet
/// une copie du nœud enrichie de clés plates : `software:packageVersion`,
/// `software:downloadLocation`, `concludedLicense`, `declaredLicense`,
/// `annotation` (liste de `{statement}`) et un `externalIdentifier` dont le
/// type d'URL de paquet est ramené à `purl`.
///
/// Les fichiers produits par les versions ≤ 1.10.x (type `software:Package`,
/// licences et annotations en ligne) restent lus.
///
/// NB : la GUI embarque une copie de ce fichier (`gui/lib/models/spdx3_view.dart`),
/// car elle ne dépend pas du paquet de la CLI — garder les deux identiques.
library;

/// Vrai si [type] désigne un paquet logiciel SPDX 3.0 (forme officielle
/// `software_Package`, ancienne forme `software:Package`, ou liste de types).
bool isSpdx3PackageType(Object? type) {
  bool match(Object? t) => t == 'software_Package' || t == 'software:Package';
  return type is List ? type.any(match) : match(type);
}

/// Valeur d'une propriété du profil `software` d'un nœud : forme officielle
/// `software_<local>`, ancienne forme `software:<local>`, ou nom nu.
Object? spdx3Prop(Map node, String local) =>
    node['software_$local'] ?? node['software:$local'] ?? node[local];

/// Paquets du graphe `@graph`, normalisés (voir l'en-tête du fichier).
List<Map<String, dynamic>> spdx3Packages(List graph) {
  final nodes = graph.whereType<Map>().map((e) => e.cast<String, dynamic>());

  String? idOf(Map n) => (n['spdxId'] ?? n['@id']) as String?;

  final expressions = <String, String>{};
  for (final n in nodes) {
    if (n['type'] != 'simplelicensing_LicenseExpression') continue;
    final id = idOf(n);
    final expr = n['simplelicensing_licenseExpression'] as String?;
    if (id != null && expr != null) expressions[id] = expr;
  }

  // Licences : relations `hasConcludedLicense` / `hasDeclaredLicense`.
  final licenses = <String, Map<String, String>>{};
  for (final n in nodes) {
    if (n['type'] != 'Relationship') continue;
    final kind = n['relationshipType'];
    if (kind != 'hasConcludedLicense' && kind != 'hasDeclaredLicense') continue;
    final from = n['from'] as String?;
    if (from == null) continue;
    for (final to in (n['to'] as List? ?? const [])) {
      final expr = expressions['$to'];
      if (expr == null) continue;
      licenses.putIfAbsent(from, () => {})['$kind'] = expr;
    }
  }

  // Annotations : éléments `Annotation` référençant leur paquet par `subject`.
  final annotations = <String, List<Map<String, dynamic>>>{};
  for (final n in nodes) {
    if (n['type'] != 'Annotation') continue;
    final subject = n['subject'] as String?;
    if (subject == null) continue;
    annotations.putIfAbsent(subject, () => []).add({
      'statement': n['statement'],
      'annotationType': n['annotationType'],
      'subject': subject,
    });
  }

  final out = <Map<String, dynamic>>[];
  for (final n in nodes) {
    if (!isSpdx3PackageType(n['type'])) continue;
    final id = idOf(n);
    final copy = Map<String, dynamic>.of(n);

    for (final local in const ['packageVersion', 'downloadLocation']) {
      final v = spdx3Prop(n, local);
      if (v != null) copy['software:$local'] = v;
    }

    final lic = licenses[id];
    if (lic != null) {
      copy['concludedLicense'] ??= lic['hasConcludedLicense'];
      copy['declaredLicense'] ??= lic['hasDeclaredLicense'];
    }

    final notes = <Object?>[
      ...(n['annotation'] as List? ?? const []),
      ...(annotations[id] ?? const []),
    ];
    if (notes.isNotEmpty) copy['annotation'] = notes;

    final ids = <Map<String, dynamic>>[
      for (final e in (n['externalIdentifier'] as List? ?? const []))
        if (e is Map)
          {
            ...e.cast<String, dynamic>(),
            if (e['externalIdentifierType'] == 'packageUrl')
              'externalIdentifierType': 'purl',
          },
    ];
    final purl = spdx3Prop(n, 'packageUrl');
    if (purl is String &&
        !ids.any((e) => e['externalIdentifierType'] == 'purl')) {
      ids.add({'externalIdentifierType': 'purl', 'identifier': purl});
    }
    if (ids.isNotEmpty) copy['externalIdentifier'] = ids;

    out.add(copy);
  }
  return out;
}
