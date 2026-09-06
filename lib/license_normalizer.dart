import 'spdx_license_ids.dart';

/// Shared license normalisation for all SBOM generators.
///
/// Converts raw RPM / Debian (`debian/copyright`, DEP-5) / Python license
/// strings to SPDX identifiers.
/// Output forms:
///   • [toSpdxExpression] — plain SPDX expression string (for SPDX 2.3 / 3.0),
///     with any term not recognised as a real SPDX license/exception id
///     escaped to a valid `LicenseRef-…` so the whole expression stays
///     syntactically valid even for Debian-specific short names (e.g.
///     `curl`, `permissive`, `public-domain`) that aren't SPDX-listed.
///   • [toCycloneDxLicenses] — CycloneDX `licenses` list JSON structure,
///     a single *declared* entry mirroring the raw package license as-is.
///   • [toCycloneDxLicensesConcluded] — same, but split into a *declared*
///     entry (raw license, untouched) plus one or more *concluded* entries
///     (this tool's SPDX-normalised determination), tagged via the
///     CycloneDX 1.5+ `license.acknowledgement` field. Used wherever a
///     consumer benefits from telling "what the package claims" apart from
///     "what we determined after normalisation" (e.g. SBOM quality scoring
///     tools such as sbomqs).
class LicenseNormalizer {
  // ── RPM/Debian → SPDX mapping table ─────────────────────────────────────────

  static const Map<String, String> _rpmToSpdx = {
    // GPL family — RPM (GPLv2, GPL-2.0) and Debian DEP-5 (GPL-2, GPL-2+)
    // conventions both map here.
    'GPL': 'GPL-2.0-only',
    'GPL+': 'GPL-2.0-or-later',
    'GPL-1': 'GPL-1.0-only',
    'GPL-1+': 'GPL-1.0-or-later',
    'GPL-2': 'GPL-2.0-only',
    'GPL-2+': 'GPL-2.0-or-later',
    'GPL-2.0': 'GPL-2.0-only',
    'GPL-2.0+': 'GPL-2.0-or-later',
    'GPLv2': 'GPL-2.0-only',
    'GPLv2+': 'GPL-2.0-or-later',
    'GPL-3': 'GPL-3.0-only',
    'GPL-3+': 'GPL-3.0-or-later',
    'GPL-3.0': 'GPL-3.0-only',
    'GPL-3.0+': 'GPL-3.0-or-later',
    'GPLv3': 'GPL-3.0-only',
    'GPLv3+': 'GPL-3.0-or-later',
    // LGPL family
    'LGPL': 'LGPL-2.0-only',
    'LGPL+': 'LGPL-2.0-or-later',
    'LGPLv2': 'LGPL-2.0-only',
    'LGPLv2+': 'LGPL-2.0-or-later',
    'LGPL-2': 'LGPL-2.0-only',
    'LGPL-2+': 'LGPL-2.0-or-later',
    'LGPL-2.0': 'LGPL-2.0-only',
    'LGPL-2.0+': 'LGPL-2.0-or-later',
    'LGPLv2.1': 'LGPL-2.1-only',
    'LGPLv2.1+': 'LGPL-2.1-or-later',
    'LGPL-2.1': 'LGPL-2.1-only',
    'LGPL-2.1+': 'LGPL-2.1-or-later',
    'LGPLv3': 'LGPL-3.0-only',
    'LGPLv3+': 'LGPL-3.0-or-later',
    'LGPL-3': 'LGPL-3.0-only',
    'LGPL-3+': 'LGPL-3.0-or-later',
    'LGPL-3.0': 'LGPL-3.0-only',
    'LGPL-3.0+': 'LGPL-3.0-or-later',
    // Apache / MIT ("Expat" is Debian's DEP-5 canonical name for MIT) / BSD
    'ASL 1.1': 'Apache-1.1',
    'ASL 2.0': 'Apache-2.0',
    'Expat': 'MIT',
    'ASL2.0': 'Apache-2.0',
    'Apache 2.0': 'Apache-2.0',
    'Apache-2.0': 'Apache-2.0',
    'Apache Software License': 'Apache-2.0',
    'MIT': 'MIT',
    'MIT License': 'MIT',
    'MIT-0': 'MIT-0',
    'ISC': 'ISC',
    'BSD': 'BSD-2-Clause',
    'BSD License': 'BSD-2-Clause',
    'BSD 2-Clause': 'BSD-2-Clause',
    'BSD-2-Clause': 'BSD-2-Clause',
    'BSD-2-clause': 'BSD-2-Clause',
    'BSD 3-Clause': 'BSD-3-Clause',
    'BSD-3-Clause': 'BSD-3-Clause',
    'BSD-3-clause': 'BSD-3-Clause',
    'BSD 4-Clause': 'BSD-4-Clause',
    'BSD-4-clause': 'BSD-4-Clause',
    // GFDL (documentation Debian/GNU)
    'GFDL-1.2': 'GFDL-1.2-only',
    'GFDL-1.2+': 'GFDL-1.2-or-later',
    'GFDL-1.3': 'GFDL-1.3-only',
    'GFDL-1.3+': 'GFDL-1.3-or-later',
    // Mozilla
    'MPLv1.1': 'MPL-1.1',
    'MPL-1.1': 'MPL-1.1',
    'MPLv2.0': 'MPL-2.0',
    'MPL-2.0': 'MPL-2.0',
    'MPL': 'MPL-2.0',
    // CDDL / CPL / EPL
    'CDDL': 'CDDL-1.0',
    'CDDLv1.0': 'CDDL-1.0',
    'CDDL-1.0': 'CDDL-1.0',
    'CPL': 'CPL-1.0',
    'CPL-1.0': 'CPL-1.0',
    'EPLv1.0': 'EPL-1.0',
    'EPL-1.0': 'EPL-1.0',
    'EPLv2.0': 'EPL-2.0',
    'EPL-2.0': 'EPL-2.0',
    // Artistic / Perl
    'Artistic': 'Artistic-1.0',
    'Artistic-1.0': 'Artistic-1.0',
    'Artistic 2.0': 'Artistic-2.0',
    'Artistic-2.0': 'Artistic-2.0',
    'Perl': 'Artistic-1.0',
    // Python / Ruby / others
    'Python': 'Python-2.0',
    'Python-2.0': 'Python-2.0',
    'Ruby': 'Ruby',
    'WTFPL': 'WTFPL',
    'Unlicense': 'Unlicense',
    'CC0': 'CC0-1.0',
    'CC0-1.0': 'CC0-1.0',
    'CC BY 4.0': 'CC-BY-4.0',
    'OFL': 'OFL-1.1',
    'OFL-1.1': 'OFL-1.1',
    'SIL OFL 1.1': 'OFL-1.1',
    'ZPLv2.0': 'ZPL-2.0',
    'ZPL-2.0': 'ZPL-2.0',
    'EUPL 1.1': 'EUPL-1.1',
    'EUPL-1.1': 'EUPL-1.1',
    'EUPL 1.2': 'EUPL-1.2',
    'EUPL-1.2': 'EUPL-1.2',
    'FTL': 'FTL',
    'FSFUL': 'LicenseRef-FSFUL',
    'FSFAP': 'FSFAP',
    'HPND': 'HPND',
    'NLPL': 'NLPL',
    'OpenLDAP': 'OLDAP-2.8',
    'Sleepycat': 'Sleepycat',
    'Boost': 'BSL-1.0',
    'zlib': 'Zlib',
    'Zlib': 'Zlib',
    'Public Domain': 'LicenseRef-PublicDomain',
    'PublicDomain': 'LicenseRef-PublicDomain',
    'public domain': 'LicenseRef-PublicDomain',
    'public-domain': 'LicenseRef-PublicDomain',
  };

  // Sorted longest-first for correct token replacement in compound expressions.
  static final List<MapEntry<String, String>> _sortedEntries =
      _rpmToSpdx.entries.toList()
        ..sort((a, b) => b.key.length.compareTo(a.key.length));

  // ── Public API ─────────────────────────────────────────────────────────────

  /// Returns a normalised SPDX expression string.
  ///
  /// Returns an empty string for empty / `(none)` input.
  /// Falls back to the raw string for unrecognised single-token licenses —
  /// escaped to `LicenseRef-…` when it doesn't look like a real SPDX id, so
  /// the result always parses as a syntactically valid SPDX expression.
  static String toSpdxExpression(String rawLicense) {
    final s = rawLicense.trim();
    if (s.isEmpty || s == '(none)') return '';

    final normalised = _normaliseOperators(s);
    if (_isCompound(normalised)) {
      return _escapeUnknownTerms(_normaliseExpressionTokens(normalised));
    }

    return _escapeUnknownTerms(_rpmToSpdx[s] ?? s);
  }

  /// Returns a CycloneDX-compatible `licenses` list.
  ///
  /// Produces `[{"expression": "…"}]` for compound expressions,
  /// `[{"license": {"id": "…"}}]` for known SPDX identifiers, and
  /// `[{"license": {"name": "…"}}]` for unrecognised or LicenseRef-* values.
  static List<Map<String, dynamic>> toCycloneDxLicenses(String rawLicense) {
    final s = rawLicense.trim();
    if (s.isEmpty || s == '(none)') return [];

    final normalised = _normaliseOperators(s);
    if (_isCompound(normalised)) {
      return [
        {'expression': _normaliseExpressionTokens(normalised)}
      ];
    }

    final mapped = _rpmToSpdx[s] ?? s;

    if (_isSpdxLicenseId(mapped)) {
      return [
        {
          'license': {'id': mapped}
        }
      ];
    }

    return [
      {
        'license': {'name': s}
      }
    ];
  }

  /// Returns a CycloneDX `licenses` list distinguishing the raw license *as
  /// declared* by the package from this tool's SPDX-normalised *concluded*
  /// determination, via the CycloneDX 1.5+ `license.acknowledgement` field.
  ///
  /// For a pure AND-compound license (several licenses combined — the
  /// common case for Debian packages, whose `debian/copyright` typically
  /// lists one license per file/section), each individual license is
  /// listed as its own `concluded` entry so it can be checked against the
  /// SPDX list on its own. CycloneDX's single-item `expression` form
  /// doesn't allow mixing a `declared` and a `concluded` entry in the same
  /// `licenses` array (schema: at most one item when using `expression`),
  /// so OR/WITH expressions (alternative licensing / an exception applied
  /// to one license — splitting would misrepresent the choice) keep the
  /// existing single-expression form from [toCycloneDxLicenses] untouched.
  static List<Map<String, dynamic>> toCycloneDxLicensesConcluded(
      String rawLicense) {
    final s = rawLicense.trim();
    if (s.isEmpty || s == '(none)') return [];

    final normalised = _normaliseOperators(s);
    if (_isCompound(normalised)) {
      if (!_isPureAnd(normalised)) return toCycloneDxLicenses(rawLicense);

      final declared = <String, dynamic>{
        'license': {'name': s, 'acknowledgement': 'declared'}
      };
      final concluded = normalised.split(' AND ').map((tok) {
        final mapped = _normaliseExpressionTokens(tok.trim());
        // Only a term that is actually on the SPDX License List goes in
        // `id` (CycloneDX `license.id` is schema-constrained to that
        // enum) — an unmapped token (Debian's "curl", "permissive", or a
        // `debian/copyright` short name like "BSD-3-clause-Berkeley" /
        // "GFDL-NIV-1.3") is reported as free text via `name` instead, so
        // the document stays schema-valid.
        final key = _isSpdxLicenseId(mapped) ? 'id' : 'name';
        return <String, dynamic>{
          'license': {key: mapped, 'acknowledgement': 'concluded'}
        };
      });
      return [declared, ...concluded];
    }

    final base = toCycloneDxLicenses(rawLicense);
    if (base.isEmpty) return base;
    final declared = <String, dynamic>{
      'license': {'name': s, 'acknowledgement': 'declared'}
    };
    return [declared, _withAcknowledgement(base.first, 'concluded')];
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  static String _normaliseOperators(String s) => s
      .replaceAll(
          RegExp(r'(?<=\S)\s+and\s+(?=\S)', caseSensitive: false), ' AND ')
      .replaceAll(
          RegExp(r'(?<=\S)\s+or\s+(?=\S)', caseSensitive: false), ' OR ')
      .replaceAll(
          RegExp(r'(?<=\S)\s+with\s+(?=\S)', caseSensitive: false), ' WITH ');

  static bool _isCompound(String s) =>
      s.contains(' AND ') || s.contains(' OR ') || s.contains(' WITH ');

  static String _normaliseExpressionTokens(String expr) {
    var result = expr;
    for (final e in _sortedEntries) {
      final pattern = RegExp(
          '(?<![A-Za-z0-9._-])${RegExp.escape(e.key)}(?![A-Za-z0-9._-])');
      result = result.replaceAll(pattern, e.value);
    }
    return result.trim();
  }

  static bool _looksLikeSpdxId(String s) =>
      s.isNotEmpty &&
      !s.contains(' ') &&
      RegExp(r'^[A-Za-z0-9][A-Za-z0-9.+\-]+$').hasMatch(s);

  static bool _isPureAnd(String normalisedExpr) =>
      normalisedExpr.contains(' AND ') &&
      !normalisedExpr.contains(' OR ') &&
      !normalisedExpr.contains(' WITH ');

  static Map<String, dynamic> _withAcknowledgement(
      Map<String, dynamic> entry, String value) {
    if (entry.containsKey('license')) {
      return {
        'license': {
          ...entry['license'] as Map<String, dynamic>,
          'acknowledgement': value,
        }
      };
    }
    // `expression` entries carry `acknowledgement` as a sibling field.
    return {...entry, 'acknowledgement': value};
  }

  /// A term safe to emit as CycloneDX `license.id` (schema-constrained to the
  /// SPDX License List enum): a real SPDX license id, or a hand-verified
  /// mapping-table target. `LicenseRef-…` custom refs and unrecognised
  /// Debian/RPM short names are excluded — they belong in `license.name`.
  static bool _isSpdxLicenseId(String term) =>
      !term.startsWith('LicenseRef-') &&
      (isSpdxLicenseId(term) || _rpmToSpdx.containsValue(term));

  // A term counts as a real SPDX license/exception id — rather than a
  // Debian-specific short name (`curl`, `permissive`, `public-domain`,
  // `BSD-3-clause-Berkeley`…) — when it is on the SPDX License List, is a
  // hand-verified mapping-table target, or is already a `LicenseRef-…`
  // custom ref (valid as-is inside an SPDX expression). Anything else is
  // escaped so the SPDX expression stays syntactically valid.
  static bool _isTrustworthySpdxTerm(String term) =>
      term.startsWith('LicenseRef-') ||
      isSpdxLicenseId(term) ||
      isSpdxExceptionId(term) ||
      _rpmToSpdx.containsValue(term);

  /// Escapes every AND/OR-separated term of an SPDX expression that isn't a
  /// [_isTrustworthySpdxTerm] to a valid `LicenseRef-<slug>`, so the whole
  /// expression always parses per the SPDX license-expression grammar even
  /// when it embeds non-SPDX-listed Debian/RPM short names. A `WITH`
  /// exception clause is validated (and, if needed, escaped) as a whole,
  /// since an SPDX exception can't stand on its own as a license term.
  static String _escapeUnknownTerms(String expr) {
    if (expr.isEmpty) return expr;
    final ops = RegExp(r'\s+(AND|OR)\s+')
        .allMatches(expr)
        .map((m) => m.group(1)!)
        .toList();
    final terms = expr.split(RegExp(r'\s+(?:AND|OR)\s+'));

    final buf = StringBuffer(_escapeTerm(terms.first));
    for (var i = 0; i < ops.length; i++) {
      buf.write(' ${ops[i]} ${_escapeTerm(terms[i + 1])}');
    }
    return buf.toString();
  }

  static String _escapeTerm(String term) {
    final t = term.trim();
    final withMatch = RegExp(r'^(.+?)\s+WITH\s+(.+)$').firstMatch(t);
    if (withMatch != null) {
      final license = withMatch.group(1)!.trim();
      final exception = withMatch.group(2)!.trim();
      if (_isTrustworthySpdxTerm(license) &&
          (isSpdxExceptionId(exception) || _looksLikeSpdxId(exception))) {
        return t;
      }
      // Can't safely split a malformed WITH-clause — escape it whole.
      return 'LicenseRef-${_slug(t)}';
    }
    return _isTrustworthySpdxTerm(t) ? t : 'LicenseRef-${_slug(t)}';
  }

  static String _slug(String s) {
    final cleaned = s
        .replaceAll(RegExp(r'[^A-Za-z0-9.+\-]+'), '-')
        .replaceAll(RegExp(r'-+'), '-')
        .replaceAll(RegExp(r'^-|-$'), '');
    return cleaned.isEmpty ? 'Unknown' : cleaned;
  }
}
