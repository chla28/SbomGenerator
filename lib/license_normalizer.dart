/// Shared license normalisation for all SBOM generators.
///
/// Converts raw RPM / Python license strings to SPDX identifiers.
/// Two output forms are provided:
///   • [toSpdxExpression] — plain SPDX expression string (for SPDX 2.3 / 3.0)
///   • [toCycloneDxLicenses] — CycloneDX `licenses` list JSON structure
class LicenseNormalizer {
  // ── RPM → SPDX mapping table ──────────────────────────────────────────────

  static const Map<String, String> _rpmToSpdx = {
    // GPL family
    'GPL': 'GPL-2.0-only',
    'GPL+': 'GPL-2.0-or-later',
    'GPL-2.0': 'GPL-2.0-only',
    'GPL-2.0+': 'GPL-2.0-or-later',
    'GPLv2': 'GPL-2.0-only',
    'GPLv2+': 'GPL-2.0-or-later',
    'GPL-3.0': 'GPL-3.0-only',
    'GPL-3.0+': 'GPL-3.0-or-later',
    'GPLv3': 'GPL-3.0-only',
    'GPLv3+': 'GPL-3.0-or-later',
    // LGPL family
    'LGPL': 'LGPL-2.0-only',
    'LGPLv2': 'LGPL-2.0-only',
    'LGPLv2+': 'LGPL-2.0-or-later',
    'LGPL-2.0': 'LGPL-2.0-only',
    'LGPL-2.0+': 'LGPL-2.0-or-later',
    'LGPLv2.1': 'LGPL-2.1-only',
    'LGPLv2.1+': 'LGPL-2.1-or-later',
    'LGPL-2.1': 'LGPL-2.1-only',
    'LGPL-2.1+': 'LGPL-2.1-or-later',
    'LGPLv3': 'LGPL-3.0-only',
    'LGPLv3+': 'LGPL-3.0-or-later',
    'LGPL-3.0': 'LGPL-3.0-only',
    'LGPL-3.0+': 'LGPL-3.0-or-later',
    // Apache / MIT / BSD
    'ASL 1.1': 'Apache-1.1',
    'ASL 2.0': 'Apache-2.0',
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
    'BSD 3-Clause': 'BSD-3-Clause',
    'BSD-3-Clause': 'BSD-3-Clause',
    'BSD 4-Clause': 'BSD-4-Clause',
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
  };

  // Sorted longest-first for correct token replacement in compound expressions.
  static final List<MapEntry<String, String>> _sortedEntries =
      _rpmToSpdx.entries.toList()
        ..sort((a, b) => b.key.length.compareTo(a.key.length));

  // ── Public API ─────────────────────────────────────────────────────────────

  /// Returns a normalised SPDX expression string.
  ///
  /// Returns an empty string for empty / `(none)` input.
  /// Falls back to the raw string for unrecognised single-token licenses.
  static String toSpdxExpression(String rawLicense) {
    final s = rawLicense.trim();
    if (s.isEmpty || s == '(none)') return '';

    final normalised = _normaliseOperators(s);
    if (_isCompound(normalised)) return _normaliseExpressionTokens(normalised);

    return _rpmToSpdx[s] ?? s;
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

    if (_looksLikeSpdxId(mapped)) {
      if (mapped.startsWith('LicenseRef-')) {
        return [
          {
            'license': {'name': s}
          }
        ];
      }
      final fromTable = _rpmToSpdx.containsKey(s);
      final isVersioned = mapped.contains(RegExp(r'-\d'));
      if (fromTable || isVersioned) {
        return [
          {
            'license': {'id': mapped}
          }
        ];
      }
    }

    return [
      {
        'license': {'name': s}
      }
    ];
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
}
