/// Curated snapshot of the SPDX License List identifiers (licenses + common
/// license-exception ids), used by [LicenseNormalizer] to decide whether a
/// single license token may be emitted as a CycloneDX `license.id` / bare
/// SPDX expression term, or must be demoted to `license.name` /
/// `LicenseRef-…`.
///
/// Case-sensitive, exact match (SPDX ids are case-sensitive). A token missing
/// from this set degrades gracefully to `name` / `LicenseRef-…` — still
/// schema-valid, just reported as free text — so it is safe to be
/// conservative here. Kept deliberately broad for the families that actually
/// surface from RPM `License:` tags, Debian `debian/copyright` (DEP-5) and
/// PyPI/npm classifiers; not an exhaustive mirror of every historical id.
///
/// Source: https://spdx.org/licenses/ (SPDX License List 3.x).
library;

/// Valid SPDX *license* identifiers (the `id` position of an expression).
const Set<String> kSpdxLicenseIds = {
  // GNU family
  'GPL-1.0-only', 'GPL-1.0-or-later',
  'GPL-2.0-only', 'GPL-2.0-or-later',
  'GPL-3.0-only', 'GPL-3.0-or-later',
  'LGPL-2.0-only', 'LGPL-2.0-or-later',
  'LGPL-2.1-only', 'LGPL-2.1-or-later',
  'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'AGPL-1.0-only', 'AGPL-1.0-or-later',
  'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'GFDL-1.1-only', 'GFDL-1.1-or-later',
  'GFDL-1.1-invariants-only', 'GFDL-1.1-invariants-or-later',
  'GFDL-1.1-no-invariants-only', 'GFDL-1.1-no-invariants-or-later',
  'GFDL-1.2-only', 'GFDL-1.2-or-later',
  'GFDL-1.2-invariants-only', 'GFDL-1.2-invariants-or-later',
  'GFDL-1.2-no-invariants-only', 'GFDL-1.2-no-invariants-or-later',
  'GFDL-1.3-only', 'GFDL-1.3-or-later',
  'GFDL-1.3-invariants-only', 'GFDL-1.3-invariants-or-later',
  'GFDL-1.3-no-invariants-only', 'GFDL-1.3-no-invariants-or-later',
  'LGPLLR',
  'FSFAP', 'FSFUL', 'FSFULLR', 'FSFULLRWD',

  // MIT / X11
  'MIT', 'MIT-0', 'MIT-advertising', 'MIT-CMU', 'MIT-enna', 'MIT-feh',
  'MIT-Modern-Variant', 'MIT-open-group', 'MIT-testregex', 'MIT-Wu', 'MITNFA',
  'X11', 'X11-distribute-modifications-variant',

  // ISC / BSD family
  'ISC', 'ISC-Veillard',
  '0BSD', 'BSD-1-Clause',
  'BSD-2-Clause', 'BSD-2-Clause-Patent', 'BSD-2-Clause-Views',
  'BSD-2-Clause-FreeBSD', 'BSD-2-Clause-NetBSD', 'BSD-2-Clause-first-lines',
  'BSD-3-Clause', 'BSD-3-Clause-Attribution', 'BSD-3-Clause-Clear',
  'BSD-3-Clause-LBNL', 'BSD-3-Clause-Modification',
  'BSD-3-Clause-No-Military-License', 'BSD-3-Clause-No-Nuclear-License',
  'BSD-3-Clause-No-Nuclear-License-2014', 'BSD-3-Clause-No-Nuclear-Warranty',
  'BSD-3-Clause-Open-MPI', 'BSD-3-Clause-flex', 'BSD-3-Clause-HP',
  'BSD-3-Clause-Sun', 'BSD-3-Clause-acpica',
  'BSD-4-Clause', 'BSD-4-Clause-UC', 'BSD-4-Clause-Shortened',
  'BSD-4.3RENO', 'BSD-4.3TAHOE',
  'BSD-Advertising-Acknowledgement', 'BSD-Attribution-HPND-disclaimer',
  'BSD-Source-Code', 'BSD-Protection', 'BSD-Systemics', 'BSD-Systemics-W3Works',
  'BSD-Inferno-Nettverk',

  // Apache / zlib / Boost
  'Apache-1.0', 'Apache-1.1', 'Apache-2.0',
  'Zlib', 'zlib-acknowledgement', 'Libpng', 'libpng-2.0', 'libtiff',
  'libselinux-1.0',
  'BSL-1.0', 'Beerware', 'bzip2-1.0.5', 'bzip2-1.0.6', 'blessing',
  // NOTE: SPDX id `curl` is intentionally omitted — Debian `debian/copyright`
  // uses "curl" as a vague short name, so [LicenseNormalizer] keeps it as
  // free text (`name` / `LicenseRef-curl`) rather than claiming it as `id`.

  // HPND / permissive
  'HPND', 'HPND-sell-variant', 'HPND-Markus-Kuhn',
  'HPND-sell-variant-MIT-disclaimer', 'HPND-DEC', 'HPND-doc', 'HPND-doc-sell',
  'HPND-export-US', 'HPND-export-US-modify', 'HPND-Fenneberg-Livingston',
  'HPND-INRIA-IMAG', 'HPND-Kevlin-Henney', 'HPND-MIT-disclaimer',
  'HPND-Pbmplus', 'HPND-sell-MIT-disclaimer-xserver', 'HPND-sell-regexpr',
  'HPND-UC', 'HPND-Netrek',
  'NTP', 'NTP-0',
  'Xerox', 'Adobe-2006', 'Adobe-Glyph', 'APAFML',
  'Unicode-DFS-2015', 'Unicode-DFS-2016', 'Unicode-TOU', 'Unicode-3.0',
  'TCL', 'TCP-wrappers',
  'Spencer-86', 'Spencer-94', 'Spencer-99',
  'Sleepycat',
  'SMLNJ', 'SGI-B-1.0', 'SGI-B-1.1', 'SGI-B-2.0', 'SGI-OpenGL', 'SunPro',
  'W3C', 'W3C-19980720', 'W3C-20150513',
  'Info-ZIP', 'IJG', 'IJG-short',
  'Naumen', 'NCSA', 'Net-SNMP', 'NetCDF', 'Newsletr',
  'OpenSSL', 'OpenSSL-standalone', 'SSLeay-standalone',
  'PostgreSQL', 'Python-2.0', 'Python-2.0.1', 'PSF-2.0',
  'Ruby', 'Ruby-pty',
  'Xnet', 'xinetd', 'xlock', 'xpp', 'Zed', 'Zend-2.0',
  'FreeBSD-DOC', 'ICU', 'NAIST-2003',
  'Latex2e', 'Latex2e-translated-notice',
  'Linux-man-pages-1-para', 'Linux-man-pages-copyleft',
  'Linux-man-pages-copyleft-2-para', 'Linux-man-pages-copyleft-var',
  'Linux-OpenIB',
  'checkmk', 'copyleft-next-0.3.0', 'copyleft-next-0.3.1',
  'DL-DE-BY-2.0', 'DL-DE-ZERO-2.0',
  'eGenix', 'FBM', 'fwlw', 'Graphics-Gems', 'gtkbook', 'HTMLTIDY',
  'IEC-Code-Components-EULA', 'Kazlib', 'Martin-Birgmeier', 'metamail',
  'mpi-permissive', 'mpich2', 'NICTA-1.0', 'NLOD-1.0', 'NLOD-2.0', 'NLPL',
  'pnmstitch', 'psfrag', 'psutils', 'snprintf', 'swrule', 'ulem',
  'Widget-Workshop', 'xkeyboard-config-Zinoviev', 'w3m', 'mplus',

  // Copyleft (non-GNU)
  'MPL-1.0', 'MPL-1.1', 'MPL-2.0', 'MPL-2.0-no-copyleft-exception',
  'CDDL-1.0', 'CDDL-1.1',
  'CPL-1.0', 'CPAL-1.0',
  'EPL-1.0', 'EPL-2.0',
  'EUPL-1.0', 'EUPL-1.1', 'EUPL-1.2',
  'CECILL-1.0', 'CECILL-1.1', 'CECILL-2.0', 'CECILL-2.1',
  'CECILL-B', 'CECILL-C',
  'Artistic-1.0', 'Artistic-1.0-Perl', 'Artistic-1.0-cl8', 'Artistic-2.0',
  'ClArtistic',
  'QPL-1.0', 'QPL-1.0-INRIA-2004',
  'OSL-1.0', 'OSL-1.1', 'OSL-2.0', 'OSL-2.1', 'OSL-3.0',
  'AFL-1.1', 'AFL-1.2', 'AFL-2.0', 'AFL-2.1', 'AFL-3.0',
  'APSL-1.0', 'APSL-1.1', 'APSL-1.2', 'APSL-2.0',
  'NPL-1.0', 'NPL-1.1',
  'Nokia', 'Motosoto', 'MirOS', 'Sendmail', 'Sendmail-8.23',
  'RPL-1.1', 'RPL-1.5', 'RPSL-1.0',
  'SISSL', 'SISSL-1.2', 'SPL-1.0', 'Watcom-1.0', 'VSL-1.0', 'Xdebug-1.03',
  'gSOAP-1.3b', 'Frameworx-1.0', 'Fair', 'Entessa',
  'IPL-1.0', 'IPA', 'Interbase-1.0',
  'LPPL-1.0', 'LPPL-1.1', 'LPPL-1.2', 'LPPL-1.3a', 'LPPL-1.3c',
  'LiLiQ-P-1.1', 'LiLiQ-R-1.1', 'LiLiQ-Rplus-1.1',
  'MS-PL', 'MS-RL', 'MS-LPL',
  'NASA-1.3', 'NBPL-1.0', 'NGPL', 'NOSL', 'NPOSL-3.0', 'NRL',
  'OGTSL', 'OLDAP-1.1', 'OLDAP-2.0', 'OLDAP-2.7', 'OLDAP-2.8',
  'OGL-Canada-2.0', 'OGL-UK-1.0', 'OGL-UK-2.0', 'OGL-UK-3.0',
  'OFL-1.0', 'OFL-1.0-RFN', 'OFL-1.0-no-RFN',
  'OFL-1.1', 'OFL-1.1-RFN', 'OFL-1.1-no-RFN',
  'SSPL-1.0', 'BUSL-1.1', 'Elastic-2.0',
  'CAL-1.0', 'CAL-1.0-Combined-Work-Exception',
  'Parity-6.0.0', 'Parity-7.0.0', 'Sustainable-Use-1.0',
  'PolyForm-Noncommercial-1.0.0', 'PolyForm-Small-Business-1.0.0',
  'UPL-1.0', 'Unlicense', 'WTFPL', 'CC0-1.0',
  'Vim', 'VOSTROM',
  'ZPL-1.1', 'ZPL-2.0', 'ZPL-2.1', 'Zimbra-1.3', 'Zimbra-1.4',

  // Creative Commons
  'CC-BY-1.0', 'CC-BY-2.0', 'CC-BY-2.5', 'CC-BY-2.5-AU', 'CC-BY-3.0',
  'CC-BY-3.0-AT', 'CC-BY-3.0-AU', 'CC-BY-3.0-DE', 'CC-BY-3.0-IGO',
  'CC-BY-3.0-NL', 'CC-BY-3.0-US', 'CC-BY-4.0',
  'CC-BY-SA-1.0', 'CC-BY-SA-2.0', 'CC-BY-SA-2.0-UK', 'CC-BY-SA-2.1-JP',
  'CC-BY-SA-2.5', 'CC-BY-SA-3.0', 'CC-BY-SA-3.0-AT', 'CC-BY-SA-3.0-DE',
  'CC-BY-SA-3.0-IGO', 'CC-BY-SA-4.0',
  'CC-BY-NC-1.0', 'CC-BY-NC-2.0', 'CC-BY-NC-2.5', 'CC-BY-NC-3.0',
  'CC-BY-NC-3.0-DE', 'CC-BY-NC-4.0',
  'CC-BY-NC-SA-1.0', 'CC-BY-NC-SA-2.0', 'CC-BY-NC-SA-2.0-DE',
  'CC-BY-NC-SA-2.0-FR', 'CC-BY-NC-SA-2.0-UK', 'CC-BY-NC-SA-2.5',
  'CC-BY-NC-SA-3.0', 'CC-BY-NC-SA-3.0-DE', 'CC-BY-NC-SA-3.0-IGO',
  'CC-BY-NC-SA-4.0',
  'CC-BY-ND-1.0', 'CC-BY-ND-2.0', 'CC-BY-ND-2.5', 'CC-BY-ND-3.0',
  'CC-BY-ND-3.0-DE', 'CC-BY-ND-4.0',
  'CC-BY-NC-ND-1.0', 'CC-BY-NC-ND-2.0', 'CC-BY-NC-ND-2.5',
  'CC-BY-NC-ND-3.0', 'CC-BY-NC-ND-3.0-DE', 'CC-BY-NC-ND-3.0-IGO',
  'CC-BY-NC-ND-4.0',
  'CC-PDDC', 'CC-SA-1.0',

  // Misc / public-domain-ish
  'CNRI-Jython', 'CNRI-Python', 'CNRI-Python-GPL-Compatible',
  'D-FSL-1.0', 'diffmark', 'DOC', 'Dotseqn', 'DRL-1.0', 'DRL-1.1',
  'DSDP', 'dvipdfm', 'ECL-1.0', 'ECL-2.0', 'EFL-1.0', 'EFL-2.0',
  'eCos-2.0', 'EPICS', 'Eurosym',
  'GD', 'Giftware', 'Glide', 'Glulxe', 'GLWTPL',
  'iMatix', 'Imlib2', 'Intel', 'Intel-ACPI', 'JasPer-2.0',
  'JSON', 'Knuth-CTAN', 'LAL-1.2', 'LAL-1.3', 'Leptonica',
  'LPL-1.0', 'LPL-1.02', 'MakeIndex', 'Mup',
  'OGC-1.0', 'OML', 'OPUBL-1.0', 'PDDL-1.0', 'Plexus',
  'Rdisc', 'RSA-MD', 'RSCPL', 'Saxpath', 'SCEA',
  'SchemeReport', 'SGP4', 'SHL-0.5', 'SHL-0.51',
  'SimPL-2.0', 'SNIA', 'SWL', 'TAPR-OHL-1.0', 'TOSL',
  'TU-Berlin-1.0', 'TU-Berlin-2.0', 'UCL-1.0',
  'Wsuipa', 'YPL-1.0', 'YPL-1.1', 'Zeeff',
  'NIST-PD', 'NIST-PD-fallback', 'NIST-Software',
};

/// Valid SPDX *license-exception* identifiers (the `WITH` operand).
const Set<String> kSpdxExceptionIds = {
  '389-exception',
  'Asterisk-exception', 'Autoconf-exception-2.0', 'Autoconf-exception-3.0',
  'Autoconf-exception-generic', 'Autoconf-exception-generic-3.0',
  'Autoconf-exception-macro',
  'Bison-exception-1.24', 'Bison-exception-2.2',
  'Bootloader-exception',
  'Classpath-exception-2.0', 'CLISP-exception-2.0',
  'cryptsetup-OpenSSL-exception',
  'DigiRule-FOSS-exception', 'eCos-exception-2.0',
  'Fawkes-Runtime-exception', 'FLTK-exception',
  'Font-exception-2.0', 'freertos-exception-2.0',
  'GCC-exception-2.0', 'GCC-exception-2.0-note', 'GCC-exception-3.1',
  'Gmsh-exception', 'GNAT-exception', 'GNOME-examples-exception',
  'GNU-compiler-exception', 'gnu-javamail-exception',
  'GPL-3.0-interface-exception', 'GPL-3.0-linking-exception',
  'GPL-3.0-linking-source-exception', 'GPL-CC-1.0',
  'GStreamer-exception-2005', 'GStreamer-exception-2008',
  'i2p-gpl-java-exception', 'KiCad-libraries-exception',
  'LGPL-3.0-linking-exception', 'libpri-OpenH323-exception',
  'Libtool-exception', 'Linux-syscall-note', 'LLGL-exception',
  'LLVM-exception', 'LZMA-exception',
  'mif-exception', 'OCaml-LGPL-linking-exception',
  'OCCT-exception-1.0', 'OpenJDK-assembly-exception-1.0',
  'openvpn-openssl-exception', 'PS-or-PDF-font-exception-20170817',
  'QPL-1.0-INRIA-2004-exception', 'Qt-GPL-exception-1.0',
  'Qt-LGPL-exception-1.1', 'Qwt-exception-1.0',
  'SANE-exception', 'SHL-2.0', 'SHL-2.1', 'stunnel-exception',
  'SWI-exception', 'Swift-exception', 'Texinfo-exception',
  'u-boot-exception-2.0', 'UBDL-exception', 'Universal-FOSS-exception-1.0',
  'vsftpd-openssl-exception', 'WxWindows-exception-3.1',
  'x11vnc-openssl-exception',
};

/// True when [id] is a real SPDX license identifier (case-sensitive). A
/// trailing `+` (deprecated "or later" shorthand still seen in RPM `License:`
/// tags) is accepted when the base id is known.
bool isSpdxLicenseId(String id) {
  if (kSpdxLicenseIds.contains(id)) return true;
  if (id.endsWith('+') &&
      kSpdxLicenseIds.contains(id.substring(0, id.length - 1))) {
    return true;
  }
  return false;
}

/// True when [id] is a real SPDX license-exception identifier.
bool isSpdxExceptionId(String id) => kSpdxExceptionIds.contains(id);
