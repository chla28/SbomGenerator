import 'dart:convert';
import 'dart:io';
import 'archive_helpers.dart';
import 'models.dart';
import 'wheel_parser.dart';

// ── Python extraction script ─────────────────────────────────────────────────
//
// Same structure as the tar extraction script but uses zipfile instead of
// tarfile. Wheels (.whl) are already handled by WheelParser — this parser
// targets generic .zip archives that are not wheels.
//
const _extractScript = r'''
import zipfile, sys, json

def is_license(path):
    name = path.split('/')[-1].upper()
    return (
        name in ('LICENSE','COPYING','LICENCE','LICENSE.TXT','COPYING.TXT',
                 'LICENSE.MD','COPYING.MD') or
        name.startswith('LICENSE-') or name.startswith('LICENSE.') or
        name.startswith('COPYING-') or name.startswith('COPYING.')
    )

try:
    z = zipfile.ZipFile(sys.argv[1])
    names = z.namelist()

    meta_name = (
        next((x for x in names if x.endswith('/METADATA') and '.dist-info' in x), None) or
        next((x for x in names if x.endswith('PKG-INFO')), None)
    )

    if meta_name:
        f = z.open(meta_name)
        text = f.read().decode('utf-8', errors='replace')
        print(json.dumps({'type': 'python', 'content': text}))
    else:
        lic_files = sorted(
            [x for x in names if x.count('/') <= 1 and is_license(x)],
            key=lambda x: (x.count('/'), len(x))
        )
        lic_content = ''
        lic_file = ''
        if lic_files:
            f = z.open(lic_files[0])
            lic_content = f.read(2048).decode('utf-8', errors='replace')
            lic_file = lic_files[0].split('/')[-1]
        print(json.dumps({'type': 'generic',
                          'licenseFile': lic_file, 'license': lic_content}))
except Exception as e:
    import sys as _sys
    print(json.dumps({'type': 'error', 'error': str(e)}), file=_sys.stderr)
    _sys.exit(1)
''';

/// Parses generic ZIP archives (.zip) that are not Python wheels.
///
/// Three outcomes mirror [TarParser]:
///   1. **Python sdist** (PKG-INFO / dist-info METADATA found) → `pkg:pypi/…`
///   2. **Generic archive** → name/version/arch from filename, license from
///      a LICENSE/COPYING file inside the ZIP. PURL `pkg:generic/…`
///
/// Requires `python3` (for zipfile extraction).
class ZipParser {
  final _wheelParser = WheelParser();

  Future<Package?> parseZipFile(String path) async {
    final result = await Process.run('python3', ['-c', _extractScript, path]);

    if (result.exitCode != 0) {
      stderr.writeln('Warning: cannot read archive "$path"');
      final err = result.stderr.toString().trim();
      if (err.isNotEmpty) stderr.writeln('  $err');
      return null;
    }

    final Map<String, dynamic> payload;
    try {
      payload =
          jsonDecode(result.stdout.toString().trim()) as Map<String, dynamic>;
    } catch (_) {
      stderr.writeln('Warning: unexpected output from python3 for "$path"');
      return null;
    }

    final type = payload['type'] as String? ?? 'error';

    if (type == 'python') {
      final content = payload['content'] as String? ?? '';
      if (content.isEmpty) {
        stderr.writeln('Warning: empty metadata for "$path"');
        return null;
      }
      return _wheelParser.parseMetadataText(path, content);
    }

    if (type == 'generic') {
      return buildGenericArchivePackage(
        path,
        licenseFile: payload['licenseFile'] as String? ?? '',
        licenseContent: payload['license'] as String? ?? '',
      );
    }

    stderr.writeln('Warning: extraction failed for "$path"');
    return null;
  }
}
