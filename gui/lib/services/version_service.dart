import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

// ─── Modèle ───────────────────────────────────────────────────────────────────

class ToolVersionInfo {
  final String? installed;  // ex. '0.87.0', null = non installé
  final String? latest;     // ex. '0.88.1', null = vérification échouée
  final String? releaseUrl; // URL de la page de release GitHub

  const ToolVersionInfo({
    this.installed,
    this.latest,
    this.releaseUrl,
  });

  bool get isInstalled => installed != null;

  bool get hasUpdate {
    if (installed == null || latest == null) return false;
    return _isNewer(latest!, installed!);
  }

  static bool _isNewer(String a, String b) {
    final pa = _parse(a);
    final pb = _parse(b);
    for (int i = 0; i < 3; i++) {
      final ia = i < pa.length ? pa[i] : 0;
      final ib = i < pb.length ? pb[i] : 0;
      if (ia != ib) return ia > ib;
    }
    return false;
  }

  static List<int> _parse(String v) {
    final s = v.startsWith('v') ? v.substring(1) : v;
    return s.split('.').map((p) => int.tryParse(p) ?? 0).toList();
  }
}

// ─── Service ─────────────────────────────────────────────────────────────────

class VersionService {
  static Future<ToolVersionInfo> checkGrype() => _check(
        command: 'grype',
        args: ['version'],
        githubRepo: 'anchore/grype',
      );

  static Future<ToolVersionInfo> checkOsv() => _check(
        command: 'osv-scanner',
        args: ['--version'],
        githubRepo: 'google/osv-scanner',
      );

  static Future<ToolVersionInfo> checkTrivy() => _check(
        command: 'trivy',
        args: ['--version'],
        githubRepo: 'aquasecurity/trivy',
      );

  static Future<ToolVersionInfo> _check({
    required String command,
    required List<String> args,
    required String githubRepo,
  }) async {
    final installed = await _installedVersion(command, args);
    final (latest, releaseUrl) = await _latestRelease(githubRepo);
    return ToolVersionInfo(
      installed: installed,
      latest: latest,
      releaseUrl: releaseUrl,
    );
  }

  static Future<String?> _installedVersion(
      String command, List<String> args) async {
    try {
      final result = await Process.run(command, args);
      final output = '${result.stdout}${result.stderr}';
      return RegExp(r'(\d+\.\d+\.\d+)').firstMatch(output)?.group(1);
    } catch (_) {
      return null;
    }
  }

  static Future<(String?, String?)> _latestRelease(String repo) async {
    try {
      final client = HttpClient()
        ..connectionTimeout = const Duration(seconds: 5);
      final req = await client
          .getUrl(Uri.parse(
              'https://api.github.com/repos/$repo/releases/latest'))
          .timeout(const Duration(seconds: 5));
      req.headers
        ..set('Accept', 'application/vnd.github+json')
        ..set('User-Agent', 'sbom-generator-gui');
      final resp = await req.close().timeout(const Duration(seconds: 5));
      if (resp.statusCode == 200) {
        final body = await resp.transform(utf8.decoder).join();
        final json = jsonDecode(body) as Map<String, dynamic>;
        final tag = json['tag_name'] as String?;
        final url = json['html_url'] as String?;
        if (tag != null) {
          final ver = tag.startsWith('v') ? tag.substring(1) : tag;
          return (ver, url);
        }
      }
      client.close(force: false);
    } catch (_) {}
    return (null, null);
  }
}

// ─── Widget badge ─────────────────────────────────────────────────────────────

class ToolVersionBadge extends StatelessWidget {
  /// null = vérification en cours (rien affiché)
  final ToolVersionInfo? info;

  const ToolVersionBadge({super.key, this.info});

  @override
  Widget build(BuildContext context) {
    final v = info;
    if (v == null) return const SizedBox.shrink();

    if (!v.isInstalled) {
      return const Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.error_outline, size: 13, color: Colors.red),
          SizedBox(width: 4),
          Text('non installé',
              style: TextStyle(fontSize: 11, color: Colors.red)),
        ],
      );
    }

    if (!v.hasUpdate) {
      return Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.check_circle_outline,
              size: 13, color: Colors.green[600]),
          const SizedBox(width: 4),
          Text('v${v.installed}',
              style: TextStyle(fontSize: 11, color: Colors.green[600])),
        ],
      );
    }

    // Mise à jour disponible — lien cliquable vers la release GitHub
    return Tooltip(
      message: 'Mise à jour disponible — cliquez pour accéder à la release',
      child: InkWell(
        onTap: v.releaseUrl != null
            ? () => launchUrl(Uri.parse(v.releaseUrl!),
                mode: LaunchMode.externalApplication)
            : null,
        borderRadius: BorderRadius.circular(4),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.upgrade, size: 13, color: Colors.orange),
              const SizedBox(width: 4),
              Text(
                'v${v.installed} → v${v.latest}',
                style: const TextStyle(
                  fontSize: 11,
                  color: Colors.orange,
                  decoration: TextDecoration.underline,
                  decorationColor: Colors.orange,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
