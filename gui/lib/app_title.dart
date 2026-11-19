import 'package:material_ui/material_ui.dart';
import 'package:package_info_plus/package_info_plus.dart';

/// Titre de la barre d'application : nom en gras suivi de la version en
/// police normale, plus petite et atténuée (« Titre  v1.2.3 »).
///
/// Même widget dans toutes les applications AuditTools : le visuel de
/// la barre de titre reste uniforme d'une GUI à l'autre.
class AppTitle extends StatefulWidget {
  const AppTitle(this.title, {super.key, this.fallbackVersion});

  final String title;

  /// Version affichée tant que (ou si) le paquet installé ne la fournit pas :
  /// tests, plateforme sans plugin. Sans valeur, rien n'est affiché alors.
  final String? fallbackVersion;

  @override
  State<AppTitle> createState() => _AppTitleState();
}

// Lecture unique par processus : la version ne change pas à l'exécution.
Future<String?>? _versionCache;

Future<String?> _readVersion() async {
  try {
    final info = await PackageInfo.fromPlatform();
    return info.version.isEmpty ? null : info.version;
  } catch (_) {
    return null;
  }
}

class _AppTitleState extends State<AppTitle> {
  late final Future<String?> _version = _versionCache ??= _readVersion();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final base = theme.appBarTheme.titleTextStyle ?? theme.textTheme.titleLarge;
    return FutureBuilder<String?>(
      future: _version,
      builder: (context, snapshot) {
        final version = snapshot.data ?? widget.fallbackVersion;
        return Row(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.baseline,
          textBaseline: TextBaseline.alphabetic,
          children: [
            Flexible(
              child: Text(
                widget.title,
                overflow: TextOverflow.ellipsis,
                style: base?.copyWith(fontWeight: FontWeight.bold),
              ),
            ),
            if (version != null && version.isNotEmpty) ...[
              const SizedBox(width: 8),
              Flexible(
                child: Text(
                  'v$version',
                  key: const Key('app-title-version'),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.labelMedium?.copyWith(
                    fontWeight: FontWeight.normal,
                    color: theme.colorScheme.outline,
                  ),
                ),
              ),
            ],
          ],
        );
      },
    );
  }
}
