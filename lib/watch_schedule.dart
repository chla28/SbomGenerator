import 'i18n.dart';

/// Guillemets simples POSIX : sûr pour une unité systemd comme pour cron.
String shellQuote(String s) => RegExp(r'^[A-Za-z0-9_./:=@%+-]+$').hasMatch(s)
    ? s
    : "'${s.replaceAll("'", r"'\''")}'";

String commandLine(List<String> argv) => argv.map(shellQuote).join(' ');

/// Expression cron (5 champs) pour un passage toutes les [d].
/// Lève [FormatException] si l'intervalle n'est pas exprimable (cron ne sait
/// pas faire « toutes les 7 minutes » de façon régulière sur l'heure).
String cronExpression(Duration d) {
  if (d.inSeconds < 60 || d.inSeconds % 60 != 0) {
    throw FormatException(tr('cron : intervalle minimal d\'une minute'));
  }
  if (d.inMinutes < 60) {
    if (60 % d.inMinutes != 0) {
      throw FormatException(tr(
          'cron : les minutes doivent diviser 60 (1, 2, 3, 5, 10, 15, 20, 30)'));
    }
    return '*/${d.inMinutes} * * * *';
  }
  if (d.inMinutes % 60 == 0 && d.inHours < 24) {
    if (24 % d.inHours != 0) {
      throw FormatException(
          tr('cron : les heures doivent diviser 24 (1, 2, 3, 4, 6, 8, 12)'));
    }
    return '0 */${d.inHours} * * *';
  }
  if (d.inHours % 24 == 0) {
    final days = d.inDays;
    return days == 1 ? '0 3 * * *' : '0 3 */$days * *';
  }
  throw FormatException(tr(
      'cron : intervalle non exprimable (utiliser un multiple de jours entiers)'));
}

String _systemdSpan(Duration d) {
  if (d.inSeconds % 86400 == 0) return '${d.inDays}d';
  if (d.inSeconds % 3600 == 0) return '${d.inHours}h';
  if (d.inSeconds % 60 == 0) return '${d.inMinutes}min';
  return '${d.inSeconds}s';
}

/// Unité de service (oneshot) lançant [argv]. `watch` sort en code 3 quand il
/// trouve de nouvelles CVE : ce n'est pas un échec du service.
String systemdService(List<String> argv, {String? workingDir}) => '''[Unit]
Description=sbom_generator watch : nouvelles CVE dans les SBOM suivis

[Service]
Type=oneshot
${workingDir != null ? 'WorkingDirectory=$workingDir\n' : ''}ExecStart=${commandLine(argv)}
SuccessExitStatus=3
''';

/// Ligne de crontab : [cron] est l'expression à 5 champs de [cronExpression].
String cronLine(String cron, List<String> argv, {String? workingDir}) =>
    '$cron ${workingDir != null ? 'cd ${shellQuote(workingDir)} && ' : ''}'
    '${commandLine(argv)}';

String systemdTimer(Duration interval) => '''[Unit]
Description=Passage périodique de sbom_generator watch

[Timer]
OnBootSec=5min
OnUnitActiveSec=${_systemdSpan(interval)}

[Install]
WantedBy=timers.target
''';
