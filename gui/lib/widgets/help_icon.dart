import 'package:flutter/material.dart';

/// Icône ❓ affichant un tooltip d'aide au survol (et au clic sur mobile).
///
/// Usage :
/// ```dart
/// Row(children: [
///   Text('Mon label'),
///   const SizedBox(width: 4),
///   const HelpIcon('Explication courte ou longue.'),
/// ])
/// ```
class HelpIcon extends StatelessWidget {
  final String message;
  final double iconSize;

  const HelpIcon(this.message, {super.key, this.iconSize = 15});

  @override
  Widget build(BuildContext context) {
    final color = Theme.of(
      context,
    ).colorScheme.onSurface.withValues(alpha: 0.4);
    return Tooltip(
      message: message,
      preferBelow: false,
      waitDuration: const Duration(milliseconds: 200),
      showDuration: const Duration(seconds: 6),
      constraints: const BoxConstraints(maxWidth: 320),
      textStyle: TextStyle(
        fontSize: 12,
        color: Theme.of(context).colorScheme.onInverseSurface,
        height: 1.4,
      ),
      child: Icon(Icons.help_outline_rounded, size: iconSize, color: color),
    );
  }
}

/// Ligne label + icône d'aide, utilisée comme en-tête de section ou label de champ.
class HelpLabel extends StatelessWidget {
  final String label;
  final String help;
  final TextStyle? style;
  final double gap;

  const HelpLabel(this.label, this.help, {super.key, this.style, this.gap = 4});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(label, style: style),
        SizedBox(width: gap),
        HelpIcon(help),
      ],
    );
  }
}
