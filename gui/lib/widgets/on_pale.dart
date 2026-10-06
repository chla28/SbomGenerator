import 'package:flutter/material.dart';

/// Couleur de texte sombre posée sur les fonds pastel (bandeaux, lignes de
/// comparaison) : en thème sombre, le texte par défaut est clair et devient
/// illisible sur ces fonds.
const kOnPale = Color(0xFF212121);

/// Force un texte (et des icônes) sombre sur un fond pastel, quel que soit le
/// thème de l'application.
class OnPale extends StatelessWidget {
  final Widget child;
  const OnPale({super.key, required this.child});

  @override
  Widget build(BuildContext context) => DefaultTextStyle.merge(
    style: const TextStyle(color: kOnPale),
    child: IconTheme.merge(
      data: const IconThemeData(color: kOnPale),
      child: child,
    ),
  );
}

/// [child] sous [OnPale] quand [pale] est vrai (fond pastel), sinon tel quel.
Widget paleIf(bool pale, Widget child) => pale ? OnPale(child: child) : child;
