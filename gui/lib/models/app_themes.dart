import 'package:flutter/material.dart';

class AppTheme {
  final String label;
  final Color color;
  const AppTheme(this.label, this.color);
}

const kAppThemes = [
  AppTheme('Indigo', Color(0xFF1A237E)),
  AppTheme('Bleu', Color(0xFF1565C0)),
  AppTheme('Violet', Color(0xFF4A148C)),
  AppTheme('Teal', Color(0xFF004D40)),
  AppTheme('Vert', Color(0xFF1B5E20)),
  AppTheme('Orange', Color(0xFFBF360C)),
  AppTheme('Rouge', Color(0xFFB71C1C)),
  AppTheme('Rose', Color(0xFF880E4F)),
  AppTheme('Ardoise', Color(0xFF37474F)),
  AppTheme('Marron', Color(0xFF4E342E)),
];
