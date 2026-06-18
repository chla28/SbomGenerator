import 'package:flutter/material.dart';
import 'home_screen.dart';

void main() {
  runApp(const SbomGeneratorApp());
}

class SbomGeneratorApp extends StatelessWidget {
  const SbomGeneratorApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SBOM Generator',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1A237E), // bleu indigo pour SBOM
        ),
        inputDecorationTheme: const InputDecorationTheme(
          contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        ),
      ),
      home: const HomeScreen(),
    );
  }
}
