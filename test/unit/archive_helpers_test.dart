import 'package:sbom_generator/archive_helpers.dart';
import 'package:test/test.dart';

void main() {
  group('parseArchiveFilename', () {
    test('apache-tomcat-10.1.44.tar.gz', () {
      final info = parseArchiveFilename('/3PP/apache-tomcat-10.1.44.tar.gz');
      expect(info.name, 'apache-tomcat');
      expect(info.version, '10.1.44');
      expect(info.arch, 'any');
    });

    test('mariadb-11.4.8-linux-systemd-x86_64.tar.gz', () {
      final info = parseArchiveFilename(
          '/3PP/mariadb-11.4.8-linux-systemd-x86_64.tar.gz');
      expect(info.name, 'mariadb');
      expect(info.version, '11.4.8');
      expect(info.arch, 'x86_64');
    });

    test('mongodb-linux-x86_64-rhel8-8.0.12.tgz', () {
      final info =
          parseArchiveFilename('/3PP/mongodb-linux-x86_64-rhel8-8.0.12.tgz');
      expect(info.name, 'mongodb');
      expect(info.version, '8.0.12');
      expect(info.arch, 'x86_64');
    });

    test('mongodb-database-tools-rhel88-x86_64-100.13.0.tgz', () {
      final info = parseArchiveFilename(
          '/3PP/mongodb-database-tools-rhel88-x86_64-100.13.0.tgz');
      expect(info.name, 'mongodb-database-tools');
      expect(info.version, '100.13.0');
      expect(info.arch, 'x86_64');
    });

    test('mongosh-2.5.6-linux-x64.tgz', () {
      final info = parseArchiveFilename('/3PP/mongosh-2.5.6-linux-x64.tgz');
      expect(info.name, 'mongosh');
      expect(info.version, '2.5.6');
      expect(info.arch, 'x86_64'); // x64 → x86_64
    });

    test('archive sans version → nom complet, version vide', () {
      final info = parseArchiveFilename('/tmp/mypkg.tar.gz');
      expect(info.name, 'mypkg');
      expect(info.version, '');
      expect(info.arch, 'any');
    });

    test('archive .zip', () {
      final info = parseArchiveFilename('/dl/myapp-2.0.0-linux-amd64.zip');
      expect(info.name, 'myapp');
      expect(info.version, '2.0.0');
      expect(info.arch, 'x86_64'); // amd64 → x86_64
    });

    test('arm64 détecté', () {
      final info = parseArchiveFilename('/dl/myapp-1.0.0-linux-arm64.tar.gz');
      expect(info.arch, 'aarch64');
    });
  });

  group('identifyArchiveLicense', () {
    test('Apache-2.0', () {
      const text = 'Apache License\nVersion 2.0, January 2004';
      expect(identifyArchiveLicense(text), 'Apache-2.0');
    });

    test('MIT', () {
      const text = 'MIT License\nPermission is hereby granted, free of charge, '
          'to any person obtaining a copy without restriction';
      expect(identifyArchiveLicense(text), 'MIT');
    });

    test('GPL-2.0-only', () {
      const text = 'GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n'
          'Copyright (C) 1989, 1991 Free Software Foundation, Inc.';
      expect(identifyArchiveLicense(text), 'GPL-2.0-only');
    });

    test('GPL-3.0-only', () {
      const text = 'GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007';
      expect(identifyArchiveLicense(text), 'GPL-3.0-only');
    });

    test('LGPL-2.1-only', () {
      const text =
          'GNU Lesser General Public License\nVersion 2.1, February 1999';
      expect(identifyArchiveLicense(text), 'LGPL-2.1-only');
    });

    test('pas de faux positif GPL sur LGPL : corps GPL-2.0 mentionne LGPL', () {
      // Le corps de GPL-2.0 mentionne "GNU Library General Public License"
      // dans sa section "How to Apply", qui apparaît loin dans le texte.
      // La vérification LGPL ne porte que sur les 300 premiers caractères
      // (le "titre"), donc ce passage tardif ne doit pas provoquer un faux
      // positif LGPL.
      final filler = 'This program is free software; you can redistribute '
          'it and/or modify it under the terms of the GNU General Public '
          'License as published by the Free Software Foundation. ';
      // Filler > 300 chars pour pousser la mention LGPL après le titre
      final gpv2Body = 'GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n'
          '${filler * 3}'
          'You may also incorporate this library into a free program '
          'using the GNU Library General Public License instead.\n'
          'version 2 of the License';
      expect(identifyArchiveLicense(gpv2Body), 'GPL-2.0-only');
    });

    test('BSD-3-Clause', () {
      const text = 'BSD 3-Clause License\n'
          'Redistribution and use in source and binary forms\n'
          'Neither the name of the organization nor the names of its\n'
          'contributors may be used to endorse or promote products.';
      expect(identifyArchiveLicense(text), 'BSD-3-Clause');
    });

    test('BSD-2-Clause', () {
      const text = 'BSD 2-Clause License\n'
          'Redistribution and use in source and binary forms, with or '
          'without modification, are permitted provided that the following '
          'conditions are met.';
      expect(identifyArchiveLicense(text), 'BSD-2-Clause');
    });

    test('BSD-3-Clause sans le mot "BSD" (style paquets Dart/Google)', () {
      // La quasi-totalité des paquets pub utilisent ce texte exact, sans
      // jamais écrire "BSD".
      const text = 'Copyright 2013, the Dart project authors.\n\n'
          'Redistribution and use in source and binary forms, with or without\n'
          'modification, are permitted provided that the following conditions '
          'are met:\n'
          '    * Neither the name of Google LLC nor the names of its\n'
          '      contributors may be used to endorse or promote products '
          'derived from this software.';
      expect(identifyArchiveLicense(text), 'BSD-3-Clause');
    });

    test('licence inconnue → chaîne vide', () {
      expect(identifyArchiveLicense('Proprietary License v1.0'), isEmpty);
    });

    test('SSPL-1.0', () {
      const text = 'Server Side Public License\nVersion 1';
      expect(identifyArchiveLicense(text), 'SSPL-1.0');
    });
  });
}
