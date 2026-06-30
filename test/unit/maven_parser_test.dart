import 'dart:io';
import 'package:sbom_generator/maven_parser.dart';
import 'package:test/test.dart';

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('maven_test_'));
  tearDown(() => tmp.deleteSync(recursive: true));

  File _write(String name, String content) {
    final f = File('${tmp.path}/$name');
    f.writeAsStringSync(content);
    return f;
  }

  group('MavenParser', () {
    final parser = MavenParser();

    test('extrait les dépendances de base', () {
      final f = _write('pom.xml', '''
<project>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.21</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>
''');
      final pkgs = parser.parsePomXml(f.path);
      expect(pkgs, hasLength(2));
      final names = pkgs.map((p) => p.name).toSet();
      expect(names, contains('org.springframework:spring-core'));
      expect(names, contains('com.google.guava:guava'));
    });

    test('nom sous forme groupId:artifactId', () {
      final f = _write('pom.xml', '''
<project>
  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.9.3</version>
    </dependency>
  </dependencies>
</project>
''');
      final pkgs = parser.parsePomXml(f.path);
      expect(pkgs[0].name, 'org.junit.jupiter:junit-jupiter');
    });

    test('version extraite correctement', () {
      final f = _write('pom.xml', '''
<project>
  <dependencies>
    <dependency>
      <groupId>io.netty</groupId>
      <artifactId>netty-all</artifactId>
      <version>4.1.94.Final</version>
    </dependency>
  </dependencies>
</project>
''');
      final pkgs = parser.parsePomXml(f.path);
      expect(pkgs[0].version, '4.1.94.Final');
    });

    test('exclut les dépendances de portée test', () {
      final f = _write('pom.xml', '''
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.21</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
''');
      final pkgs = parser.parsePomXml(f.path);
      expect(pkgs, hasLength(1));
      expect(pkgs[0].name, 'org.springframework:spring-core');
    });

    test('exclut les dépendances de portée system', () {
      final f = _write('pom.xml', '''
<project>
  <dependencies>
    <dependency>
      <groupId>com.sun</groupId>
      <artifactId>tools</artifactId>
      <version>1.8.0</version>
      <scope>system</scope>
    </dependency>
  </dependencies>
</project>
''');
      final pkgs = parser.parsePomXml(f.path);
      expect(pkgs, isEmpty);
    });

    test('exclut dependencyManagement', () {
      final f = _write('pom.xml', '''
<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>managed</groupId>
        <artifactId>dep</artifactId>
        <version>1.0.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>real</groupId>
      <artifactId>dep</artifactId>
      <version>2.0.0</version>
    </dependency>
  </dependencies>
</project>
''');
      final pkgs = parser.parsePomXml(f.path);
      expect(pkgs, hasLength(1));
      expect(pkgs[0].name, 'real:dep');
    });

    test('packageType est maven', () {
      final f = _write('pom.xml', '''
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>lib</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
''');
      final pkgs = parser.parsePomXml(f.path);
      expect(pkgs[0].packageType, 'maven');
    });

    test('PURL de type pkg:maven/...', () {
      final f = _write('pom.xml', '''
<project>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.7</version>
    </dependency>
  </dependencies>
</project>
''');
      final pkgs = parser.parsePomXml(f.path);
      expect(pkgs[0].purl, 'pkg:maven/org.slf4j/slf4j-api@2.0.7');
    });

    test('fichier inexistant → liste vide', () {
      expect(parser.parsePomXml('/nonexistent/pom.xml'), isEmpty);
    });

    test('pom sans section dependencies → liste vide', () {
      final f = _write('pom.xml', '''
<project>
  <groupId>com.example</groupId>
  <artifactId>empty</artifactId>
  <version>1.0.0</version>
</project>
''');
      expect(parser.parsePomXml(f.path), isEmpty);
    });
  });
}
