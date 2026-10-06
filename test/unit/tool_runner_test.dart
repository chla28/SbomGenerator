import 'package:sbom_generator/tool_runner.dart';
import 'package:test/test.dart';

void main() {
  test('runTool : outil absent du PATH → code 127, sans exception', () async {
    final r = await runTool('outil-inexistant-sbomgen', ['--version']);
    expect(r.exitCode, 127);
  });

  test('runTool : outil présent → résultat normal', () async {
    final r = await runTool('sh', ['-c', 'exit 3']);
    expect(r.exitCode, 3);
  });
}
