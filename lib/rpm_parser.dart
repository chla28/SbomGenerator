import 'dart:io';
import 'models.dart';

/// Queries RPM metadata using the system `rpm` binary.
///
/// Supports both installed packages (queried by name/NEVRA) and local
/// .rpm archive files (queried with the -p flag).
class RpmParser {
  /// RPM query format string.
  /// Fields (0-based): NAME|VERSION|RELEASE|ARCH|EPOCH|LICENSE|VENDOR|URL|
  ///                   BUILDTIME|SHA256HEADER|SOURCERPM|SUMMARY
  /// SUMMARY is intentionally last so that embedded '|' characters are
  /// handled by rejoining any extra segments at index ≥ 11.
  static const _queryFormat =
      r'%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{EPOCH}|%{LICENSE}|%{VENDOR}|%{URL}|%{BUILDTIME}|%{SHA256HEADER}|%{SOURCERPM}|%{SUMMARY}\n';

  /// Parse a single RPM reference (package name/NEVRA or path to .rpm file).
  /// Returns null and emits a warning if the package cannot be queried.
  Future<RpmPackage?> parsePackage(String packageRef) async {
    final isFile = packageRef.endsWith('.rpm');
    final qFlag = isFile ? '-qp' : '-q';

    // Run all three queries concurrently (metadata + requires + provides)
    final results = await Future.wait([
      Process.run('rpm', [qFlag, '--queryformat', _queryFormat, packageRef]),
      Process.run('rpm', [qFlag, '--requires', packageRef]),
      Process.run('rpm', [qFlag, '--provides', packageRef]),
    ]);

    final infoResult = results[0];
    if (infoResult.exitCode != 0) {
      stderr.writeln('Warning: cannot query "$packageRef"');
      final errMsg = infoResult.stderr.toString().trim();
      if (errMsg.isNotEmpty) stderr.writeln('  $errMsg');
      return null;
    }

    final rawOutput = infoResult.stdout.toString().trim();
    if (rawOutput.isEmpty) {
      stderr.writeln('Warning: empty output for "$packageRef"');
      return null;
    }

    // Take only the first line (handles multiple installed versions)
    final line = rawOutput.split('\n').first;
    final allParts = line.split('|');
    if (allParts.length < 12) {
      stderr
          .writeln('Warning: unexpected query output for "$packageRef": $line');
      return null;
    }

    // Rejoin summary fragments if it contained '|' (summary is at index 11+)
    final parts = allParts.length > 12
        ? [...allParts.sublist(0, 11), allParts.sublist(11).join('|')]
        : allParts;

    final requires = _parseCapabilities(results[1]);
    final provides = _parseCapabilities(results[2]);

    // Sanitise checksum: rpm returns "(none)" when unavailable
    final sha256Raw = parts[9].trim();
    final sha256 =
        (sha256Raw == '(none)' || sha256Raw.isEmpty) ? '' : sha256Raw;

    final sourceRpmRaw = parts[10].trim();
    final sourceRpm =
        (sourceRpmRaw == '(none)' || sourceRpmRaw.isEmpty) ? '' : sourceRpmRaw;

    return RpmPackage(
      name: parts[0].trim(),
      version: parts[1].trim(),
      release: parts[2].trim(),
      arch: parts[3].trim(),
      epoch: parts[4].trim(),
      license: parts[5].trim(),
      vendor: parts[6].trim(),
      url: parts[7].trim(),
      buildTime: parts[8].trim(),
      sha256Header: sha256,
      sourceRpm: sourceRpm,
      summary: parts[11].trim(),
      requires: requires,
      provides: provides,
      sourceRef: packageRef,
    );
  }

  List<String> _parseCapabilities(ProcessResult result) {
    if (result.exitCode != 0) return [];
    return result.stdout
        .toString()
        .split('\n')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
  }

  /// Build the dependency graph for a collection of packages.
  ///
  /// Algorithm:
  ///   1. Build a map: capability_name → bomRef for every package and every
  ///      entry in its `provides` list.
  ///   2. For each package, strip version constraints from its `requires` list
  ///      and resolve them against the map built in step 1.
  ///   3. Self-references (a package depends on itself) are filtered out.
  ///
  /// Only intra-list dependencies are included; unresolved external requires
  /// are silently ignored.
  List<PackageDependency> buildDependencies(List<Package> packages) {
    // Step 1 – build provides map
    final providesMap = <String, String>{}; // capability → bomRef
    for (final pkg in packages) {
      providesMap[pkg.name] = pkg.bomRef;
      for (final cap in pkg.provides) {
        final name = _capabilityName(cap);
        providesMap.putIfAbsent(name, () => pkg.bomRef);
      }
    }

    final knownRefs = {for (final p in packages) p.bomRef};

    // Step 2 – resolve requires
    final result = <PackageDependency>[];
    for (final pkg in packages) {
      final deps = <String>{};
      for (final req in pkg.requires) {
        final capName = _capabilityName(req);
        final targetRef = providesMap[capName];
        if (targetRef != null &&
            targetRef != pkg.bomRef &&
            knownRefs.contains(targetRef)) {
          deps.add(targetRef);
        }
      }
      result.add(PackageDependency(
        sourceRef: pkg.bomRef,
        dependsOn: deps.toList()..sort(),
      ));
    }

    return result;
  }

  /// Extract the capability name from an RPM requires/provides entry.
  ///
  /// Only the version constraint (operator + version) is stripped; parenthesised
  /// module names that are part of the capability name are preserved.
  ///
  /// Examples:
  ///   "bash >= 4.1"                        → "bash"
  ///   "python3dist(lxml) >= 3.0"           → "python3dist(lxml)"
  ///   "python3dist(lxml)"                  → "python3dist(lxml)"
  ///   "libc.so.6(GLIBC_2.17)(64bit)"       → "libc.so.6(GLIBC_2.17)(64bit)"
  ///   "rpmlib(CompressedFileNames) <= 3.0"  → "rpmlib(CompressedFileNames)"
  ///   "VirtualBox-7.2 = 7.2.2_170484-1"   → "VirtualBox-7.2"
  ///   "/bin/sh"                            → "/bin/sh"
  String _capabilityName(String capability) {
    // Split only on whitespace immediately followed by a comparison operator.
    // This preserves "foo(bar)" style capability names while removing " >= x.y".
    return capability.split(RegExp(r'\s+[<>=!]'))[0].trim();
  }
}
