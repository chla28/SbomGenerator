/// Descente dans les objets imbriqués (`--depth`) : un RPM qui contient des
/// jars, une archive qui contient des paquets…
///
/// Pour chaque objet racine (rpm, deb, jar/war/ear, wheel, zip, tar, tgz),
/// [NestedExplorer] en extrait **sélectivement** (script Python embarqué, sans
/// dépendance à `rpm2cpio`/`cpio`/`dpkg-deb`) les objets analysables qu'il
/// contient : paquets (rpm, deb, wheel), jars, archives, et manifestes
/// (`package-lock.json`, `go.sum`, `pom.xml`…). Chaque objet est analysé par le
/// parseur habituel, puis la descente se poursuit jusqu'à la profondeur
/// demandée.
///
/// Profondeur : 0 = l'objet seul (comportement historique), 1 = ses objets
/// directs, N = N niveaux. Les extractions sont bornées (taille, nombre de
/// fichiers, chemins hors destination refusés) contre les archives piégées.
///
/// Les paquets imbriqués portent un `sourceRef` « logique »
/// `racine.rpm!/chemin/dans/l/archive/x.jar` (jamais un chemin temporaire) ;
/// c'est lui qui permet aux générateurs d'émettre `location` / `depth` et au
/// scan d'attribuer une CVE à l'objet qui la contient.
library;

import 'dart:convert';
import 'dart:io';
import 'tool_runner.dart';

import 'deb_parser.dart';
import 'go_parser.dart';
import 'jar_parser.dart';
import 'maven_parser.dart';
import 'models.dart';
import 'npm_parser.dart';
import 'pubspec_parser.dart';
import 'requirements_parser.dart';
import 'rpm_parser.dart';
import 'tar_parser.dart';
import 'wheel_parser.dart';
import 'yarn_parser.dart';
import 'zip_parser.dart';
import 'i18n.dart';

/// Profondeur maximale (`--depth all`) : garde-fou contre les archives
/// auto-référentes ou démesurément imbriquées.
const maxNestedDepth = 10;

/// Séparateur entre un objet et un chemin interne dans un `sourceRef` logique
/// (même convention que les URL `jar:file.jar!/chemin`).
const nestedSeparator = '!/';

/// Préfixe des propriétés CycloneDX émises pour un composant imbriqué.
const nestedPropertyPrefix = 'sbom_generator:nested:';

/// Limites d'une extraction (par archive).
const _maxTotalBytes = 4 * 1024 * 1024 * 1024;
const _maxFiles = 50000;
const _maxMemberBytes = 2 * 1024 * 1024 * 1024;

/// `true` si [sourceRef] désigne un composant trouvé dans un objet imbriqué.
bool isNestedRef(String sourceRef) => sourceRef.contains(nestedSeparator);

/// Profondeur d'un `sourceRef` logique (0 pour un objet racine).
int nestedDepthOf(String sourceRef) =>
    nestedSeparator.allMatches(sourceRef).length;

/// Champs `location` / `depth` d'un composant imbriqué (vide pour un objet
/// racine) — partagés par tous les générateurs.
Map<String, String> nestedFields(Package pkg) => isNestedRef(pkg.sourceRef)
    ? {'location': pkg.sourceRef, 'depth': '${nestedDepthOf(pkg.sourceRef)}'}
    : const {};

/// Valeur de `--depth` : entier ≥ 0 ou `all`. `null` si invalide.
int? parseNestedDepth(String raw) {
  final v = raw.trim().toLowerCase();
  if (v == 'all') return maxNestedDepth;
  final n = int.tryParse(v);
  if (n == null || n < 0) return null;
  return n > maxNestedDepth ? maxNestedDepth : n;
}

/// Un objet trouvé dans un conteneur : un fichier analysé par un parseur.
class NestedObject {
  NestedObject({
    required this.location,
    required this.depth,
    required this.packages,
    required this.parentRef,
    required this.isArchive,
  });

  /// Chemin logique `racine.rpm!/usr/share/java/x.jar`.
  final String location;

  /// 1 = objet direct de la racine, 2 = objet d'un objet direct…
  final int depth;

  /// Composants décrits par l'objet (`sourceRef` = [location]).
  final List<Package> packages;

  /// `bomRef` du composant principal du conteneur (null si inconnu).
  final String? parentRef;

  /// `true` pour un paquet/une archive (descente possible), `false` pour un
  /// manifeste (lockfile…).
  final bool isArchive;

  /// Composant qui représente l'objet lui-même (le jar, le rpm…), pour les
  /// objets archive ; les manifestes n'en ont pas.
  Package? get primary =>
      isArchive && packages.isNotEmpty ? packages.first : null;
}

/// Résultat d'exploration d'un objet racine.
class NestedResult {
  final objects = <NestedObject>[];
  final warnings = <String>[];
}

/// Explore les objets imbriqués d'archives et paquets.
class NestedExplorer {
  NestedExplorer({
    required this.maxDepth,
    this.sdkVersions = const {},
    this.pubCache,
    this.flutterRoot,
    this.onProgress,
  });

  final int maxDepth;
  final Map<String, String> sdkVersions;
  final String? pubCache;
  final String? flutterRoot;

  /// Appelé avant l'analyse de chaque objet (`verbose`).
  final void Function(String location)? onProgress;

  final _rpm = RpmParser();
  final _whl = WheelParser();
  final _tar = TarParser();
  final _zip = ZipParser();
  final _deb = DebParser();
  final _jar = JarParser();
  final _req = RequirementsParser();
  final _go = GoParser();
  final _npm = NpmParser();
  final _yarn = YarnParser();
  final _maven = MavenParser();
  final _pubspec = PubspecParser();

  /// `true` si [path] est un objet dans lequel on sait descendre.
  static bool isExplorable(String path) => _kindOf(path) == _Kind.archive;

  /// Explore [rootPath] ; [rootPrimaryRef] est le `bomRef` du composant qui
  /// décrit la racine (parent des objets de premier niveau).
  Future<NestedResult> explore(String rootPath,
      {String? rootPrimaryRef}) async {
    final result = NestedResult();
    if (maxDepth <= 0 || !isExplorable(rootPath)) return result;
    final rootName = rootPath.split('/').last;
    await _walk(rootPath, rootName, rootPrimaryRef, 1, result);
    return result;
  }

  Future<void> _walk(String archivePath, String prefix, String? parentRef,
      int level, NestedResult out) async {
    final tmp = await Directory.systemTemp.createTemp('sbom_nested_');
    try {
      final extracted = await _extract(archivePath, tmp.path, out, prefix);
      extracted.sort();
      for (final rel in extracted) {
        final abs = '${tmp.path}/$rel';
        final location = '$prefix$nestedSeparator$rel';
        final kind = _kindOf(rel);
        if (kind == _Kind.none) continue;
        onProgress?.call(location);

        List<Package> pkgs;
        try {
          pkgs = await _parse(abs);
        } catch (e) {
          out.warnings.add(tr('$location : analyse impossible ($e)',
              '$location: analysis failed ($e)'));
          pkgs = const [];
        }
        pkgs = [for (final p in pkgs) p.copyWith(sourceRef: location)];

        final isArchive = kind == _Kind.archive;
        final obj = NestedObject(
          location: location,
          depth: level,
          packages: pkgs,
          parentRef: parentRef,
          isArchive: isArchive,
        );
        if (pkgs.isNotEmpty) out.objects.add(obj);

        if (isArchive && level < maxDepth) {
          await _walk(
              abs, location, obj.primary?.bomRef ?? parentRef, level + 1, out);
        }
      }
    } finally {
      try {
        await tmp.delete(recursive: true);
      } on FileSystemException {
        // Nettoyage best-effort.
      }
    }
  }

  Future<List<Package>> _parse(String path) async {
    final lower = path.toLowerCase();
    final base = lower.split('/').last;
    switch (base) {
      case 'requirements.txt':
        return _req.parseFile(path);
      case 'go.sum':
        return _go.parseGoSum(path);
      case 'go.mod':
        return _go.parseGoMod(path);
      case 'package-lock.json':
        return _npm.parsePackageLock(path);
      case 'yarn.lock':
        return _yarn.parseYarnLock(path);
      case 'pom.xml':
        return _maven.parsePomXml(path);
      case 'pubspec.lock':
        return _pubspec.parsePubspecLock(path,
            sdkVersions: sdkVersions,
            pubCache: pubCache,
            flutterRoot: flutterRoot);
      case 'pubspec.yaml':
        return _pubspec.parsePubspecYaml(path, sdkVersions: sdkVersions);
    }
    Package? single;
    if (lower.endsWith('.whl')) {
      single = await _whl.parseWheelFile(path);
    } else if (lower.endsWith('.rpm')) {
      single = await _rpm.parsePackage(path);
    } else if (lower.endsWith('.deb')) {
      single = await _deb.parseDebFile(path);
    } else if (_isJarName(lower)) {
      return _jar.parseJarFile(path);
    } else if (lower.endsWith('.zip')) {
      single = await _zip.parseZipFile(path);
    } else if (_isTarName(lower)) {
      single = await _tar.parseTarFile(path);
    }
    return single != null ? [single] : const [];
  }

  /// Extrait de [archive] (rpm, deb, zip, tar…) les seuls objets analysables
  /// vers [dest] ; renvoie leurs chemins relatifs.
  Future<List<String>> _extract(
      String archive, String dest, NestedResult out, String label) async {
    final ProcessResult r;
    try {
      r = await runTool('python3', [
        '-c',
        _extractScript,
        archive,
        dest,
        '$_maxTotalBytes',
        '$_maxFiles',
        '$_maxMemberBytes',
      ]);
    } on ProcessException {
      out.warnings.add(tr(
          'python3 introuvable : impossible de descendre dans $label.',
          'python3 not found: cannot descend into $label.'));
      return const [];
    }
    if (r.exitCode != 0) {
      final err = r.stderr.toString().trim().split('\n').last;
      out.warnings.add(tr('$label : extraction impossible ($err)',
          '$label: extraction failed ($err)'));
      return const [];
    }
    try {
      final json = jsonDecode(r.stdout.toString().trim()) as Map;
      for (final w in (json['warnings'] as List? ?? const [])) {
        out.warnings.add('$label : $w');
      }
      return [for (final f in (json['files'] as List)) f as String];
    } catch (_) {
      out.warnings.add(tr('$label : sortie d\'extraction illisible',
          '$label: unreadable extraction output'));
      return const [];
    }
  }
}

// ── Typage des fichiers ───────────────────────────────────────────────────

enum _Kind { archive, manifest, none }

const _manifestNames = {
  'requirements.txt',
  'pom.xml',
  'go.sum',
  'go.mod',
  'package-lock.json',
  'yarn.lock',
  'pubspec.lock',
  'pubspec.yaml',
};

bool _isJarName(String lower) =>
    lower.endsWith('.jar') || lower.endsWith('.war') || lower.endsWith('.ear');

bool _isTarName(String lower) =>
    lower.endsWith('.tar') ||
    lower.endsWith('.tar.gz') ||
    lower.endsWith('.tgz');

_Kind _kindOf(String path) {
  final lower = path.toLowerCase();
  if (_manifestNames.contains(lower.split('/').last)) return _Kind.manifest;
  if (lower.endsWith('.rpm') ||
      lower.endsWith('.deb') ||
      lower.endsWith('.whl') ||
      lower.endsWith('.zip') ||
      _isJarName(lower) ||
      _isTarName(lower)) {
    return _Kind.archive;
  }
  return _Kind.none;
}

// ── Dépendances parent → enfant ───────────────────────────────────────────

/// Ajoute à [deps] les arêtes de contenance : composant principal du
/// conteneur → composant principal de l'objet imbriqué, et composant
/// principal de l'objet → ses autres composants (dépendances relocalisées d'un
/// uber-jar…). Un manifeste (sans composant principal) est rattaché
/// directement au conteneur. Les arêtes existantes sont conservées.
List<PackageDependency> withNestedDependencies(
    List<PackageDependency> deps, Iterable<NestedObject> objects) {
  final byRef = <String, Set<String>>{
    for (final d in deps) d.sourceRef: {...d.dependsOn},
  };
  void edge(String? from, String to) {
    if (from == null || from == to) return;
    (byRef[from] ??= {}).add(to);
  }

  for (final o in objects) {
    final primary = o.primary;
    if (primary != null) {
      edge(o.parentRef, primary.bomRef);
      for (final p in o.packages.skip(1)) {
        edge(primary.bomRef, p.bomRef);
      }
    } else {
      for (final p in o.packages) {
        edge(o.parentRef, p.bomRef);
      }
    }
  }
  return [
    for (final e in byRef.entries)
      PackageDependency(sourceRef: e.key, dependsOn: e.value.toList()..sort()),
  ];
}

/// Nom de base (sans extension de format) du SBOM d'un objet imbriqué :
/// `<base>.nested-NN-<slug>` — `NN` sur deux chiffres au moins pour que
/// l'ordre alphabétique suive l'ordre de découverte.
String nestedFileBase(String base, int index, int total, String location) {
  final width = total < 100 ? 2 : total.toString().length;
  var slug = location
      .split(nestedSeparator)
      .last
      .split('/')
      .last
      .replaceAll(RegExp(r'[^A-Za-z0-9._-]'), '_');
  if (slug.length > 60) slug = slug.substring(0, 60);
  return '$base.nested-${index.toString().padLeft(width, '0')}-$slug';
}

// ── Relecture pour le scan ────────────────────────────────────────────────

/// Index `nom@version` → emplacement (`location`) lu dans un SBOM CycloneDX
/// produit avec `--depth`, pour attribuer chaque CVE à l'objet qui la
/// contient (`scan --package`).
class NestedSbomIndex {
  NestedSbomIndex(this.locationByPackage);

  final Map<String, String> locationByPackage;

  bool get isEmpty => locationByPackage.isEmpty;

  /// Emplacement du paquet `nom@version` ; repli sur le nom seul quand toutes
  /// les versions de ce nom sont au même endroit (versions normalisées par
  /// les scanners).
  String? locationOf(String packageAtVersion) {
    final exact = locationByPackage[packageAtVersion];
    if (exact != null) return exact;
    final at = packageAtVersion.lastIndexOf('@');
    final name = at > 0 ? packageAtVersion.substring(0, at) : packageAtVersion;
    final candidates = {
      for (final e in locationByPackage.entries)
        if (e.key.startsWith('$name@')) e.value,
    };
    return candidates.length == 1 ? candidates.first : null;
  }

  static NestedSbomIndex load(String cycloneDxPath) {
    final map = <String, String>{};
    try {
      final json = jsonDecode(File(cycloneDxPath).readAsStringSync());
      if (json is Map) {
        for (final c in (json['components'] as List? ?? const [])) {
          if (c is! Map) continue;
          for (final p in (c['properties'] as List? ?? const [])) {
            if (p is Map && p['name'] == '${nestedPropertyPrefix}location') {
              map['${c['name']}@${c['version'] ?? ''}'] = '${p['value']}';
            }
          }
        }
      }
    } on FormatException {
      // SBOM illisible : index vide.
    }
    return NestedSbomIndex(map);
  }
}

/// Rattache chaque vulnérabilité de [vulns] (clé `package` = `nom@version`) à
/// l'objet qui la contient : clé `container` (emplacement logique, ou le nom
/// de la racine pour un composant de premier niveau). Renvoie le nombre de
/// vulnérabilités non rattachées.
int attributeNested(
    List<Map<String, dynamic>> vulns, NestedSbomIndex index, String rootLabel) {
  var unknown = 0;
  for (final v in vulns) {
    final key = (v['package'] as String?) ?? '';
    final loc = index.locationOf(key);
    if (loc != null) {
      v['container'] = loc;
    } else {
      v['container'] = rootLabel;
      unknown++;
    }
  }
  return unknown;
}

// ── Script d'extraction ───────────────────────────────────────────────────
//
// Argv : archive, destination, octets max au total, fichiers max, octets max
// par fichier. Sort une ligne JSON {"files": [...], "warnings": [...]}.
// Formats reconnus par signature : rpm (en-têtes + cpio newc gz/xz/bz2/zstd),
// deb (ar → data.tar.*), zip/jar/war/whl, tar (gz/xz/bz2). Ne retient que les
// fichiers « analysables » (archives, paquets, manifestes). Les chemins
// absolus ou sortant de la destination sont ignorés, les liens aussi.
const _extractScript = r'''
import sys, os, re, json, io, struct, subprocess, tarfile, zipfile
import gzip, bz2, lzma

src, dest = sys.argv[1], sys.argv[2]
MAX_TOTAL, MAX_FILES, MAX_MEMBER = (int(x) for x in sys.argv[3:6])

ARCH = re.compile(r'\.(jar|war|ear|whl|zip|rpm|deb|tar|tgz|tar\.gz)$', re.I)
MANIFESTS = {'requirements.txt', 'pom.xml', 'go.sum', 'go.mod',
             'package-lock.json', 'yarn.lock', 'pubspec.lock', 'pubspec.yaml'}

out, warnings = [], []
written = 0

class Limit(Exception):
    pass

def wanted(path):
    parts = path.replace('\\', '/').strip('/').split('/')
    base = parts[-1]
    if ARCH.search(base):
        return True
    return base in MANIFESTS and 'META-INF' not in parts[:-1]

def safe_rel(name):
    n = os.path.normpath(name.replace('\\', '/').lstrip('/'))
    if n in ('.', '') or n == '..' or n.startswith('../') or os.path.isabs(n):
        return None
    return n

def put(name, stream):
    global written
    rel = safe_rel(name)
    if rel is None:
        return
    if len(out) >= MAX_FILES:
        raise Limit('nombre maximal de fichiers atteint (%d)' % MAX_FILES)
    target = os.path.join(dest, rel)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    size = 0
    try:
        with open(target, 'wb') as f:
            while True:
                chunk = stream.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                written += len(chunk)
                if size > MAX_MEMBER or written > MAX_TOTAL:
                    raise Limit('taille maximale décompressée dépassée')
                f.write(chunk)
    except Limit:
        try:
            os.remove(target)
        except OSError:
            pass
        raise
    out.append(rel)

def read_exact(s, n):
    data = b''
    while len(data) < n:
        c = s.read(n - len(data))
        if not c:
            break
        data += c
    return data

def skip(s, n):
    while n > 0:
        c = s.read(min(n, 1 << 20))
        if not c:
            break
        n -= len(c)

class Bounded:
    def __init__(self, s, n):
        self.s, self.n = s, n
    def read(self, k=-1):
        if self.n <= 0:
            return b''
        if k < 0 or k > self.n:
            k = self.n
        d = self.s.read(k)
        self.n -= len(d)
        return d

def decompress(f, head):
    if head[:2] == b'\x1f\x8b':
        return gzip.GzipFile(fileobj=f)
    if head[:6] == b'\xfd7zXZ\x00':
        return lzma.LZMAFile(f)
    if head[:3] == b'BZh':
        return bz2.BZ2File(f)
    if head[:4] == b'\x28\xb5\x2f\xfd':
        p = subprocess.Popen(['zstd', '-dc'], stdin=f, stdout=subprocess.PIPE)
        return p.stdout
    return f

def do_cpio(s):
    while True:
        h = read_exact(s, 110)
        if len(h) < 110:
            break
        if h[:6] not in (b'070701', b'070702'):
            raise ValueError('cpio non reconnu')
        v = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        mode, fsize, nsize = v[1], v[6], v[11]
        name = read_exact(s, nsize)[:-1].decode('utf-8', 'replace')
        skip(s, (4 - (110 + nsize) % 4) % 4)
        if name == 'TRAILER!!!':
            break
        if (mode & 0o170000) == 0o100000 and wanted(name):
            put(name, Bounded(s, fsize))
        else:
            skip(s, fsize)
        skip(s, (4 - fsize % 4) % 4)

def do_rpm(path):
    f = open(path, 'rb', buffering=0)
    if read_exact(f, 96)[:4] != b'\xed\xab\xee\xdb':
        raise ValueError('rpm invalide')
    def header():
        m = read_exact(f, 8)
        if m[:3] != b'\x8e\xad\xe8':
            raise ValueError('en-tête rpm invalide')
        n, size = struct.unpack('>II', read_exact(f, 8))
        f.seek(n * 16 + size, 1)
    header()
    f.seek((8 - f.tell() % 8) % 8, 1)
    header()
    pos = f.tell()
    head = read_exact(f, 6)
    f.seek(pos)
    s = decompress(io.BufferedReader(f) if head[:4] != b'\x28\xb5\x2f\xfd' else f, head)
    do_cpio(s)

def do_tar(fileobj=None, path=None):
    tf = tarfile.open(name=path, fileobj=fileobj, mode='r|*' if fileobj else 'r:*')
    for m in tf:
        if m.isreg() and wanted(m.name):
            put(m.name, tf.extractfile(m))

def do_deb(path):
    with open(path, 'rb') as f:
        if f.read(8) != b'!<arch>\n':
            raise ValueError('deb invalide')
        while True:
            h = f.read(60)
            if len(h) < 60:
                raise ValueError('data.tar introuvable')
            name = h[:16].decode().strip().rstrip('/')
            size = int(h[48:58])
            if name.startswith('data.tar'):
                if name.endswith('.zst'):
                    tmp = dest + '.zst.tmp'
                    with open(tmp, 'wb') as t:
                        t.write(f.read(size))
                    with open(tmp, 'rb') as t:
                        p = subprocess.Popen(['zstd', '-dc'], stdin=t, stdout=subprocess.PIPE)
                        do_tar(fileobj=p.stdout)
                    os.remove(tmp)
                else:
                    do_tar(fileobj=Bounded(f, size))
                return
            f.seek(size + (size % 2), 1)

def do_zip(path):
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            if not i.is_dir() and wanted(i.filename):
                with z.open(i) as s:
                    put(i.filename, s)

try:
    with open(src, 'rb') as f:
        head = f.read(8)
    try:
        if head[:4] == b'\xed\xab\xee\xdb':
            do_rpm(src)
        elif head == b'!<arch>\n':
            do_deb(src)
        elif zipfile.is_zipfile(src):
            do_zip(src)
        else:
            do_tar(path=src)
    except Limit as e:
        warnings.append(str(e) + ' — extraction tronquée / extraction truncated')
    print(json.dumps({'files': out, 'warnings': warnings}))
except Exception as e:
    print('%s: %s' % (type(e).__name__, e), file=sys.stderr)
    sys.exit(1)
''';
