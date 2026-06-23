Name:           sbom-generator
Version:        %{version}
Release:        1%{?dist}
Summary:        Générateur de SBOM (CycloneDX / SPDX) depuis des listes de paquets
License:        MIT
Source0:        sbom_generator-%{version}-linux-%{_arch}.tar.gz
BuildArch:      %{_arch}
ExclusiveArch:  x86_64 aarch64

# Binaires précompilés (Dart + Flutter) : désactiver strip et check-rpaths
%global __strip /bin/true
%global __brp_check_rpaths /bin/true
%define debug_package %{nil}

%description
Génère des Software Bill of Materials (SBOM) aux formats CycloneDX et SPDX 2.3/3.0
depuis des listes de paquets RPM, Python, DEB ou archives tar.
Le binaire CLI est autonome (pas de runtime Dart requis).

# ── Sous-package GUI ─────────────────────────────────────────────────────────

%package gui
Summary:        Interface graphique Flutter pour SBOM Generator
Requires:       %{name} = %{version}-%{release}
Requires:       fontconfig
Requires:       mesa-libGL

%if 0%{?rhel} && 0%{?rhel} <= 8
Requires:       gtk3
Requires:       libXi
Requires:       libXext
Requires:       libXrender
Requires:       libXfixes
%else
Requires:       gtk4
Requires:       libsecret
%endif

%description gui
Interface graphique Flutter pour SBOM Generator.
Permet de générer des SBOM CycloneDX/SPDX depuis une interface visuelle.
Installe également le raccourci applications et l'icône système.

# ── Phases de build ──────────────────────────────────────────────────────────

%prep
%setup -q -n sbom_generator-%{version}-linux-%{_arch}

%install
# CLI — binaire statique Dart
install -Dm755 bin/sbom-generator %{buildroot}%{_bindir}/sbom-generator

# GUI — bundle Flutter complet
install -dm755 %{buildroot}%{_libdir}/sbom_generator
cp -r gui/. %{buildroot}%{_libdir}/sbom_generator/
chmod +x %{buildroot}%{_libdir}/sbom_generator/sbom_generator_gui
# Le .desktop est installé dans le bon emplacement ci-dessous
rm -f %{buildroot}%{_libdir}/sbom_generator/sbom_generator.desktop

# Lien symbolique pour lancer le GUI depuis le PATH
install -dm755 %{buildroot}%{_bindir}
ln -sf %{_libdir}/sbom_generator/sbom_generator_gui \
       %{buildroot}%{_bindir}/sbom-generator-gui

# Icône scalable
install -Dm644 gui/sbom_generator.svg \
  %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/sbom_generator.svg

# Raccourci applications
install -Dm644 gui/sbom_generator.desktop \
  %{buildroot}%{_datadir}/applications/sbom_generator.desktop

# ── Listes de fichiers ───────────────────────────────────────────────────────

%files
%{_bindir}/sbom-generator

%files gui
%{_bindir}/sbom-generator-gui
%{_libdir}/sbom_generator/
%{_datadir}/icons/hicolor/scalable/apps/sbom_generator.svg
%{_datadir}/applications/sbom_generator.desktop

# ── Scripts post-install / post-remove ───────────────────────────────────────

%post gui
gtk-update-icon-cache -qf %{_datadir}/icons/hicolor &>/dev/null || :
update-desktop-database -q %{_datadir}/applications &>/dev/null || :

%postun gui
gtk-update-icon-cache -qf %{_datadir}/icons/hicolor &>/dev/null || :
update-desktop-database -q %{_datadir}/applications &>/dev/null || :

%changelog
* %(LC_ALL=C date "+%a %b %d %Y") Build System - %{version}-1
- Packaging automatique — version %{version}
