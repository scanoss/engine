Name:       scanoss
Version:    ENGINE_VERSION
Release:    1%{?dist}
Summary:    SCANOSS Engine
License:    GPLv2
BuildArch:  x86_64

%description
SCANOSS is an open, configurable OSS engine that was built specifically for developers, empowering them to confidently produce compliant code from the moment they begin writing, while delivering greater license and usage visibility for the broader DevOps team and supply chain partners.

%prep

%build

%install
mkdir -p %{buildroot}/%{_bindir}
install -m 0755 %{name} %{buildroot}/%{_bindir}/%{name}

%files
%{_bindir}/%{name}

%changelog