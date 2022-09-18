Name: pam-openid
Version: 1.0.0
Release: 1.0.0
Summary: OpenID PAM authentication
License: Apache License Version 2
URL: https://github.com/MWY3510/pam_oauth2_device
Source: https://github.com/MWY3510/pam_oauth2_device/archive/refs/heads/master.zip
BufURL: 

%description
The pam_oauth2_device authentication PAM module provides the facility for
RPM based systems to perform social authentication with the same auth services
that are used for your web applications.

%prep
%autosetup

%build
%configure
%make_build

%install
%make_install

%files

%changelog
* Mon July 18 2022 MWY3510 - 1.0.0
- Initial version of this package