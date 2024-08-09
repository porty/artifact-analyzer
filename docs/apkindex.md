# APKINDEX Format

https://wiki.alpinelinux.org/wiki/Apk_spec

The APKINDEX file contains a set of records extracted from the PKGINFO file of each package in the repository. Each line is prefixed with a letter, colon, and is followed by the value of the field. Lines are newline (\n) terminated and there is one blank line between records for a package.

The apk_pkg_write_index_entry function of package.c defines the currently accepted fields. As of July 2022, these are:

```
C: - file checksum, see below
P: - package name (corresponds to pkgname in PKGINFO)
V: - package version (corresponds to pkgver in PKGINFO)
A: - architecture (corresponds to arch in PKGINFO), optional
S: - size of entire package, integer
I: - installed size, integer (corresponds to size in PKGINFO)
T: - description (corresponds to pkgdesc in PKGINFO)
U: - url (corresponds to url in PKGINFO)
L: - license (corresponds to license in PKGINFO)
o: - origin (corresponds to origin in PKGINFO), optional
m: - maintainer (corresponds to maintainer in PKGINFO), optional
t: - build time (corresponds to builddate in PKGINFO), optional
c: - commit (corresponds to commit in PKGINFO), optional
k: - provider priority, integer (corresponds to provider_priority in PKGINFO), optional
D: - dependencies (corresponds to depend in PKGINFO, concatenated by spaces into a single line)
p: - provides (corresponds to provides in PKGINFO, concatenated by spaces into a single line)
i: - install if (corresponds to install_if in PKGINFO, concatenated by spaces into a single line)
```
