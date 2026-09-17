Thank you for considering contributing to the SCANOSS Inventory Engine. It's people like you that make the SCANOSS Inventory Engine such a great tool. Feel welcome and read the following sections
in order to know how to get involved, ask questions and more importantly how to work on something.

The SCANOSS Inventory Engine is an open source project and we love to receive contributions from our community. There are many ways to contribute, from writing tutorials or blog posts, improving the documentation, submitting bug reports and feature requests, or writing code.
A welcome addition to the project is an integration with a new source code repository.

### Submitting bugs

If you are submitting a bug, please tell us:

- Version of SCANOSS Inventory Engine you are using
- Linux OS Version
- GCC version
- how to reproduce the bug.

### Pull requests

Want to submit a pull request? Great! But please follow some basic rules:

- Write a brief description that help us understand what you are trying to accomplish: what the change does, link to any relevant issue
- If you are changing a source file please make sure that you only include in the changeset the lines changed by you (beware of your editor reformatting the file)
- If you are adding functionality, please write a unit test.

When reviewing your pull request, we will follow a checklist similar to this one: https://gist.github.com/audreyr/4feef90445b9680475f2

We will also verify that the functionality implemented change serves the general public and not a particular interest group. 

### Release lines and tagging

The SCANOSS engine is maintained as two parallel release lines, and a pull request must target the right one:

| Release line | Branch | Engine versions | Tag format | Requires LDB |
|---|---|---|---|---|
| Traditional | `main` | 5.x | `vMAJOR.MINOR.PATCH` (e.g. `v5.5.1`) | 4.x, from the `main` branch of scanoss/ldb |
| CRC64-compatible | `crc64` | 6.x and later | `vMAJOR.MINOR.PATCH-crc64` (e.g. `v6.0.0-crc64`) | 5.x-crc64, from the `crc64` branch of scanoss/ldb |

The `-crc64` suffix is mandatory on the CRC64 line: both lines are tagged in the same repository, and the suffix is what keeps
their tags, release artifacts and installed package versions distinguishable. It is also carried by `SCANOSS_VERSION`, so
`scanoss -v` identifies which line a binary comes from.

Because RPM does not allow `-` in the `Version` field, `package.sh` translates the suffix to `_` for the spec file
(`6.0.0-crc64` becomes `6.0.0_crc64`). Debian packages keep the tag spelling as is.

A fix that applies to both lines should be submitted against `main` and then ported to `crc64`; the two branches are not merged
into each other. This includes CI workflow changes: keeping `.github/workflows/` in sync between the branches avoids one line
silently rotting while the other gets fixed.

### LDB version requirement

The minimum LDB version is declared once, in [`inc/ldb_compat.h`](inc/ldb_compat.h). Both the build time check
(`scripts/check_ldb_version.sh`, run from the Makefile) and the run time check (`ldb_compat_check()`, called from
`initialize_ldb_tables()`) read it from there. Do not hardcode a version anywhere else: the two checks must never be able to
disagree.

Bumping the requirement is a one line change to that header.

### Licensing

The SCANOSS Platform is released under the GPL-2.0 license. If you wish to contribute, you must accept that you are aware of the license under which the project is released, and that your contribution will be released under the same license. Sometimes the GPL-2.0 license is incompatible with other licenses chosen by other projects. Therefore, you must accept that your contribution can also be released under the MIT license, which is the license we choose for those situations. Unless you expressly request otherwise, we may use your name, email address, username or URL for your attribution notice text. The submission of your contribution implies that you agree with these licensing terms.
