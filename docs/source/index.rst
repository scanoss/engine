================================
Documentation for SCANOSS Engine
================================

The SCANOSS Engine is an open, configurable OSS engine that was built specifically for developers, empowering them to confidently produce compliant code from the moment they begin writing, while delivering greater license and usage visibility for the broader DevOps team and supply chain partners.

With its open architecture that is easy to integrate into existing processes and toolchains, SCANOSS transforms software bill of materials (SBOM) creation from 'write now, audit later' to an always-on analysis of live code.

By freeing developers to focus on writing great, compliant code that they and their team can completely trust, applications are finished earlier, quality is consistently higher, and development costs are dramatically lower.

Release line: CRC64-compatible (6.x)
------------------------------------

This documentation covers the ``crc64`` release line of the SCANOSS engine, starting at v6.0.0-crc64.

The engine is maintained as two parallel release lines:

.. list-table::
   :header-rows: 1

   * - Release line
     - Branch
     - Engine versions
     - Tag format
     - Requires LDB
   * - Traditional
     - ``main``
     - 5.x
     - ``v5.5.1``
     - 4.x (``main`` branch of scanoss/ldb)
   * - CRC64-compatible
     - ``crc64``
     - 6.x and later
     - ``v6.0.0-crc64``
     - 5.x-crc64 (``crc64`` branch of scanoss/ldb)

Engine 6.x requires LDB 5.0.0-crc64 or later. Engine 5.x and earlier go with the traditional LDB line (4.x). The constraint
comes from the LDB on-disk table layout and the library API surface, not from the choice of CRC64 vs MD5, so it applies in both
hash modes. The requirement is enforced at build time (``scripts/check_ldb_version.sh``) and at run time
(``ldb_compat_check()``), both driven from ``inc/ldb_compat.h``.

Setup
-----

The Scanoss engine requires a Knowledge database installed for retrieving results. Scanoss use the SCANOSS LDB (Linked-list database) as a shared library. LDB Source code and installation guide can be found on https://github.com/scanoss/ldb

The knowledge database is incrementally built using the SCANOSS mining tool (minr). It source code and installation guide can be found on https://github.com/scanoss/minr

Prerequisites
-------------

* LDB shared library, **5.0.0-crc64 or later**, built from the ``crc64`` branch. Installation instructions: `LDB README (crc64 branch) <https://github.com/scanoss/ldb/blob/crc64/README.md>`_.
* libgcrypt-dev

Installation
-------------

The SCANOSS Engine is a command-line tool used for comparing a file or directory against the SCANOSS Knowledgebase. The source code can be downloaded and compiled as follows::

    git clone -b crc64 https://github.com/scanoss/engine
    cd engine
    make
    sudo make install
    cd ..
    scanoss -v

If you want to try scanoss without install it, execute this command in bash::

    export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH

The last command should show the installed version of the SCANOSS Engine.

Usage
-----
This program performs an OSS inventory for the given TARGET comparing against the ScanOSS LDB Knowledgebase. Results are printed in STDOUT in JSON format.
You can create your own knowledgebase with the minr command, available at https://github.com/scanoss/minr

**Syntax**: scanoss [parameters] [TARGET]

Configuration:
~~~~~~~~~~~~~~

* ``-w`` Treats TARGET as a .wfp file regardless of the actual file extension
* ``-s FILE`` Use assets specified in the provided JSON SBOM (CycloneDX/SPDX2.2 JSON format) as input to identification
* ``-b FILE`` Ignore matches to assets specified in the provided JSON SBOM (CycloneDX/SPDX2.2 JSON format)

Options:
~~~~~~~~

* ``-t`` Tests engine performance
* ``-v`` Display version and exit
* ``-h`` Display this help and exit
* ``-d`` Enable debugging information

File matching logic
--------------------

The scanning engine attempts to match files with the following criteria:

Is the file matching an entire package?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

(matching directly the archive downloaded from the URL)

This produces an identification (id) of type "url"

Is the file matching an entire known file?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This produces an identification (id) of type "file"

Snippet comparison execution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Comparing snippet hashes produces an identification (id) of type "snippet"

If none of the above
~~~~~~~~~~~~~~~~~~~~

This produces an identification (id) of type "none"

File ranking algorithm
----------------------

Often, the SCANOSS engine finds files that are present in different components and versions, which triggers a series of functions to determine the best match. These functions are detailed below:

Component hint retrieval
~~~~~~~~~~~~~~~~~~~~~~~~

The scanning client can optionally pass a component hint (context). The context is the name of the last component detected. This context will influence results and the scanning engine will favour the files belonging to a component matching the provided context.

First component released
~~~~~~~~~~~~~~~~~~~~~~~~

If no hint is provided, the SCANOSS engine will look for the oldest component in the KB which matches the scanned file. In case of a tie between two components with the same release date, other available information will be used to select the best match.

SBOM Ingestion
~~~~~~~~~~~~~~

The user can use the "-s" optional argument plus a sbom.json. The engine will prioritize the declared components during the analysis. If a file cannot be matched against any declared component, then the logic previously explained will be applied.

License
-------

The Scanoss Open Source Engine is released under the GPL 2.0 license. Please check the LICENSE file for more information.

Copyright (C) 2018-2020 SCANOSS.COM