# SCANOSS Open Source Inventory Engine

THE FIRST OPEN SOURCE INVENTORY ENGINE BUILT FOR DEVELOPERS

SCANOSS is an open, configurable OSS inventory engine that was built specifically for developers, empowering them to confidently produce compliant code from the moment they begin writing, while delivering greater license and usage visibility for the broader DevOps team and supply chain partners.

With its open architecture that is easy to integrate into existing processes and toolchains, SCANOSS transforms software bill of materials (SBOM) creation from ‘write now, audit later’ to an always-on analysis of live code.

By freeing developers to focus on writing great, compliant code that they and their team can completely trust, applications are finished earlier, quality is consistently higher, and development costs are dramatically lower.

# Setup 
The Scanoss engine requires a Knowledge database installed for retrieving results. Scanoss use the SCANOSS LDB (Linked-list database) as a shared library. LDB Source code and installation guide can be found on https://github.com/scanoss/ldb
The knowledge database is incrementally built using the SCANOSS mining tool (minr). It source code and installation guide can be found on https://github.com/scanoss/minr

# Installation

The SCANOSS Inventory Engine a command-line tool used for comparing a file or directory against the SCANOSS Knowledgebase. The source code can be downloaded and compiled as follows:

```
wget -O engine.zip https://github.com/scanoss/engine/archive/master.zip
unzip engine.zip
cd engine-master
make
sudo make install
cd ..
scanoss -v
```

If you want to try scanoss without install it, the execute this command in bash:
```
export LD_LIBRARY_PATH=.:$LD_LIBRARY_PATH
```

The last command should show the installed version of the SCANOSS Inventory Engine.

# Usage

This program performs an OSS inventory for the given TARGET comparing against the ScanOSS LDB Knowledgebase. Results are printed in STDOUT in JSON format.
You can create your own knowledgebase with the minr command, available at https://github.com/scanoss/minr

Syntax: scanoss [parameters] [TARGET]

Configuration:
* -w       Treats TARGET as a .wfp file regardless of the actual file extension
* -s FILE  Use assets specified in the provided JSON SBOM (CycloneDX/SPDX2.2 JSON format) as input to identification
* -b FILE  Blacklist matches to assets specified in the provided JSON SBOM (CycloneDX/SPDX2.2 JSON format)

Options:
* -t  Tests engine performance
* -v  Display version and exit
* -h  Display this help and exit
* -d  Enable debugging information

# File matching logic

The scanning engine attempts to match files with the following criteria:

## Is the file matching an entire package (matching directly the archive downloaded from the URL)?
This produces an identifycation (id) of type "url"

##Otherwise, is the file matching an entire known file?
This produces an identification (id) of type "file"

##Otherwise, snippet comparison is executed comparing snippet hashes
This produces an identification (id) of type "snippet"

## If none of the above,
This produces an identification (id) of type "none"

# File ranking algorithm

Often, the SCANOSS engine finds files that are present in different components and versions, which triggers a series of functions to determine the best match. These functions are detailed below:

## Component hint retrieval

The scanning client can optionally pass a a component hint (context). The context is the name of the last component detected. This context will influence results and the scanning engine will favour the files belonging to a component matching the provided context.

## Component hint calculation

If a component hint is not provided, the engine will try to attempt detection of a component hint by:

* Attempt to detect the component name by looking at the path. For example, looking after /vendor/ or /external/ in the file path, and looking for this component in the URLs that the file points to.
* Otherwise, attempt to detect a component name in the start of the path (i.e. linux-2.1/src), and comparing this component hint with the components in the URLs that the file points to.
* Otherwise, look for the shortest file path and search for the respective component name in the file path.
* Last, ignore the component hint and select the first file from the results list.

# License

The Scanoss Open Source Inventory Engine is released under the GPL 2.0 license. Please check the LICENSE file for more information.

Copyright (C) 2018-2020 SCANOSS.COM

