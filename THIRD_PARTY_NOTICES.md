# Third Party Notices

This file summarizes third party software and assets used by ScanOps. It is
not a license grant for ScanOps itself.

## Application runtime dependencies

The frontend and backend dependencies used by this project are distributed
under permissive open source licenses:

### Frontend

- react 18.3.1: MIT
- react-dom 18.3.1: MIT
- SheetJS Community Edition 0.20.3 (vendored `xlsx` package): Apache-2.0
- Vite build tooling and related bundled packages: MIT, Apache-2.0, ISC,
  BSD-3-Clause, and CC-BY-4.0

### Backend

- annotated-types 0.7.0: MIT
- anyio 4.14.0: MIT
- click 8.4.1: BSD-3-Clause
- colorama 0.4.6: BSD
- et_xmlfile 2.0.0: MIT
- exceptiongroup 1.3.1: MIT
- fastapi 0.115.6: MIT
- greenlet 3.5.1: MIT AND PSF-2.0
- h11 0.16.0: MIT
- idna 3.18: BSD-3-Clause
- openpyxl 3.1.5: MIT
- pydantic 2.10.4: MIT
- pydantic-core 2.27.2: MIT
- pydantic-settings 2.7.1: MIT
- python-dotenv 1.2.2: BSD-3-Clause
- python-multipart 0.0.20: Apache-2.0
- SQLAlchemy 2.0.36: MIT
- starlette 0.41.3: BSD-3-Clause
- typing-extensions 4.15.0: PSF-2.0
- uvicorn 0.34.0: BSD-3-Clause

## Fonts

ScanOps bundles IBM Plex Sans and IBM Plex Mono web fonts.

- Copyright 2017 IBM Corp. with Reserved Font Name "Plex"
- License: SIL Open Font License, Version 1.1

The OFL permits the fonts to be bundled, embedded, redistributed, and sold with
software, provided the required copyright and license notices are preserved and
the fonts are not sold by themselves.

## Optional embedded Python bundle

The all-in-one package builder may include the Windows embeddable distribution
of Python 3.12.8. Python is distributed by the Python Software Foundation under
the Python Software Foundation License and related historical open source
licenses. The embedded Python archive contains its own LICENSE.txt.

## External tools not bundled

ScanOps can execute Nmap when it is installed separately on the target system.
The standard ScanOps packages do not bundle Nmap or Npcap. Nmap is governed by
the Nmap Public Source License or by separate written license terms obtained
from the Nmap Project.

## Development and sample-only services

The Docker Compose files under lab/ and live_sample/ reference public container
images for local testing only. They are not part of the ScanOps application
runtime package unless a distributor intentionally ships those sample services.
# SheetJS Community Edition

- Version: 0.20.3
- Source: `https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz`
- Vendored file: `frontend/vendor/xlsx-0.20.3.tgz`
- SHA-256: `8DC73FC3B00203E72D176E85B50938627C7B086E607C682E8D3C22C02BB99FE8`
- License: Apache-2.0

## Vendored SheetJS update and air-gapped verification

1. On a connected, controlled build workstation, download the release archive only from the
   corresponding versioned `cdn.sheetjs.com` release URL. For a version change, use a new
   versioned filename, update the `file:vendor/...` dependency in `frontend/package.json`, and
   regenerate `frontend/package-lock.json` with
   `npm install --package-lock-only --ignore-scripts`.
2. Calculate SHA-256 and inspect the archive metadata and license before accepting it. Update
   the version, source URL, vendored path, hash, and license in this notice together.

   ```powershell
   $sheetjsArchive = "frontend/vendor/xlsx-0.20.3.tgz"
   (Get-FileHash -Algorithm SHA256 -LiteralPath $sheetjsArchive).Hash
   tar -xOf $sheetjsArchive package/package.json
   tar -xOf $sheetjsArchive package/LICENSE
   ```

3. On the connected build workstation, run `npm ci`, `npm test`,
   `npm audit --omit=dev --audit-level=moderate`, `npm audit --audit-level=moderate`, and
   `npm run build` from `frontend/`. Commit the versioned archive, package and lock files,
   this notice, tests, and rebuilt `frontend/dist/` together.
4. After transfer into the air-gapped environment, independently repeat the SHA-256 and
   archive metadata/license commands and compare them with this notice. The deployed ScanOps
   runtime uses the prebuilt `frontend/dist/` and does not require Node.js. If the frontend
   must be rebuilt inside the air gap, transfer a separately verified npm cache and use
   `npm ci --offline`; do not allow a registry fallback.
