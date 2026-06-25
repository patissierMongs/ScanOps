# Third Party Notices

This file summarizes third party software and assets used by ScanOps. It is
not a license grant for ScanOps itself.

## Application runtime dependencies

The frontend and backend dependencies used by this project are distributed
under permissive open source licenses:

### Frontend

- react 18.3.1: MIT
- react-dom 18.3.1: MIT
- xlsx 0.18.5 and bundled SheetJS support packages: Apache-2.0
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
