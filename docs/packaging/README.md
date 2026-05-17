# Packaging

Native OS packages for unattended UEM deployment (Intune, JAMF, SCCM, etc.).

| Platform | Format | Status | Doc |
|---|---|---|---|
| Linux  | `.deb`, `.rpm` (amd64, arm64) | shipped | [`linux.md`](./linux.md) |
| macOS  | `.pkg` + `.mobileconfig`      | planned | _phase 2_ |
| Windows | MSI                           | planned | _phase 3_ |

Each phase covers silent install, service registration, OS trust-store integration, externalized configuration, and clean uninstall. Source under `packaging/<platform>/`.
