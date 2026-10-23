# GAP07 — Credential Exposure Audit Platform

Windows file-server credential audit (PowerShell, pure — zero dependencies). Version **v2.3.1**.

## What it does

Scans SMB shares / directories for:
- **Open-share ACL risks** (broad-group allow patterns, severity via `Get-ShareAclSeverity`)
- **Cleartext credentials** (multilingual regex: EN/FR/ES/PT/DE/IT/NL/TR)
- **Vault / key files** (`.kdbx`, `.pem`, `.pfx`, `.jks` — cert vs vault split)
- **Formula-injection-safe CSV** (`Escape-CsvField` with `'` prefix for `=+-@`)

Output per target: `1_open_shares.csv`, `2_credentials.csv`, `3_vaultfiles.csv`, `summary.txt`.

## Quick start

```powershell
# Automated
.\scan_credentials_v6.ps1 -Mode automated -ScanPath C:\Data -ConfigPath .\config.json -OutputPath .\results

# Interactive (discover → pick → scan)
.\scan_credentials_v6.ps1 -Mode interactive -OutputPath .\results
```

Config (`config.json`): `MaxFileSizeMB`, `MaxDepth`, `ThrottleMs`, `ExcludeSystemShares`, `ExcludeSystemPaths`, `ExcludeEncryptedFiles`, `ExcludeTempPaths`, `ScanDiscoveredShares`, `AdditionalScanPaths`.

## Architecture (5 phases)

1. **Discovery / ACL** (`Invoke-ShareDiscovery`, `Get-ShareAclSeverity`) — share-level permissions
2. **Content scan** (`Invoke-FullScan`, `Get-EligibleFiles`) — traverses excluding OS/system/temp/encrypted paths
3. **Vault detection** (`VaultExtSet` vs `CertExtSet`) — keys vs certificates
4. **Reporting / attribution** (`Distribute-Phase1Results`, `Test-PathUnderTarget`, `Get-CsvFieldValue`)
5. **Hygiene / summary** (`Write-SummaryFile`, UTF-8, versioned output)

Shared source of truth: `Get-ShareAclSeverity` (line 487). See `WIKI.md` for full docs (Mermaid diagrams, data model, API reference).

## Tutorial / docs

- `WIKI.md` — full codebase documentation (architecture, data flow, ER diagrams, development guide)
- `backup/scan_credentials.ps1` — original v2.1.0 baseline

## Remediation status

23 findings addressed across ordered phases (Critical → High → Medium → Low), verified via `Parser::ParseFile`. All commits pushed to `https://github.com/cromstel/gap07.git`.

## Safety notes

- No external dependencies; pure PowerShell
- No hardcoded secrets; config + env only
- CSV formula injection neutralized
- No mutation of shared state; immutable patterns (`Clone`, spread)
