# VirusTotalScanner — Agent Rules

## Overview

.NET 8.0 CLI utility: scans files/directories, computes SHA-256 hashes, queries VirusTotal API v3, and exports results to CSV.

## Project Structure

```
src/VirusTotalScanner/
├── Program.cs                  — Entry point, DI setup, CLI parsing
├── Options.cs                  — CLI arguments (CommandLineParser)
├── appsettings.json            — Config (API key)
├── Models/
│   ├── FileScanResult.cs              — Result DTO (public sealed)
│   ├── VirusTotalResponse.cs          — API response DTO (public sealed, nested classes)
│   ├── VirusTotalUploadResponse.cs    — Upload API response DTO
│   └── VirusTotalAnalysisResponse.cs  — Analysis API response DTO
├── Cache/
│   ├── IVirusTotalCacheRepository.cs / VirusTotalCacheRepository.cs  — VT report cache (LiteDB)
│   ├── IFileHashCacheRepository.cs / FileHashCacheRepository.cs      — SHA-256 hash cache (LiteDB)
│   ├── IPendingAnalysisRepository.cs / PendingAnalysisRepository.cs  — Pending upload tracking (LiteDB)
│   ├── VirusTotalCacheEntry.cs        — VT cache entry model
│   ├── FileHashCacheEntry.cs          — Hash cache entry model
│   └── PendingAnalysisEntry.cs        — Pending analysis entry model (keyed by SHA256)
├── Services/
│   ├── IFileHasher.cs / FileHasher.cs           — SHA-256 hashing
│   ├── IFileEnumerator.cs / FileEnumerator.cs   — File/directory enumeration
│   ├── IVirusTotalClient.cs / VirusTotalClient.cs — VT API client (report, upload, analysis)
│   ├── IVirusTotalService.cs / VirusTotalService.cs — Caching layer over VT client
│   └── IScanOrchestrator.cs / ScanOrchestrator.cs — Two-phase scan workflow
└── Reporting/
    ├── IConsoleReporter.cs / ConsoleReporter.cs — Console output (colors, progress)
    └── ICsvExporter.cs / CsvExporter.cs         — CSV export (CsvHelper)

tests/VirusTotalScanner.Tests/
├── Cache/
│   ├── VirusTotalCacheRepositoryTests.cs  — VT cache CRUD
│   ├── FileHashCacheRepositoryTests.cs    — Hash cache CRUD
│   └── PendingAnalysisRepositoryTests.cs  — Pending analysis CRUD
├── Services/
│   ├── FileHasherTests.cs         — SHA-256 verification
│   ├── VirusTotalClientTests.cs   — API client (report, upload, analysis)
│   ├── VirusTotalServiceTests.cs  — Caching behavior
│   └── ScanOrchestratorTests.cs   — Two-phase workflow (all deps mocked)
└── Reporting/
    └── CsvExporterTests.cs        — CSV format verification
```

## Architecture

### Program Flow
1. Parse CLI args (`--path`, `--api-key`, `--output`, `--no-upload`) via CommandLineParser
2. Load config: CLI `--api-key` > `appsettings.json` > error
3. Register services as singletons in DI container (`Program.cs`)
4. `ScanOrchestrator.ScanAsync()` runs two phases:
   - **Phase 1**: enumerate files → hash → query VT API → if not found, check pending repo or upload → report
   - **Phase 2**: poll all pending analyses until completed or timeout (10 min)
5. Export results to CSV, optionally open file

### DI Registration (Program.cs)
All services registered as singletons. HttpClient configured with base address `https://www.virustotal.com/api/v3/` and `x-apikey` header.

### Key Behaviors
- **Retry logic**: Up to 3 retries with exponential backoff (2^attempt seconds)
- **HTTP 404**: File not in VT database → upload file (unless `--no-upload`) → poll for analysis
- **HTTP 429**: Rate limited → reactive retry with configurable delay (default 15s)
- **File upload**: Files ≤32 MB → `POST /files`; files >32 MB → `GET /files/upload_url` then POST
- **Large files**: Files >650 MB skipped (VirusTotal limit), no hashing or API call
- **Pending analyses**: Tracked in LiteDB by SHA256; reused across runs to avoid re-uploading
- **Analysis polling**: 15s between rounds, 10 min max timeout
- **Not-found caching**: Disabled — null API results are never cached
- **Errors**: UnauthorizedAccessException/IOException logged, scanning continues

## Codestyle

### Indentation
- Use **tabs** for indentation, not spaces
- Applies to all source files: `.cs`, `.csproj`, `.json`

### Access Modifiers
- Always **explicitly specify visibility** for all members (classes, methods, properties, fields)
- Use `internal` for **concrete class implementations** (not interfaces)
- Interfaces remain `public`
- Use `public` for models/DTOs that need to be accessible from tests
- All classes that are not intended to be inherited from must be **`sealed`**

### Naming Conventions
- **Private methods**: `camelCase` (e.g., `mapToResult`, `createClient`)
- **Public/internal methods**: `PascalCase`
- **Private fields**: `_camelCase` with underscore prefix
- **Constants**: `PascalCase`

### Dependency Injection
- Use **Microsoft.Extensions.DependencyInjection** container for service registration
- Register services in `Program.cs` via `ServiceCollection`

### Scope
- All codestyle rules apply equally to **src** and **tests** projects
- **Exception**: xUnit requires test classes to be `public`, so test classes use `public sealed`

### Project Structure
- Interfaces and implementations live in the same directory
- `InternalsVisibleTo` is configured for the test assembly so `internal` classes are testable

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| CommandLineParser | 2.9.1 | CLI argument parsing |
| CsvHelper | 33.1.0 | CSV export |
| Microsoft.Extensions.Configuration.Json | 10.0.3 | JSON config |
| Microsoft.Extensions.DependencyInjection | 10.0.3 | DI container |
| xunit | 2.5.3 | Test framework |
| Moq | 4.20.72 | Mocking |

## Testing Conventions

- **Framework**: xUnit + Moq
- **Naming**: `MethodName_Scenario_ExpectedResult()`
- **Test classes**: `public sealed class` (xUnit requirement)
- **Cleanup**: `IDisposable` for temp files/directories
- **Mocking**: Mock all dependencies except the SUT
- **Run tests**: `dotnet test` from solution root

## Build & Run

```bash
dotnet build                                    # Build all
dotnet test                                     # Run tests
dotnet run --project src/VirusTotalScanner -- --path <dir> --api-key <key>
```
