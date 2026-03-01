# VirusTotalScanner

A .NET 8.0 CLI utility that scans files and directories by computing SHA-256 hashes, querying the [VirusTotal API v3](https://docs.virustotal.com/reference/overview), and exporting results to CSV.

## Features

- **Recursive directory scanning** — point at a single file or an entire directory tree
- **File prioritization** — executables and scripts are scanned first, archives and documents follow
- **Smart rate-limit handling** — exponential backoff on transient errors; distinguishes per-minute rate limits from daily quota exhaustion
- **Large file detection** — files over 650 MB are skipped automatically (VirusTotal limit)
- **Color-coded console output** — red for detections, yellow for files not in the VT database
- **CSV export** — results saved with timestamps, optionally opened in the default viewer

## Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later
- A [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) (free tier works)

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/<owner>/VirusTotalScanner.git
cd VirusTotalScanner
```

### 2. Configure the API key

Copy the example config and insert your key:

```bash
cp src/VirusTotalScanner/appsettings.example.json src/VirusTotalScanner/appsettings.json
```

Edit `appsettings.json`:

```json
{
  "VirusTotal": {
    "ApiKey": "your_api_key_here"
  }
}
```

Alternatively, pass the key via the `--api-key` CLI flag (overrides the config file).

### 3. Build

```bash
dotnet build
```

### 4. Run

```bash
dotnet run --project src/VirusTotalScanner -- --path <file-or-directory> [options]
```

## Usage

```
  -p, --path       Required. Path to a file or directory to scan.
  -k, --api-key    VirusTotal API key (overrides appsettings.json).
  -o, --output     Output CSV file path (default: scan_results_<timestamp>.csv).
```

### Examples

Scan a directory:

```bash
dotnet run --project src/VirusTotalScanner -- --path C:\Downloads
```

Scan a single file with an inline API key and custom output path:

```bash
dotnet run --project src/VirusTotalScanner -- \
  --path report.exe \
  --api-key YOUR_KEY \
  --output results.csv
```

## Project Structure

```
src/VirusTotalScanner/
├── Program.cs                  — Entry point, DI setup, CLI parsing
├── Options.cs                  — CLI arguments (CommandLineParser)
├── appsettings.json            — Config (API key, git-ignored)
├── Models/
│   ├── FileScanResult.cs       — Scan result DTO
│   ├── VirusTotalResponse.cs   — API response mapping
│   └── VirusTotalErrorResponse.cs
├── Services/
│   ├── FileHasher.cs           — Async SHA-256 hashing
│   ├── FileEnumerator.cs       — Recursive file enumeration
│   ├── FilePrioritizer.cs      — Risk-based file sorting
│   ├── VirusTotalClient.cs     — VT API v3 client with retry logic
│   ├── ScanOrchestrator.cs     — Main scan workflow
│   └── QuotaExceededException.cs
└── Reporting/
    ├── ConsoleReporter.cs      — Color-coded console output
    └── CsvExporter.cs          — CSV export (CsvHelper)

tests/VirusTotalScanner.Tests/  — xUnit + Moq tests
```

## How It Works

1. **Parse CLI arguments** — `--path`, `--api-key`, `--output` via CommandLineParser
2. **Enumerate files** — single file or recursive directory traversal
3. **Prioritize** — sort by risk level (executables > scripts > documents > archives > other)
4. **Hash** — compute SHA-256 for each file asynchronously
5. **Query VirusTotal** — `GET /files/{sha256}` with retry on 429
6. **Report** — print detections to the console in real time
7. **Export** — write all results to a CSV file

### Rate Limiting

| Scenario | Behavior |
|----------|----------|
| HTTP 429 (per-minute limit) | Waits 15 seconds, then retries (up to 3 times) |
| Quota exceeded (daily limit) | Stops scanning, marks remaining files as skipped |
| Other HTTP errors | Retries with exponential backoff (2, 4, 8 seconds) |

## Running Tests

```bash
dotnet test
```

Tests cover hashing, API client retry logic, orchestrator workflow, file prioritization, and CSV export.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
