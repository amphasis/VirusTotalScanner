using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

public interface IScanOrchestrator
{
    Task<List<FileScanResult>> ScanAsync(string path);
}
