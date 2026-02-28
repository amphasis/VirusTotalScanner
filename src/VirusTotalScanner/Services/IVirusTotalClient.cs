using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

public interface IVirusTotalClient
{
    Task<FileScanResult?> GetFileReportAsync(string sha256);
}
