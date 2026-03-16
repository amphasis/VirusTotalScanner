using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

public interface IVirusTotalService
{
	Task<FileScanResult?> GetFileReportAsync(string sha256);
}
