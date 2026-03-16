using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

public interface IVirusTotalService
{
	Task<VirusTotalReport?> GetFileReportAsync(string sha256);
}
