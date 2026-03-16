using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

public interface IVirusTotalClient
{
	Task<VirusTotalReport?> GetFileReportAsync(string sha256);
}
