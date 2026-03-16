using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

public interface IVirusTotalService
{
	Task<VirusTotalReport?> GetFileReportAsync(string sha256);
	Task<string> UploadFileAsync(string filePath);
	void CacheReport(string sha256, VirusTotalReport report);
}
