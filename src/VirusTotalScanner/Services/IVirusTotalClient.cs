using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

public interface IVirusTotalClient
{
	Task<VirusTotalReport?> GetFileReportAsync(string sha256);
	Task<string> UploadFileAsync(string filePath);
	Task<VirusTotalReport?> GetAnalysisAsync(string analysisId);
}
