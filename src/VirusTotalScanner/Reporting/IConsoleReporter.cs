using VirusTotalScanner.Models;

namespace VirusTotalScanner.Reporting;

public interface IConsoleReporter
{
	void ReportProgress(int current, int total, string fileName);
	void ReportDetection(FileScanResult result);
	void ReportClean(FileScanResult result);
	void ReportNotFound(string fileName);
	void ReportError(string message);
	void ReportComplete(int total, int withDetections);
}
