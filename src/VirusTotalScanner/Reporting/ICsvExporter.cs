using VirusTotalScanner.Models;

namespace VirusTotalScanner.Reporting;

public interface ICsvExporter
{
	void Export(List<FileScanResult> results, string outputPath);
}
