namespace VirusTotalScanner.Models;

public sealed class FileScanResult
{
	public string FullPath { get; set; } = string.Empty;
	public long SizeBytes { get; set; }
	public string SHA256 { get; set; } = string.Empty;
	public int TotalEngines { get; set; }
	public int Detections { get; set; }
	public string Threats { get; set; } = string.Empty;
	public bool HasDetections => Detections > 0;
}
