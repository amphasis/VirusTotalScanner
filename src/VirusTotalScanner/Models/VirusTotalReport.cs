namespace VirusTotalScanner.Models;

public sealed class VirusTotalReport
{
	public string SHA256 { get; set; } = string.Empty;
	public int TotalEngines { get; set; }
	public int Detections { get; set; }
	public string Threats { get; set; } = string.Empty;
	public bool HasDetections => Detections > 0;
}
