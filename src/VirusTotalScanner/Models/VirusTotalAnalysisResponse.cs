using System.Text.Json.Serialization;

namespace VirusTotalScanner.Models;

public sealed class VirusTotalAnalysisResponse
{
	[JsonPropertyName("data")]
	public VtAnalysisData? Data { get; set; }
}

public sealed class VtAnalysisData
{
	[JsonPropertyName("attributes")]
	public VtAnalysisAttributes? Attributes { get; set; }
}

public sealed class VtAnalysisAttributes
{
	[JsonPropertyName("status")]
	public string Status { get; set; } = string.Empty;

	[JsonPropertyName("stats")]
	public VtAnalysisStats? Stats { get; set; }

	[JsonPropertyName("results")]
	public Dictionary<string, VtEngineResult>? Results { get; set; }
}
