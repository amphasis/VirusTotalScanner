using System.Text.Json.Serialization;

namespace VirusTotalScanner.Models;

public sealed class VirusTotalResponse
{
	[JsonPropertyName("data")]
	public VtData? Data { get; set; }
}

public sealed class VtData
{
	[JsonPropertyName("attributes")]
	public VtAttributes? Attributes { get; set; }
}

public sealed class VtAttributes
{
	[JsonPropertyName("last_analysis_stats")]
	public VtAnalysisStats? LastAnalysisStats { get; set; }

	[JsonPropertyName("last_analysis_results")]
	public Dictionary<string, VtEngineResult>? LastAnalysisResults { get; set; }
}

public sealed class VtAnalysisStats
{
	[JsonPropertyName("malicious")]
	public int Malicious { get; set; }

	[JsonPropertyName("suspicious")]
	public int Suspicious { get; set; }

	[JsonPropertyName("undetected")]
	public int Undetected { get; set; }

	[JsonPropertyName("harmless")]
	public int Harmless { get; set; }

	[JsonPropertyName("timeout")]
	public int Timeout { get; set; }

	[JsonPropertyName("confirmed-timeout")]
	public int ConfirmedTimeout { get; set; }

	[JsonPropertyName("failure")]
	public int Failure { get; set; }

	[JsonPropertyName("type-unsupported")]
	public int TypeUnsupported { get; set; }
}

public sealed class VtEngineResult
{
	[JsonPropertyName("category")]
	public string Category { get; set; } = string.Empty;

	[JsonPropertyName("engine_name")]
	public string EngineName { get; set; } = string.Empty;

	[JsonPropertyName("result")]
	public string? Result { get; set; }
}
