using System.Text.Json.Serialization;

namespace VirusTotalScanner.Models;

public sealed class VirusTotalUploadResponse
{
	[JsonPropertyName("data")]
	public VtUploadData? Data { get; set; }
}

public sealed class VtUploadData
{
	[JsonPropertyName("id")]
	public string Id { get; set; } = string.Empty;
}
