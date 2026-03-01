using System.Text.Json.Serialization;

namespace VirusTotalScanner.Models;

public sealed class VirusTotalErrorResponse
{
	[JsonPropertyName("error")]
	public VtError? Error { get; set; }
}

public sealed class VtError
{
	[JsonPropertyName("code")]
	public string Code { get; set; } = string.Empty;

	[JsonPropertyName("message")]
	public string Message { get; set; } = string.Empty;
}
