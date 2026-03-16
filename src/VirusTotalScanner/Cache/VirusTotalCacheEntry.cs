using LiteDB;

namespace VirusTotalScanner.Cache;

public sealed class VirusTotalCacheEntry
{
	[BsonId]
	[BsonField("sha256")]
	public string SHA256 { get; set; } = string.Empty;

	[BsonField("createdAt")]
	public DateTime CreatedAt { get; set; }

	[BsonField("totalEngines")]
	public int TotalEngines { get; set; }

	[BsonField("detections")]
	public int Detections { get; set; }

	[BsonField("threats")]
	public List<string> Threats { get; set; } = [];

	[BsonField("notInDatabase")]
	public bool NotInDatabase { get; set; }
}
