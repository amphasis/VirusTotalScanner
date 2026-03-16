using LiteDB;

namespace VirusTotalScanner.Cache;

public sealed class PendingAnalysisEntry
{
	[BsonId]
	[BsonField("sha256")]
	public string SHA256 { get; set; } = string.Empty;

	[BsonField("analysisId")]
	public string AnalysisId { get; set; } = string.Empty;

	[BsonField("filePath")]
	public string FilePath { get; set; } = string.Empty;

	[BsonField("sizeBytes")]
	public long SizeBytes { get; set; }

	[BsonField("uploadedAt")]
	public DateTime UploadedAt { get; set; }
}
