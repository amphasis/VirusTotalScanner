using LiteDB;

namespace VirusTotalScanner.Cache;

public sealed class FileHashCacheEntry
{
	[BsonId]
	[BsonField("filePath")]
	public string FilePath { get; set; } = string.Empty;

	[BsonField("sha256")]
	public string SHA256 { get; set; } = string.Empty;

	[BsonField("lastWriteTimeUtc")]
	public DateTime LastWriteTimeUtc { get; set; }

	[BsonField("fileSize")]
	public long FileSize { get; set; }
}
