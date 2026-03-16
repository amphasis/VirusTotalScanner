namespace VirusTotalScanner.Cache;

public interface IFileHashCacheRepository
{
	FileHashCacheEntry? FindByPath(string filePath);
	void Upsert(FileHashCacheEntry entry);
}
