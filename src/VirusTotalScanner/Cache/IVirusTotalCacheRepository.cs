namespace VirusTotalScanner.Cache;

public interface IVirusTotalCacheRepository
{
	VirusTotalCacheEntry? FindByHash(string sha256);
	void Upsert(VirusTotalCacheEntry entry);
}
