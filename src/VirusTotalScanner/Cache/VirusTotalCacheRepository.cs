using LiteDB;

namespace VirusTotalScanner.Cache;

internal sealed class VirusTotalCacheRepository : IVirusTotalCacheRepository
{
	private readonly ILiteCollection<VirusTotalCacheEntry> _collection;

	public VirusTotalCacheRepository(ILiteDatabase database)
	{
		_collection = database.GetCollection<VirusTotalCacheEntry>("virusTotalCache");
	}

	public VirusTotalCacheEntry? FindByHash(string sha256)
	{
		return _collection.FindById(sha256);
	}

	public void Upsert(VirusTotalCacheEntry entry)
	{
		_collection.Upsert(entry);
	}
}
