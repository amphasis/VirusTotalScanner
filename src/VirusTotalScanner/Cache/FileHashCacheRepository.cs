using LiteDB;

namespace VirusTotalScanner.Cache;

internal sealed class FileHashCacheRepository : IFileHashCacheRepository
{
	private readonly ILiteCollection<FileHashCacheEntry> _collection;

	public FileHashCacheRepository(ILiteDatabase database)
	{
		_collection = database.GetCollection<FileHashCacheEntry>("fileHashCache");
	}

	public FileHashCacheEntry? FindByPath(string filePath)
	{
		return _collection.FindById(filePath);
	}

	public void Upsert(FileHashCacheEntry entry)
	{
		_collection.Upsert(entry);
	}
}
