using LiteDB;

namespace VirusTotalScanner.Cache;

internal sealed class PendingAnalysisRepository : IPendingAnalysisRepository
{
	private readonly ILiteCollection<PendingAnalysisEntry> _collection;

	public PendingAnalysisRepository(ILiteDatabase database)
	{
		_collection = database.GetCollection<PendingAnalysisEntry>("pendingAnalyses");
	}

	public PendingAnalysisEntry? FindByHash(string sha256)
	{
		return _collection.FindById(sha256);
	}

	public void Upsert(PendingAnalysisEntry entry)
	{
		_collection.Upsert(entry);
	}

	public void Remove(string sha256)
	{
		_collection.Delete(sha256);
	}

	public List<PendingAnalysisEntry> GetAll()
	{
		return _collection.FindAll().ToList();
	}
}
