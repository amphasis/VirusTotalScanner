namespace VirusTotalScanner.Cache;

public interface IPendingAnalysisRepository
{
	PendingAnalysisEntry? FindByHash(string sha256);
	void Upsert(PendingAnalysisEntry entry);
	void Remove(string sha256);
	List<PendingAnalysisEntry> GetAll();
}
