using VirusTotalScanner.Cache;
using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

internal sealed class VirusTotalService : IVirusTotalService
{
	private static readonly TimeSpan CleanTtl = TimeSpan.FromDays(30);
	private static readonly TimeSpan DetectionTtl = TimeSpan.FromDays(7);

	private readonly IVirusTotalCacheRepository _cacheRepository;
	private readonly IVirusTotalClient _vtClient;

	public VirusTotalService(IVirusTotalCacheRepository cacheRepository, IVirusTotalClient vtClient)
	{
		_cacheRepository = cacheRepository;
		_vtClient = vtClient;
	}

	public async Task<VirusTotalReport?> GetFileReportAsync(string sha256)
	{
		var cached = _cacheRepository.FindByHash(sha256);

		if (cached != null && !isExpired(cached))
			return mapFromCache(cached);

		var result = await _vtClient.GetFileReportAsync(sha256);
		saveToCache(sha256, result);
		return result;
	}

	private static bool isExpired(VirusTotalCacheEntry entry)
	{
		if (entry.NotInDatabase)
			return true;

		var ttl = entry.Detections > 0 ? DetectionTtl : CleanTtl;

		return DateTime.UtcNow - entry.CreatedAt > ttl;
	}

	private static VirusTotalReport? mapFromCache(VirusTotalCacheEntry entry)
	{
		if (entry.NotInDatabase)
			return null;

		return new VirusTotalReport
		{
			SHA256 = entry.SHA256,
			TotalEngines = entry.TotalEngines,
			Detections = entry.Detections,
			Threats = string.Join(", ", entry.Threats)
		};
	}

	public async Task<string> UploadFileAsync(string filePath)
	{
		return await _vtClient.UploadFileAsync(filePath);
	}

	public void CacheReport(string sha256, VirusTotalReport report)
	{
		saveToCache(sha256, report);
	}

	private void saveToCache(string sha256, VirusTotalReport? result)
	{
		if (result == null)
			return;

		var entry = new VirusTotalCacheEntry
		{
			SHA256 = sha256,
			CreatedAt = DateTime.UtcNow,
			TotalEngines = result.TotalEngines,
			Detections = result.Detections,
			Threats = string.IsNullOrEmpty(result.Threats)
				? []
				: result.Threats.Split(", ").ToList()
		};

		_cacheRepository.Upsert(entry);
	}
}
