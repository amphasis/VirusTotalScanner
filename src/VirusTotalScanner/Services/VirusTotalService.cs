using VirusTotalScanner.Cache;
using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

internal sealed class VirusTotalService : IVirusTotalService
{
	private static readonly TimeSpan CleanTtl = TimeSpan.FromDays(30);
	private static readonly TimeSpan NotFoundTtl = TimeSpan.FromDays(1);
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
		var ttl = entry.NotInDatabase ? NotFoundTtl
			: entry.Detections > 0 ? DetectionTtl
			: CleanTtl;

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

	private void saveToCache(string sha256, VirusTotalReport? result)
	{
		var entry = new VirusTotalCacheEntry
		{
			SHA256 = sha256,
			CreatedAt = DateTime.UtcNow,
		};

		if (result == null)
		{
			entry.NotInDatabase = true;
		}
		else
		{
			entry.TotalEngines = result.TotalEngines;
			entry.Detections = result.Detections;
			entry.Threats = string.IsNullOrEmpty(result.Threats)
				? []
				: result.Threats.Split(", ").ToList();
		}

		_cacheRepository.Upsert(entry);
	}
}
