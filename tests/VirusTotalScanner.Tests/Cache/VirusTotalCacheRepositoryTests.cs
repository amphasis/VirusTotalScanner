using LiteDB;
using VirusTotalScanner.Cache;

namespace VirusTotalScanner.Tests.Cache;

public sealed class VirusTotalCacheRepositoryTests : IDisposable
{
	private readonly string _dbPath;
	private readonly ILiteDatabase _database;
	private readonly VirusTotalCacheRepository _repository;

	public VirusTotalCacheRepositoryTests()
	{
		_dbPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.db");
		_database = new LiteDatabase(_dbPath);
		_repository = new VirusTotalCacheRepository(_database);
	}

	public void Dispose()
	{
		_database.Dispose();
		if (File.Exists(_dbPath))
			File.Delete(_dbPath);
	}

	[Fact]
	public void FindByHash_CacheMiss_ReturnsNull()
	{
		var result = _repository.FindByHash("nonexistent_hash");

		Assert.Null(result);
	}

	[Fact]
	public void Upsert_ThenFindByHash_ReturnsEntry()
	{
		var entry = new VirusTotalCacheEntry
		{
			SHA256 = "abc123",
			CreatedAt = DateTime.UtcNow,
			TotalEngines = 70,
			Detections = 3,
			Threats = ["Trojan.Gen", "Malware.AI"],
			NotInDatabase = false
		};

		_repository.Upsert(entry);
		var result = _repository.FindByHash("abc123");

		Assert.NotNull(result);
		Assert.Equal("abc123", result.SHA256);
		Assert.Equal(70, result.TotalEngines);
		Assert.Equal(3, result.Detections);
		Assert.Equal(2, result.Threats.Count);
		Assert.Contains("Trojan.Gen", result.Threats);
		Assert.False(result.NotInDatabase);
	}

	[Fact]
	public void Upsert_ExistingEntry_UpdatesEntry()
	{
		var entry = new VirusTotalCacheEntry
		{
			SHA256 = "abc123",
			CreatedAt = DateTime.UtcNow.AddDays(-10),
			TotalEngines = 70,
			Detections = 3,
			Threats = ["Trojan.Gen"],
			NotInDatabase = false
		};
		_repository.Upsert(entry);

		var updated = new VirusTotalCacheEntry
		{
			SHA256 = "abc123",
			CreatedAt = DateTime.UtcNow,
			TotalEngines = 72,
			Detections = 0,
			Threats = [],
			NotInDatabase = false
		};
		_repository.Upsert(updated);

		var result = _repository.FindByHash("abc123");

		Assert.NotNull(result);
		Assert.Equal(72, result.TotalEngines);
		Assert.Equal(0, result.Detections);
		Assert.Empty(result.Threats);
	}
}
