using LiteDB;
using VirusTotalScanner.Cache;

namespace VirusTotalScanner.Tests.Cache;

public sealed class FileHashCacheRepositoryTests : IDisposable
{
	private readonly string _dbPath;
	private readonly ILiteDatabase _database;
	private readonly FileHashCacheRepository _repository;

	public FileHashCacheRepositoryTests()
	{
		_dbPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.db");
		_database = new LiteDatabase(_dbPath);
		_repository = new FileHashCacheRepository(_database);
	}

	public void Dispose()
	{
		_database.Dispose();
		if (File.Exists(_dbPath))
			File.Delete(_dbPath);
	}

	[Fact]
	public void FindByPath_CacheMiss_ReturnsNull()
	{
		var result = _repository.FindByPath(@"C:\nonexistent\file.txt");

		Assert.Null(result);
	}

	[Fact]
	public void Upsert_ThenFindByPath_ReturnsEntry()
	{
		var entry = new FileHashCacheEntry
		{
			FilePath = @"C:\test\file.exe",
			SHA256 = "abc123",
			LastWriteTimeUtc = new DateTime(2026, 1, 15, 10, 30, 0, DateTimeKind.Utc),
			FileSize = 12345
		};

		_repository.Upsert(entry);
		var result = _repository.FindByPath(@"C:\test\file.exe");

		Assert.NotNull(result);
		Assert.Equal("abc123", result.SHA256);
		Assert.Equal(12345, result.FileSize);
		Assert.Equal(
			new DateTime(2026, 1, 15, 10, 30, 0, DateTimeKind.Utc),
			result.LastWriteTimeUtc.ToUniversalTime());
	}

	[Fact]
	public void Upsert_ExistingEntry_UpdatesEntry()
	{
		var entry = new FileHashCacheEntry
		{
			FilePath = @"C:\test\file.exe",
			SHA256 = "abc123",
			LastWriteTimeUtc = new DateTime(2026, 1, 15, 10, 30, 0, DateTimeKind.Utc),
			FileSize = 12345
		};
		_repository.Upsert(entry);

		var updated = new FileHashCacheEntry
		{
			FilePath = @"C:\test\file.exe",
			SHA256 = "def456",
			LastWriteTimeUtc = new DateTime(2026, 2, 20, 14, 0, 0, DateTimeKind.Utc),
			FileSize = 67890
		};
		_repository.Upsert(updated);

		var result = _repository.FindByPath(@"C:\test\file.exe");

		Assert.NotNull(result);
		Assert.Equal("def456", result.SHA256);
		Assert.Equal(67890, result.FileSize);
	}
}
