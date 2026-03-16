using LiteDB;
using VirusTotalScanner.Cache;

namespace VirusTotalScanner.Tests.Cache;

public sealed class PendingAnalysisRepositoryTests : IDisposable
{
	private readonly string _dbPath;
	private readonly ILiteDatabase _database;
	private readonly PendingAnalysisRepository _repository;

	public PendingAnalysisRepositoryTests()
	{
		_dbPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.db");
		_database = new LiteDatabase(_dbPath);
		_repository = new PendingAnalysisRepository(_database);
	}

	public void Dispose()
	{
		_database.Dispose();
		if (File.Exists(_dbPath))
			File.Delete(_dbPath);
	}

	[Fact]
	public void FindByHash_NoEntry_ReturnsNull()
	{
		var result = _repository.FindByHash("nonexistent");

		Assert.Null(result);
	}

	[Fact]
	public void Upsert_ThenFindByHash_ReturnsEntry()
	{
		var entry = new PendingAnalysisEntry
		{
			SHA256 = "abc123",
			AnalysisId = "analysis-1",
			FilePath = "/path/to/file.exe",
			SizeBytes = 1024,
			UploadedAt = DateTime.UtcNow
		};

		_repository.Upsert(entry);
		var result = _repository.FindByHash("abc123");

		Assert.NotNull(result);
		Assert.Equal("abc123", result.SHA256);
		Assert.Equal("analysis-1", result.AnalysisId);
		Assert.Equal("/path/to/file.exe", result.FilePath);
		Assert.Equal(1024, result.SizeBytes);
	}

	[Fact]
	public void Upsert_ExistingEntry_UpdatesEntry()
	{
		_repository.Upsert(new PendingAnalysisEntry
		{
			SHA256 = "abc123",
			AnalysisId = "analysis-1",
			FilePath = "/old/path.exe",
			SizeBytes = 1024
		});

		_repository.Upsert(new PendingAnalysisEntry
		{
			SHA256 = "abc123",
			AnalysisId = "analysis-2",
			FilePath = "/new/path.exe",
			SizeBytes = 2048
		});

		var result = _repository.FindByHash("abc123");

		Assert.NotNull(result);
		Assert.Equal("analysis-2", result.AnalysisId);
		Assert.Equal("/new/path.exe", result.FilePath);
	}

	[Fact]
	public void Remove_ExistingEntry_RemovesIt()
	{
		_repository.Upsert(new PendingAnalysisEntry
		{
			SHA256 = "abc123",
			AnalysisId = "analysis-1",
			FilePath = "/path.exe",
			SizeBytes = 1024
		});

		_repository.Remove("abc123");
		var result = _repository.FindByHash("abc123");

		Assert.Null(result);
	}

	[Fact]
	public void GetAll_ReturnsAllEntries()
	{
		_repository.Upsert(new PendingAnalysisEntry { SHA256 = "hash1", AnalysisId = "a1" });
		_repository.Upsert(new PendingAnalysisEntry { SHA256 = "hash2", AnalysisId = "a2" });
		_repository.Upsert(new PendingAnalysisEntry { SHA256 = "hash3", AnalysisId = "a3" });

		var all = _repository.GetAll();

		Assert.Equal(3, all.Count);
	}

	[Fact]
	public void GetAll_EmptyCollection_ReturnsEmpty()
	{
		var all = _repository.GetAll();

		Assert.Empty(all);
	}
}
