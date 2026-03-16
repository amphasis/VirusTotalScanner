using Moq;
using VirusTotalScanner.Cache;
using VirusTotalScanner.Services;

namespace VirusTotalScanner.Tests.Services;

public sealed class FileHasherTests : IDisposable
{
	private readonly Mock<IFileHashCacheRepository> _cacheRepository = new();
	private readonly FileHasher _hasher;
	private readonly string _tempDir;

	public FileHasherTests()
	{
		_hasher = new FileHasher(_cacheRepository.Object);
		_tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
		Directory.CreateDirectory(_tempDir);
	}

	public void Dispose()
	{
		if (Directory.Exists(_tempDir))
			Directory.Delete(_tempDir, true);
	}

	[Fact]
	public async Task ComputeSha256Async_KnownContent_ReturnsExpectedHash()
	{
		var tempFile = Path.Combine(_tempDir, "hello.txt");
		// "hello" SHA-256 = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
		await File.WriteAllTextAsync(tempFile, "hello");

		var hash = await _hasher.ComputeSha256Async(tempFile);

		Assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash);
	}

	[Fact]
	public async Task ComputeSha256Async_EmptyFile_ReturnsEmptyFileHash()
	{
		var tempFile = Path.Combine(_tempDir, "empty.txt");
		await File.WriteAllBytesAsync(tempFile, []);
		// Empty file SHA-256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

		var hash = await _hasher.ComputeSha256Async(tempFile);

		Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
	}

	[Fact]
	public async Task ComputeSha256Async_CacheHit_Valid_ReturnsCachedHash()
	{
		var tempFile = Path.Combine(_tempDir, "test.exe");
		File.WriteAllText(tempFile, "content");
		var fileInfo = new FileInfo(tempFile);

		_cacheRepository.Setup(r => r.FindByPath(tempFile)).Returns(new FileHashCacheEntry
		{
			FilePath = tempFile,
			SHA256 = "cached_hash",
			LastWriteTimeUtc = fileInfo.LastWriteTimeUtc,
			FileSize = fileInfo.Length
		});

		var result = await _hasher.ComputeSha256Async(tempFile);

		Assert.Equal("cached_hash", result);
		_cacheRepository.Verify(r => r.Upsert(It.IsAny<FileHashCacheEntry>()), Times.Never);
	}

	[Fact]
	public async Task ComputeSha256Async_CacheHit_LastWriteTimeMismatch_Recomputes()
	{
		var tempFile = Path.Combine(_tempDir, "test.exe");
		File.WriteAllText(tempFile, "content");
		var fileInfo = new FileInfo(tempFile);

		_cacheRepository.Setup(r => r.FindByPath(tempFile)).Returns(new FileHashCacheEntry
		{
			FilePath = tempFile,
			SHA256 = "old_hash",
			LastWriteTimeUtc = fileInfo.LastWriteTimeUtc.AddSeconds(-1),
			FileSize = fileInfo.Length
		});

		var result = await _hasher.ComputeSha256Async(tempFile);

		Assert.NotEqual("old_hash", result);
		_cacheRepository.Verify(r => r.Upsert(It.Is<FileHashCacheEntry>(e =>
			e.FilePath == tempFile && e.SHA256 == result)), Times.Once);
	}

	[Fact]
	public async Task ComputeSha256Async_CacheHit_FileSizeMismatch_Recomputes()
	{
		var tempFile = Path.Combine(_tempDir, "test.exe");
		File.WriteAllText(tempFile, "content");
		var fileInfo = new FileInfo(tempFile);

		_cacheRepository.Setup(r => r.FindByPath(tempFile)).Returns(new FileHashCacheEntry
		{
			FilePath = tempFile,
			SHA256 = "old_hash",
			LastWriteTimeUtc = fileInfo.LastWriteTimeUtc,
			FileSize = fileInfo.Length + 100
		});

		var result = await _hasher.ComputeSha256Async(tempFile);

		Assert.NotEqual("old_hash", result);
		_cacheRepository.Verify(r => r.Upsert(It.Is<FileHashCacheEntry>(e =>
			e.FilePath == tempFile && e.SHA256 == result)), Times.Once);
	}

	[Fact]
	public async Task ComputeSha256Async_CacheMiss_ComputesAndSaves()
	{
		var tempFile = Path.Combine(_tempDir, "test.exe");
		File.WriteAllText(tempFile, "content");
		var fileInfo = new FileInfo(tempFile);

		var result = await _hasher.ComputeSha256Async(tempFile);

		Assert.NotEmpty(result);
		_cacheRepository.Verify(r => r.Upsert(It.Is<FileHashCacheEntry>(e =>
			e.FilePath == tempFile &&
			e.SHA256 == result &&
			e.LastWriteTimeUtc == fileInfo.LastWriteTimeUtc &&
			e.FileSize == fileInfo.Length)), Times.Once);
	}
}
