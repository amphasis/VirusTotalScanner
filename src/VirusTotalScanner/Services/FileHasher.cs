using System.Security.Cryptography;
using VirusTotalScanner.Cache;

namespace VirusTotalScanner.Services;

internal sealed class FileHasher : IFileHasher
{
	private readonly IFileHashCacheRepository _cacheRepository;

	public FileHasher(IFileHashCacheRepository cacheRepository)
	{
		_cacheRepository = cacheRepository;
	}

	public async Task<string> ComputeSha256Async(string filePath)
	{
		var fileInfo = new FileInfo(filePath);
		var cached = _cacheRepository.FindByPath(filePath);

		if (cached != null
			&& cached.LastWriteTimeUtc == fileInfo.LastWriteTimeUtc
			&& cached.FileSize == fileInfo.Length)
		{
			return cached.SHA256;
		}

		await using var stream = File.OpenRead(filePath);
		var hashBytes = await SHA256.HashDataAsync(stream);
		var sha256 = Convert.ToHexString(hashBytes).ToLowerInvariant();

		_cacheRepository.Upsert(new FileHashCacheEntry
		{
			FilePath = filePath,
			SHA256 = sha256,
			LastWriteTimeUtc = fileInfo.LastWriteTimeUtc,
			FileSize = fileInfo.Length
		});

		return sha256;
	}
}
