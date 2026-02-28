using System.Security.Cryptography;

namespace VirusTotalScanner.Services;

internal sealed class FileHasher : IFileHasher
{
	public async Task<string> ComputeSha256Async(string filePath)
	{
		using var stream = File.OpenRead(filePath);
		var hashBytes = await SHA256.HashDataAsync(stream);
		return Convert.ToHexString(hashBytes).ToLowerInvariant();
	}
}
