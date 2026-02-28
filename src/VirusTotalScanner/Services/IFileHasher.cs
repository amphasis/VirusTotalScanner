namespace VirusTotalScanner.Services;

public interface IFileHasher
{
    Task<string> ComputeSha256Async(string filePath);
}
