using VirusTotalScanner.Services;

namespace VirusTotalScanner.Tests.Services;

public class FileHasherTests
{
    [Fact]
    public async Task ComputeSha256Async_KnownContent_ReturnsExpectedHash()
    {
        var hasher = new FileHasher();
        var tempFile = Path.GetTempFileName();

        try
        {
            // "hello" SHA-256 = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
            await File.WriteAllTextAsync(tempFile, "hello");
            var hash = await hasher.ComputeSha256Async(tempFile);
            Assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ComputeSha256Async_EmptyFile_ReturnsEmptyFileHash()
    {
        var hasher = new FileHasher();
        var tempFile = Path.GetTempFileName();

        try
        {
            // Empty file SHA-256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            var hash = await hasher.ComputeSha256Async(tempFile);
            Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }
}
