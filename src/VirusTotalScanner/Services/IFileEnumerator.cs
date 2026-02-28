namespace VirusTotalScanner.Services;

public interface IFileEnumerator
{
    IEnumerable<string> EnumerateFiles(string path);
}
