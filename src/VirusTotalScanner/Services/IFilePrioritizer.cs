namespace VirusTotalScanner.Services;

public interface IFilePrioritizer
{
	IReadOnlyList<string> Prioritize(IEnumerable<string> filePaths);
}
