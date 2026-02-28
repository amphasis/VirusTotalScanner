namespace VirusTotalScanner.Services;

internal sealed class FileEnumerator : IFileEnumerator
{
	public IEnumerable<string> EnumerateFiles(string path)
	{
		if (File.Exists(path))
		{
			return [Path.GetFullPath(path)];
		}

		if (Directory.Exists(path))
		{
			return Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories);
		}

		throw new FileNotFoundException($"Path not found: {path}");
	}
}
