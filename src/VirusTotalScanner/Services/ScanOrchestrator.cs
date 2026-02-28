using VirusTotalScanner.Models;
using VirusTotalScanner.Reporting;

namespace VirusTotalScanner.Services;

internal sealed class ScanOrchestrator : IScanOrchestrator
{
	private readonly IFileEnumerator _fileEnumerator;
	private readonly IFileHasher _fileHasher;
	private readonly IVirusTotalClient _vtClient;
	private readonly IConsoleReporter _reporter;

	public ScanOrchestrator(
		IFileEnumerator fileEnumerator,
		IFileHasher fileHasher,
		IVirusTotalClient vtClient,
		IConsoleReporter reporter)
	{
		_fileEnumerator = fileEnumerator;
		_fileHasher = fileHasher;
		_vtClient = vtClient;
		_reporter = reporter;
	}

	public async Task<List<FileScanResult>> ScanAsync(string path)
	{
		var files = _fileEnumerator.EnumerateFiles(path).ToList();
		var results = new List<FileScanResult>();

		for (int i = 0; i < files.Count; i++)
		{
			var filePath = files[i];
			_reporter.ReportProgress(i + 1, files.Count, Path.GetFileName(filePath));

			try
			{
				var hash = await _fileHasher.ComputeSha256Async(filePath);
				var fileInfo = new FileInfo(filePath);

				var result = await _vtClient.GetFileReportAsync(hash);

				if (result == null)
				{
					result = new FileScanResult
					{
						FullPath = filePath,
						SizeBytes = fileInfo.Length,
						SHA256 = hash,
						Threats = "Not in VT database"
					};
					_reporter.ReportNotFound(Path.GetFileName(filePath));
				}
				else
				{
					result.FullPath = filePath;
					result.SizeBytes = fileInfo.Length;

					if (result.HasDetections)
						_reporter.ReportDetection(result);
					else
						_reporter.ReportClean(result);
				}

				results.Add(result);
			}
			catch (UnauthorizedAccessException)
			{
				_reporter.ReportError($"Access denied: {filePath}");
			}
			catch (IOException ex)
			{
				_reporter.ReportError($"IO error for {filePath}: {ex.Message}");
			}
		}

		_reporter.ReportComplete(results.Count, results.Count(r => r.HasDetections));
		return results;
	}
}
