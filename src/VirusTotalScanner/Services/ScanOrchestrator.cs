using VirusTotalScanner.Models;
using VirusTotalScanner.Reporting;

namespace VirusTotalScanner.Services;

internal sealed class ScanOrchestrator : IScanOrchestrator
{
	private const long MaxFileSizeBytes = 650L * 1024 * 1024;

	private readonly IFileEnumerator _fileEnumerator;
	private readonly IFilePrioritizer _filePrioritizer;
	private readonly IFileHasher _fileHasher;
	private readonly IVirusTotalService _vtService;
	private readonly IConsoleReporter _reporter;

	public ScanOrchestrator(
		IFileEnumerator fileEnumerator,
		IFilePrioritizer filePrioritizer,
		IFileHasher fileHasher,
		IVirusTotalService vtService,
		IConsoleReporter reporter)
	{
		_fileEnumerator = fileEnumerator;
		_filePrioritizer = filePrioritizer;
		_fileHasher = fileHasher;
		_vtService = vtService;
		_reporter = reporter;
	}

	public async Task<List<FileScanResult>> ScanAsync(string path)
	{
		var files = _filePrioritizer.Prioritize(_fileEnumerator.EnumerateFiles(path));
		var results = new List<FileScanResult>();

		for (int i = 0; i < files.Count; i++)
		{
			var filePath = files[i];
			_reporter.ReportProgress(i + 1, files.Count, Path.GetFileName(filePath));

			try
			{
				var fileInfo = new FileInfo(filePath);

				if (fileInfo.Length > MaxFileSizeBytes)
				{
					results.Add(new FileScanResult
					{
						FullPath = filePath,
						SizeBytes = fileInfo.Length,
						Threats = "Skipped: file exceeds 650 MB VirusTotal limit"
					});
					_reporter.ReportSkipped(Path.GetFileName(filePath), "file exceeds 650 MB VirusTotal limit");
					continue;
				}

				var hash = await _fileHasher.ComputeSha256Async(filePath);

				var result = await _vtService.GetFileReportAsync(hash);

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
			catch (QuotaExceededException)
			{
				_reporter.ReportError("VirusTotal daily quota exceeded, skipping remaining files");

				for (int j = i; j < files.Count; j++)
				{
					var skippedPath = files[j];
					var skippedInfo = new FileInfo(skippedPath);
					results.Add(new FileScanResult
					{
						FullPath = skippedPath,
						SizeBytes = skippedInfo.Exists ? skippedInfo.Length : 0,
						Threats = "Skipped: VirusTotal daily quota exceeded"
					});
				}

				break;
			}
		}

		_reporter.ReportComplete(results.Count, results.Count(r => r.HasDetections));
		return results;
	}
}
