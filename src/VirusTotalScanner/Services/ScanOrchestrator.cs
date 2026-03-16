using VirusTotalScanner.Cache;
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
	private readonly IVirusTotalClient _vtClient;
	private readonly IPendingAnalysisRepository _pendingAnalysisRepository;
	private readonly IConsoleReporter _reporter;
	private readonly ScanOptions _options;

	public ScanOrchestrator(
		IFileEnumerator fileEnumerator,
		IFilePrioritizer filePrioritizer,
		IFileHasher fileHasher,
		IVirusTotalService vtService,
		IVirusTotalClient vtClient,
		IPendingAnalysisRepository pendingAnalysisRepository,
		IConsoleReporter reporter,
		ScanOptions options)
	{
		_fileEnumerator = fileEnumerator;
		_filePrioritizer = filePrioritizer;
		_fileHasher = fileHasher;
		_vtService = vtService;
		_vtClient = vtClient;
		_pendingAnalysisRepository = pendingAnalysisRepository;
		_reporter = reporter;
		_options = options;
	}

	public async Task<List<FileScanResult>> ScanAsync(string path)
	{
		var files = _filePrioritizer.Prioritize(_fileEnumerator.EnumerateFiles(path));
		var results = new List<FileScanResult>();
		var pendingFiles = new List<PendingAnalysisEntry>();

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
				var report = await _vtService.GetFileReportAsync(hash);

				if (report != null)
				{
					var scanResult = new FileScanResult
					{
						FullPath = filePath,
						SizeBytes = fileInfo.Length,
						SHA256 = report.SHA256,
						TotalEngines = report.TotalEngines,
						Detections = report.Detections,
						Threats = report.Threats
					};

					if (scanResult.HasDetections)
						_reporter.ReportDetection(scanResult);
					else
						_reporter.ReportClean(scanResult);

					results.Add(scanResult);
					continue;
				}

				var pendingEntry = handleNotFound(filePath, fileInfo, hash, pendingFiles);
				if (pendingEntry != null)
					await handlePendingAnalysis(filePath, fileInfo, hash, pendingEntry, results, pendingFiles);
				else if (_options.UploadEnabled)
					await uploadFile(filePath, fileInfo, hash, results, pendingFiles);
				else
					addNotFoundResult(filePath, fileInfo, hash, results);
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

		if (pendingFiles.Count > 0)
		{
			var pollingResults = await pollPendingAnalyses(pendingFiles);
			results.AddRange(pollingResults);
		}

		_reporter.ReportComplete(results.Count, results.Count(r => r.HasDetections));
		return results;
	}

	private PendingAnalysisEntry? handleNotFound(string filePath, FileInfo fileInfo, string hash,
		List<PendingAnalysisEntry> pendingFiles)
	{
		return _pendingAnalysisRepository.FindByHash(hash);
	}

	private async Task handlePendingAnalysis(string filePath, FileInfo fileInfo, string hash,
		PendingAnalysisEntry pendingEntry, List<FileScanResult> results, List<PendingAnalysisEntry> pendingFiles)
	{
		try
		{
			var analysisReport = await _vtClient.GetAnalysisAsync(pendingEntry.AnalysisId);

			if (analysisReport != null)
			{
				_vtService.CacheReport(hash, analysisReport);
				_pendingAnalysisRepository.Remove(hash);

				var scanResult = new FileScanResult
				{
					FullPath = filePath,
					SizeBytes = fileInfo.Length,
					SHA256 = hash,
					TotalEngines = analysisReport.TotalEngines,
					Detections = analysisReport.Detections,
					Threats = analysisReport.Threats
				};

				if (scanResult.HasDetections)
					_reporter.ReportDetection(scanResult);
				else
					_reporter.ReportClean(scanResult);

				results.Add(scanResult);
			}
			else
			{
				pendingEntry.FilePath = filePath;
				pendingEntry.SizeBytes = fileInfo.Length;
				pendingFiles.Add(pendingEntry);
			}
		}
		catch (Exception ex) when (ex is not QuotaExceededException)
		{
			_reporter.ReportError($"Failed to check analysis for {Path.GetFileName(filePath)}: {ex.Message}");
			pendingEntry.FilePath = filePath;
			pendingEntry.SizeBytes = fileInfo.Length;
			pendingFiles.Add(pendingEntry);
		}
	}

	private async Task uploadFile(string filePath, FileInfo fileInfo, string hash,
		List<FileScanResult> results, List<PendingAnalysisEntry> pendingFiles)
	{
		var fileName = Path.GetFileName(filePath);
		try
		{
			_reporter.ReportUploading(fileName);
			var analysisId = await _vtService.UploadFileAsync(filePath);

			var entry = new PendingAnalysisEntry
			{
				SHA256 = hash,
				AnalysisId = analysisId,
				FilePath = filePath,
				SizeBytes = fileInfo.Length,
				UploadedAt = DateTime.UtcNow
			};

			_pendingAnalysisRepository.Upsert(entry);
			pendingFiles.Add(entry);
			_reporter.ReportUploaded(fileName);
		}
		catch (Exception ex) when (ex is not QuotaExceededException)
		{
			results.Add(new FileScanResult
			{
				FullPath = filePath,
				SizeBytes = fileInfo.Length,
				SHA256 = hash,
				Threats = $"Upload failed: {ex.Message}"
			});
			_reporter.ReportError($"Upload failed for {fileName}: {ex.Message}");
		}
	}

	private void addNotFoundResult(string filePath, FileInfo fileInfo, string hash,
		List<FileScanResult> results)
	{
		results.Add(new FileScanResult
		{
			FullPath = filePath,
			SizeBytes = fileInfo.Length,
			SHA256 = hash,
			Threats = "Not in VT database"
		});
		_reporter.ReportNotFound(Path.GetFileName(filePath));
	}

	private async Task<List<FileScanResult>> pollPendingAnalyses(List<PendingAnalysisEntry> pendingFiles)
	{
		_reporter.ReportPollingStart(pendingFiles.Count);

		var results = new List<FileScanResult>();
		var remaining = new List<PendingAnalysisEntry>(pendingFiles);
		var startTime = DateTime.UtcNow;
		int round = 0;

		while (remaining.Count > 0 && DateTime.UtcNow - startTime < _options.PollingTimeout)
		{
			round++;
			await Task.Delay(_options.PollingInterval);

			var stillPending = new List<PendingAnalysisEntry>();

			foreach (var entry in remaining)
			{
				try
				{
					var report = await _vtClient.GetAnalysisAsync(entry.AnalysisId);

					if (report != null)
					{
						_vtService.CacheReport(entry.SHA256, report);
						_pendingAnalysisRepository.Remove(entry.SHA256);

						var scanResult = new FileScanResult
						{
							FullPath = entry.FilePath,
							SizeBytes = entry.SizeBytes,
							SHA256 = entry.SHA256,
							TotalEngines = report.TotalEngines,
							Detections = report.Detections,
							Threats = report.Threats
						};

						if (scanResult.HasDetections)
							_reporter.ReportDetection(scanResult);
						else
							_reporter.ReportClean(scanResult);

						results.Add(scanResult);
					}
					else
					{
						stillPending.Add(entry);
					}
				}
				catch (QuotaExceededException)
				{
					foreach (var p in stillPending.Concat(remaining.SkipWhile(e => e != entry)))
					{
						results.Add(new FileScanResult
						{
							FullPath = p.FilePath,
							SizeBytes = p.SizeBytes,
							SHA256 = p.SHA256,
							Threats = "Skipped: VirusTotal daily quota exceeded"
						});
					}
					return results;
				}
				catch (Exception ex)
				{
					_reporter.ReportError($"Error polling analysis for {Path.GetFileName(entry.FilePath)}: {ex.Message}");
					stillPending.Add(entry);
				}
			}

			remaining = stillPending;
			_reporter.ReportPollingProgress(pendingFiles.Count - remaining.Count, pendingFiles.Count, round);
		}

		foreach (var entry in remaining)
		{
			results.Add(new FileScanResult
			{
				FullPath = entry.FilePath,
				SizeBytes = entry.SizeBytes,
				SHA256 = entry.SHA256,
				Threats = "Analysis timed out"
			});
			_reporter.ReportAnalysisTimeout(Path.GetFileName(entry.FilePath));
		}

		return results;
	}
}
