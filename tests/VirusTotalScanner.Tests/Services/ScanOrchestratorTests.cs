using Moq;
using VirusTotalScanner.Cache;
using VirusTotalScanner.Models;
using VirusTotalScanner.Reporting;
using VirusTotalScanner.Services;

namespace VirusTotalScanner.Tests.Services;

public sealed class ScanOrchestratorTests : IDisposable
{
	private readonly Mock<IFileEnumerator> _fileEnumerator = new();
	private readonly Mock<IFilePrioritizer> _filePrioritizer = new();
	private readonly Mock<IFileHasher> _fileHasher = new();
	private readonly Mock<IVirusTotalService> _vtService = new();
	private readonly Mock<IVirusTotalClient> _vtClient = new();
	private readonly Mock<IPendingAnalysisRepository> _pendingAnalysisRepository = new();
	private readonly Mock<IConsoleReporter> _reporter = new();
	private readonly string _tempDir;

	public ScanOrchestratorTests()
	{
		_filePrioritizer
			.Setup(p => p.Prioritize(It.IsAny<IEnumerable<string>>()))
			.Returns((IEnumerable<string> paths) => paths.ToList());

		_tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
		Directory.CreateDirectory(_tempDir);
	}

	public void Dispose()
	{
		if (Directory.Exists(_tempDir))
			Directory.Delete(_tempDir, true);
	}

	private ScanOrchestrator createOrchestrator(bool uploadEnabled = true)
	{
		var options = new ScanOptions
		{
			UploadEnabled = uploadEnabled,
			PollingInterval = TimeSpan.Zero
		};

		return new ScanOrchestrator(
			_fileEnumerator.Object,
			_filePrioritizer.Object,
			_fileHasher.Object,
			_vtService.Object,
			_vtClient.Object,
			_pendingAnalysisRepository.Object,
			_reporter.Object,
			options);
	}

	[Fact]
	public async Task ScanAsync_MixedResults_ReturnsAllResults()
	{
		var file1 = Path.Combine(_tempDir, "file1.exe");
		var file2 = Path.Combine(_tempDir, "file2.dll");
		var file3 = Path.Combine(_tempDir, "file3.txt");
		File.WriteAllText(file1, "content1");
		File.WriteAllText(file2, "content2");
		File.WriteAllText(file3, "content3");

		var files = new[] { file1, file2, file3 };
		_fileEnumerator.Setup(f => f.EnumerateFiles("testdir")).Returns(files);

		_fileHasher.Setup(h => h.ComputeSha256Async(file1)).ReturnsAsync("hash1");
		_fileHasher.Setup(h => h.ComputeSha256Async(file2)).ReturnsAsync("hash2");
		_fileHasher.Setup(h => h.ComputeSha256Async(file3)).ReturnsAsync("hash3");

		_vtService.Setup(c => c.GetFileReportAsync("hash1")).ReturnsAsync(new VirusTotalReport
		{
			SHA256 = "hash1",
			TotalEngines = 70,
			Detections = 5,
			Threats = "Engine1: Trojan.Gen"
		});
		_vtService.Setup(c => c.GetFileReportAsync("hash2")).ReturnsAsync(new VirusTotalReport
		{
			SHA256 = "hash2",
			TotalEngines = 70,
			Detections = 0,
			Threats = ""
		});
		_vtService.Setup(c => c.GetFileReportAsync("hash3")).ReturnsAsync((VirusTotalReport?)null);

		// file3 not found → upload → returns analysis ID
		_vtService.Setup(c => c.UploadFileAsync(file3)).ReturnsAsync("analysis-id-3");

		// polling phase: analysis completes
		_vtClient.Setup(c => c.GetAnalysisAsync("analysis-id-3")).ReturnsAsync(new VirusTotalReport
		{
			SHA256 = "hash3",
			TotalEngines = 70,
			Detections = 0,
			Threats = ""
		});

		var orchestrator = createOrchestrator();
		var results = await orchestrator.ScanAsync("testdir");

		Assert.Equal(3, results.Count);
		Assert.True(results[0].HasDetections);
		Assert.False(results[1].HasDetections);
		Assert.Equal("hash3", results[2].SHA256);
		Assert.False(results[2].HasDetections);

		_reporter.Verify(r => r.ReportProgress(It.IsAny<int>(), 3, It.IsAny<string>()), Times.Exactly(3));
		_reporter.Verify(r => r.ReportDetection(It.IsAny<FileScanResult>()), Times.Once);
		_reporter.Verify(r => r.ReportUploaded(It.IsAny<string>()), Times.Once);
		_pendingAnalysisRepository.Verify(r => r.Upsert(It.Is<PendingAnalysisEntry>(
			e => e.SHA256 == "hash3" && e.AnalysisId == "analysis-id-3")), Times.Once);
		_vtService.Verify(c => c.CacheReport("hash3", It.IsAny<VirusTotalReport>()), Times.Once);
	}

	[Fact]
	public async Task ScanAsync_NoUpload_ReturnsNotFound()
	{
		var file1 = Path.Combine(_tempDir, "file1.exe");
		File.WriteAllText(file1, "content1");

		_fileEnumerator.Setup(f => f.EnumerateFiles("testdir")).Returns(new[] { file1 });
		_fileHasher.Setup(h => h.ComputeSha256Async(file1)).ReturnsAsync("hash1");
		_vtService.Setup(c => c.GetFileReportAsync("hash1")).ReturnsAsync((VirusTotalReport?)null);

		var orchestrator = createOrchestrator(uploadEnabled: false);
		var results = await orchestrator.ScanAsync("testdir");

		Assert.Single(results);
		Assert.Equal("Not in VT database", results[0].Threats);
		_reporter.Verify(r => r.ReportNotFound(It.IsAny<string>()), Times.Once);
		_vtService.Verify(c => c.UploadFileAsync(It.IsAny<string>()), Times.Never);
	}

	[Fact]
	public async Task ScanAsync_PendingAnalysisFromPreviousRun_PollsExistingAnalysis()
	{
		var file1 = Path.Combine(_tempDir, "file1.exe");
		File.WriteAllText(file1, "content1");

		_fileEnumerator.Setup(f => f.EnumerateFiles("testdir")).Returns(new[] { file1 });
		_fileHasher.Setup(h => h.ComputeSha256Async(file1)).ReturnsAsync("hash1");
		_vtService.Setup(c => c.GetFileReportAsync("hash1")).ReturnsAsync((VirusTotalReport?)null);

		// existing pending entry from previous run
		_pendingAnalysisRepository.Setup(r => r.FindByHash("hash1"))
			.Returns(new PendingAnalysisEntry
			{
				SHA256 = "hash1",
				AnalysisId = "old-analysis-id",
				FilePath = file1,
				SizeBytes = 8
			});

		// analysis already completed
		_vtClient.Setup(c => c.GetAnalysisAsync("old-analysis-id")).ReturnsAsync(new VirusTotalReport
		{
			SHA256 = "hash1",
			TotalEngines = 70,
			Detections = 1,
			Threats = "Engine1: Trojan.Gen"
		});

		var orchestrator = createOrchestrator();
		var results = await orchestrator.ScanAsync("testdir");

		Assert.Single(results);
		Assert.True(results[0].HasDetections);
		_vtService.Verify(c => c.UploadFileAsync(It.IsAny<string>()), Times.Never);
		_vtService.Verify(c => c.CacheReport("hash1", It.IsAny<VirusTotalReport>()), Times.Once);
		_pendingAnalysisRepository.Verify(r => r.Remove("hash1"), Times.Once);
	}

	[Fact]
	public async Task ScanAsync_UploadFails_ReportsErrorAndContinues()
	{
		var file1 = Path.Combine(_tempDir, "file1.exe");
		File.WriteAllText(file1, "content1");

		_fileEnumerator.Setup(f => f.EnumerateFiles("testdir")).Returns(new[] { file1 });
		_fileHasher.Setup(h => h.ComputeSha256Async(file1)).ReturnsAsync("hash1");
		_vtService.Setup(c => c.GetFileReportAsync("hash1")).ReturnsAsync((VirusTotalReport?)null);
		_vtService.Setup(c => c.UploadFileAsync(file1))
			.ThrowsAsync(new HttpRequestException("Upload failed after 3 retries"));

		var orchestrator = createOrchestrator();
		var results = await orchestrator.ScanAsync("testdir");

		Assert.Single(results);
		Assert.Contains("Upload failed", results[0].Threats);
		_reporter.Verify(r => r.ReportError(It.Is<string>(s => s.Contains("Upload failed"))), Times.Once);
	}

	[Fact]
	public async Task ScanAsync_LargeFile_SkipsHashingAndApi()
	{
		var filePath = Path.Combine(_tempDir, "large.bin");
		using (var fs = File.Create(filePath))
		{
			fs.SetLength(651L * 1024 * 1024);
		}

		_fileEnumerator.Setup(f => f.EnumerateFiles("testdir")).Returns(new[] { filePath });

		var orchestrator = createOrchestrator();
		var results = await orchestrator.ScanAsync("testdir");

		Assert.Single(results);
		Assert.Equal("Skipped: file exceeds 650 MB VirusTotal limit", results[0].Threats);
		Assert.Equal(filePath, results[0].FullPath);
		Assert.Equal(651L * 1024 * 1024, results[0].SizeBytes);
		Assert.Equal(string.Empty, results[0].SHA256);

		_fileHasher.Verify(h => h.ComputeSha256Async(It.IsAny<string>()), Times.Never);
		_vtService.Verify(c => c.GetFileReportAsync(It.IsAny<string>()), Times.Never);
		_reporter.Verify(r => r.ReportSkipped(
			"large.bin",
			"file exceeds 650 MB VirusTotal limit"), Times.Once);
		_reporter.Verify(r => r.ReportComplete(1, 0), Times.Once);
	}

	[Fact]
	public async Task ScanAsync_QuotaExceeded_ContinuesWithCachedResults()
	{
		var file1 = Path.Combine(_tempDir, "file1.exe");
		var file2 = Path.Combine(_tempDir, "file2.dll");
		var file3 = Path.Combine(_tempDir, "file3.txt");
		File.WriteAllText(file1, "content1");
		File.WriteAllText(file2, "content2");
		File.WriteAllText(file3, "content3");

		var files = new[] { file1, file2, file3 };
		_fileEnumerator.Setup(f => f.EnumerateFiles("testdir")).Returns(files);

		_fileHasher.Setup(h => h.ComputeSha256Async(file1)).ReturnsAsync("hash1");
		_fileHasher.Setup(h => h.ComputeSha256Async(file2)).ReturnsAsync("hash2");
		_fileHasher.Setup(h => h.ComputeSha256Async(file3)).ReturnsAsync("hash3");

		// file1: quota exceeded on API call
		_vtService.Setup(c => c.GetFileReportAsync("hash1"))
			.ThrowsAsync(new QuotaExceededException("VirusTotal daily quota exceeded"));

		// file2: cached result available
		_vtService.Setup(c => c.GetFileReportAsync("hash2")).ReturnsAsync(new VirusTotalReport
		{
			SHA256 = "hash2",
			TotalEngines = 70,
			Detections = 2,
			Threats = "Engine1: Trojan.Gen"
		});

		// file3: cache miss → report is null → skipped because quota exceeded
		_vtService.Setup(c => c.GetFileReportAsync("hash3")).ReturnsAsync((VirusTotalReport?)null);

		var orchestrator = createOrchestrator();
		var results = await orchestrator.ScanAsync("testdir");

		Assert.Equal(3, results.Count);
		// file1: skipped due to quota
		Assert.Equal("Skipped: VirusTotal daily quota exceeded", results[0].Threats);
		// file2: served from cache despite quota
		Assert.True(results[1].HasDetections);
		Assert.Equal("hash2", results[1].SHA256);
		// file3: cache miss, skipped due to quota
		Assert.Equal("Skipped: VirusTotal daily quota exceeded", results[2].Threats);

		_reporter.Verify(r => r.ReportError(It.Is<string>(s => s.Contains("daily quota exceeded"))), Times.Once);
		_reporter.Verify(r => r.ReportDetection(It.IsAny<FileScanResult>()), Times.Once);
		_reporter.Verify(r => r.ReportComplete(3, 1), Times.Once);
	}

	[Fact]
	public async Task ScanAsync_EmptyDirectory_ReturnsEmpty()
	{
		_fileEnumerator.Setup(f => f.EnumerateFiles("empty")).Returns(Array.Empty<string>());

		var orchestrator = createOrchestrator();
		var results = await orchestrator.ScanAsync("empty");

		Assert.Empty(results);
		_reporter.Verify(r => r.ReportComplete(0, 0), Times.Once);
	}
}
