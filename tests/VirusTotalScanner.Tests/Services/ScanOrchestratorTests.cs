using Moq;
using VirusTotalScanner.Models;
using VirusTotalScanner.Reporting;
using VirusTotalScanner.Services;

namespace VirusTotalScanner.Tests.Services;

public class ScanOrchestratorTests : IDisposable
{
	private readonly Mock<IFileEnumerator> _fileEnumerator = new();
	private readonly Mock<IFileHasher> _fileHasher = new();
	private readonly Mock<IVirusTotalClient> _vtClient = new();
	private readonly Mock<IConsoleReporter> _reporter = new();
	private readonly ScanOrchestrator _orchestrator;
	private readonly string _tempDir;

	public ScanOrchestratorTests()
	{
		_orchestrator = new ScanOrchestrator(
			_fileEnumerator.Object,
			_fileHasher.Object,
			_vtClient.Object,
			_reporter.Object);

		_tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
		Directory.CreateDirectory(_tempDir);
	}

	public void Dispose()
	{
		if (Directory.Exists(_tempDir))
			Directory.Delete(_tempDir, true);
	}

	[Fact]
	public async Task ScanAsync_MixedResults_ReturnsAllResults()
	{
		// Create real temp files so FileInfo.Length works
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

		_vtClient.Setup(c => c.GetFileReportAsync("hash1")).ReturnsAsync(new FileScanResult
		{
			SHA256 = "hash1",
			TotalEngines = 70,
			Detections = 5,
			Threats = "Engine1: Trojan.Gen"
		});
		_vtClient.Setup(c => c.GetFileReportAsync("hash2")).ReturnsAsync(new FileScanResult
		{
			SHA256 = "hash2",
			TotalEngines = 70,
			Detections = 0,
			Threats = ""
		});
		_vtClient.Setup(c => c.GetFileReportAsync("hash3")).ReturnsAsync((FileScanResult?)null);

		// Act
		var results = await _orchestrator.ScanAsync("testdir");

		// Assert
		Assert.Equal(3, results.Count);
		Assert.True(results[0].HasDetections);
		Assert.False(results[1].HasDetections);
		Assert.Equal("Not in VT database", results[2].Threats);

		_reporter.Verify(r => r.ReportProgress(It.IsAny<int>(), 3, It.IsAny<string>()), Times.Exactly(3));
		_reporter.Verify(r => r.ReportDetection(It.IsAny<FileScanResult>()), Times.Once);
		_reporter.Verify(r => r.ReportClean(It.IsAny<FileScanResult>()), Times.Once);
		_reporter.Verify(r => r.ReportNotFound(It.IsAny<string>()), Times.Once);
		_reporter.Verify(r => r.ReportComplete(3, 1), Times.Once);
	}

	[Fact]
	public async Task ScanAsync_EmptyDirectory_ReturnsEmpty()
	{
		_fileEnumerator.Setup(f => f.EnumerateFiles("empty")).Returns(Array.Empty<string>());

		var results = await _orchestrator.ScanAsync("empty");

		Assert.Empty(results);
		_reporter.Verify(r => r.ReportComplete(0, 0), Times.Once);
	}
}
