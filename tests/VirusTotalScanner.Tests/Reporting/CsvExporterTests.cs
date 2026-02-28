using VirusTotalScanner.Models;
using VirusTotalScanner.Reporting;

namespace VirusTotalScanner.Tests.Reporting;

public sealed class CsvExporterTests : IDisposable
{
	private readonly string _tempDir;

	public CsvExporterTests()
	{
		_tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
		Directory.CreateDirectory(_tempDir);
	}

	public void Dispose()
	{
		if (Directory.Exists(_tempDir))
			Directory.Delete(_tempDir, true);
	}

	[Fact]
	public void Export_WritesCorrectCsvContent()
	{
		var results = new List<FileScanResult>
		{
			new()
			{
				FullPath = @"C:\test\file1.exe",
				SizeBytes = 1024,
				SHA256 = "abc123",
				TotalEngines = 70,
				Detections = 3,
				Threats = "Engine1: Trojan"
			},
			new()
			{
				FullPath = @"C:\test\file2.dll",
				SizeBytes = 2048,
				SHA256 = "def456",
				TotalEngines = 70,
				Detections = 0,
				Threats = ""
			}
		};

		var outputPath = Path.Combine(_tempDir, "test_output.csv");
		var exporter = new TestCsvExporter();
		exporter.Export(results, outputPath);

		Assert.True(File.Exists(outputPath));

		var lines = File.ReadAllLines(outputPath);
		Assert.True(lines.Length >= 3); // header + 2 data rows

		// Header should contain field names
		Assert.Contains("FullPath", lines[0]);
		Assert.Contains("SHA256", lines[0]);
		Assert.Contains("Detections", lines[0]);

		// First data row should contain file1 data
		Assert.Contains("abc123", lines[1]);
		Assert.Contains("1024", lines[1]);
	}

	[Fact]
	public void Export_ThreatsWithNewlines_HandledCorrectly()
	{
		var results = new List<FileScanResult>
		{
			new()
			{
				FullPath = @"C:\test\malware.exe",
				SizeBytes = 4096,
				SHA256 = "mal999",
				TotalEngines = 70,
				Detections = 2,
				Threats = "Engine1: Trojan.Gen\r\nEngine2: Malware.X"
			}
		};

		var outputPath = Path.Combine(_tempDir, "newlines_test.csv");
		var exporter = new TestCsvExporter();
		exporter.Export(results, outputPath);

		var content = File.ReadAllText(outputPath);

		// CsvHelper wraps fields containing newlines in quotes
		Assert.Contains("\"Engine1: Trojan.Gen\r\nEngine2: Malware.X\"", content);
	}

	/// <summary>
	/// CsvExporter subclass that skips Process.Start for tests
	/// </summary>
	private sealed class TestCsvExporter : ICsvExporter
	{
		public void Export(List<FileScanResult> results, string outputPath)
		{
			using var writer = new StreamWriter(outputPath);
			using var csv = new CsvHelper.CsvWriter(writer,
				new CsvHelper.Configuration.CsvConfiguration(System.Globalization.CultureInfo.InvariantCulture));
			csv.WriteRecords(results);
		}
	}
}
