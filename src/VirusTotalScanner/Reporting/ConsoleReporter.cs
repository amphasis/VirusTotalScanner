using VirusTotalScanner.Models;

namespace VirusTotalScanner.Reporting;

internal sealed class ConsoleReporter : IConsoleReporter
{
	public void ReportProgress(int current, int total, string fileName)
	{
		Console.Write($"\r[{current}/{total}] Scanning: {fileName}".PadRight(Console.WindowWidth - 1));
	}

	public void ReportDetection(FileScanResult result)
	{
		Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");
		var prevColor = Console.ForegroundColor;
		Console.ForegroundColor = ConsoleColor.Red;
		Console.WriteLine($"[DETECTED] {result.Detections}/{result.TotalEngines} - {Path.GetFileName(result.FullPath)}");
		Console.ForegroundColor = prevColor;
	}

	public void ReportClean(FileScanResult result)
	{
		Console.Write($"\r{new string(' ', Console.WindowWidth - 1)}\r");
	}

	public void ReportNotFound(string fileName)
	{
		Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");
		var prevColor = Console.ForegroundColor;
		Console.ForegroundColor = ConsoleColor.Yellow;
		Console.WriteLine($"[NOT FOUND] {fileName} - not in VirusTotal database");
		Console.ForegroundColor = prevColor;
	}

	public void ReportSkipped(string fileName, string reason)
	{
		Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");
		var prevColor = Console.ForegroundColor;
		Console.ForegroundColor = ConsoleColor.DarkYellow;
		Console.WriteLine($"[SKIPPED] {fileName} - {reason}");
		Console.ForegroundColor = prevColor;
	}

	public void ReportError(string message)
	{
		Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");
		var prevColor = Console.ForegroundColor;
		Console.ForegroundColor = ConsoleColor.DarkYellow;
		Console.WriteLine($"[ERROR] {message}");
		Console.ForegroundColor = prevColor;
	}

	public void ReportComplete(int total, int withDetections)
	{
		Console.WriteLine();
		Console.WriteLine($"Scan complete: {total} files scanned, {withDetections} with detections.");
	}
}
