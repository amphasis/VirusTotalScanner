namespace VirusTotalScanner.Services;

public sealed class ScanOptions
{
	public bool UploadEnabled { get; init; } = true;
	public TimeSpan PollingInterval { get; init; } = TimeSpan.FromSeconds(15);
	public TimeSpan PollingTimeout { get; init; } = TimeSpan.FromMinutes(10);
}
