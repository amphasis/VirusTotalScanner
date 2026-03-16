using CommandLine;

namespace VirusTotalScanner;

internal sealed class Options
{
	[Option('p', "path", Required = true, HelpText = "Path to file or directory to scan")]
	public string Path { get; set; } = string.Empty;

	[Option('k', "api-key", Required = false, HelpText = "VirusTotal API key (overrides appsettings.json)")]
	public string? ApiKey { get; set; }

	[Option('o', "output", Required = false, HelpText = "Output CSV file path")]
	public string? Output { get; set; }

	[Option("no-upload", Required = false, Default = false, HelpText = "Disable automatic file upload for files not found in VirusTotal")]
	public bool NoUpload { get; set; }
}
