using CommandLine;
using LiteDB;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using VirusTotalScanner;
using VirusTotalScanner.Cache;
using VirusTotalScanner.Reporting;
using VirusTotalScanner.Services;

return await Parser.Default.ParseArguments<Options>(args)
	.MapResult(runAsync, _ => Task.FromResult(1));

static async Task<int> runAsync(Options opts)
{
	var configuration = new ConfigurationBuilder()
		.SetBasePath(AppContext.BaseDirectory)
		.AddJsonFile("appsettings.json", optional: true)
		.Build();

	var apiKey = opts.ApiKey ?? configuration["VirusTotal:ApiKey"];

	if (string.IsNullOrWhiteSpace(apiKey))
	{
		Console.ForegroundColor = ConsoleColor.Red;
		Console.WriteLine("ERROR: VirusTotal API key is required.");
		Console.ResetColor();
		Console.WriteLine("Provide it via:");
		Console.WriteLine("  --api-key YOUR_KEY");
		Console.WriteLine("  or set it in appsettings.json");
		return 1;
	}

	if (!File.Exists(opts.Path) && !Directory.Exists(opts.Path))
	{
		Console.ForegroundColor = ConsoleColor.Red;
		Console.WriteLine($"ERROR: Path not found: {opts.Path}");
		Console.ResetColor();
		return 1;
	}

	var services = new ServiceCollection();

	services.AddSingleton<IConfiguration>(configuration);
	services.AddSingleton<IFileHasher, FileHasher>();
	services.AddSingleton<IFileEnumerator, FileEnumerator>();
	services.AddSingleton<IFilePrioritizer, FilePrioritizer>();
	services.AddSingleton<IConsoleReporter, ConsoleReporter>();
	services.AddSingleton<ICsvExporter, CsvExporter>();
	services.AddSingleton<IVirusTotalClient, VirusTotalClient>();
	services.AddSingleton<ILiteDatabase>(_ =>
	{
		var cacheDir = Path.Combine(
			Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
			"VirusTotalScanner");
		Directory.CreateDirectory(cacheDir);
		return new LiteDatabase(Path.Combine(cacheDir, "cache.db"));
	});
	services.AddSingleton<IFileHashCacheRepository, FileHashCacheRepository>();
	services.AddSingleton<IVirusTotalCacheRepository, VirusTotalCacheRepository>();
	services.AddSingleton<IPendingAnalysisRepository, PendingAnalysisRepository>();
	services.AddSingleton<IVirusTotalService, VirusTotalService>();
	services.AddSingleton(new ScanOptions { UploadEnabled = !opts.NoUpload });
	services.AddSingleton<IScanOrchestrator, ScanOrchestrator>();

	services.AddSingleton(_ =>
	{
		var httpClient = new HttpClient
		{
			BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
		};
		httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);
		return httpClient;
	});

	await using var serviceProvider = services.BuildServiceProvider();

	var orchestrator = serviceProvider.GetRequiredService<IScanOrchestrator>();
	var results = await orchestrator.ScanAsync(opts.Path);

	if (results.Count > 0)
	{
		var outputPath = opts.Output
			?? Path.Combine(Directory.GetCurrentDirectory(),
				$"scan_results_{DateTime.Now:yyyyMMdd_HHmmss}.csv");

		var csvExporter = serviceProvider.GetRequiredService<ICsvExporter>();
		csvExporter.Export(results, outputPath);
	}
	else
	{
		Console.WriteLine("No files were scanned.");
	}

	return 0;
}
