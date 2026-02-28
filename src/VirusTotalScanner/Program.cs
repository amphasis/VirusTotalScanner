using CommandLine;
using Microsoft.Extensions.Configuration;
using VirusTotalScanner;
using VirusTotalScanner.Infrastructure;
using VirusTotalScanner.Reporting;
using VirusTotalScanner.Services;

return await Parser.Default.ParseArguments<Options>(args)
    .MapResult(RunAsync, _ => Task.FromResult(1));

async Task<int> RunAsync(Options opts)
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

    var httpClient = new HttpClient
    {
        BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
    };
    httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);

    var rateLimiter = new RateLimiter();
    var vtClient = new VirusTotalClient(httpClient, rateLimiter);
    var fileHasher = new FileHasher();
    var fileEnumerator = new FileEnumerator();
    var consoleReporter = new ConsoleReporter();
    var orchestrator = new ScanOrchestrator(fileEnumerator, fileHasher, vtClient, consoleReporter);

    var results = await orchestrator.ScanAsync(opts.Path);

    if (results.Count > 0)
    {
        var outputPath = opts.Output
            ?? Path.Combine(Directory.GetCurrentDirectory(),
                $"scan_results_{DateTime.Now:yyyyMMdd_HHmmss}.csv");

        var csvExporter = new CsvExporter();
        csvExporter.Export(results, outputPath);
    }
    else
    {
        Console.WriteLine("No files were scanned.");
    }

    return 0;
}
