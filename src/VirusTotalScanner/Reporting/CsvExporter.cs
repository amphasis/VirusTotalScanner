using System.Diagnostics;
using System.Globalization;
using CsvHelper;
using CsvHelper.Configuration;
using VirusTotalScanner.Models;

namespace VirusTotalScanner.Reporting;

public class CsvExporter : ICsvExporter
{
    public void Export(List<FileScanResult> results, string outputPath)
    {
        var config = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            HasHeaderRecord = true,
        };

        using (var writer = new StreamWriter(outputPath))
        using (var csv = new CsvWriter(writer, config))
        {
            csv.WriteRecords(results);
        }

        Console.WriteLine($"Results saved to: {outputPath}");

        try
        {
            Process.Start(new ProcessStartInfo(outputPath) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Could not open file automatically: {ex.Message}");
        }
    }
}
