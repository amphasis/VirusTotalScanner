using System.Net;
using System.Text.Json;
using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

internal sealed class VirusTotalClient : IVirusTotalClient
{
	private readonly HttpClient _httpClient;
	private readonly TimeSpan _rateLimitRetryDelay;
	private const int MaxRetries = 3;

	public VirusTotalClient(HttpClient httpClient, TimeSpan? rateLimitRetryDelay = null)
	{
		_httpClient = httpClient;
		_rateLimitRetryDelay = rateLimitRetryDelay ?? TimeSpan.FromSeconds(15);
	}

	public async Task<FileScanResult?> GetFileReportAsync(string sha256)
	{
		for (int attempt = 0; attempt <= MaxRetries; attempt++)
		{
			try
			{
				var response = await _httpClient.GetAsync($"files/{sha256}");

				if (response.StatusCode == HttpStatusCode.NotFound)
					return null;

				if (response.StatusCode == (HttpStatusCode)429)
				{
					await Task.Delay(_rateLimitRetryDelay);
					continue;
				}

				response.EnsureSuccessStatusCode();

				var json = await response.Content.ReadAsStringAsync();
				var vtResponse = JsonSerializer.Deserialize<VirusTotalResponse>(json);

				return mapToResult(sha256, vtResponse);
			}
			catch (HttpRequestException) when (attempt < MaxRetries)
			{
				var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt));
				await Task.Delay(delay);
			}
		}

		throw new HttpRequestException($"Failed to get report for {sha256} after {MaxRetries} retries");
	}

	private static FileScanResult mapToResult(string sha256, VirusTotalResponse? vtResponse)
	{
		var stats = vtResponse?.Data?.Attributes?.LastAnalysisStats;
		var results = vtResponse?.Data?.Attributes?.LastAnalysisResults;

		int totalEngines = 0;
		int detections = 0;
		var threats = new List<string>();

		if (stats != null)
		{
			totalEngines = stats.Malicious + stats.Suspicious + stats.Undetected +
						   stats.Harmless + stats.Timeout + stats.ConfirmedTimeout +
						   stats.Failure + stats.TypeUnsupported;
			detections = stats.Malicious + stats.Suspicious;
		}

		if (results != null)
		{
			foreach (var kvp in results)
			{
				if (kvp.Value.Category is "malicious" or "suspicious" && !string.IsNullOrEmpty(kvp.Value.Result))
				{
					threats.Add($"{kvp.Value.EngineName}: {kvp.Value.Result}");
				}
			}
		}

		return new FileScanResult
		{
			SHA256 = sha256,
			TotalEngines = totalEngines,
			Detections = detections,
			Threats = string.Join("\r\n", threats)
		};
	}
}
