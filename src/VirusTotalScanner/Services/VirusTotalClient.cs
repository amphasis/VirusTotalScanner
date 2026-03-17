using System.Net;
using System.Text.Json;
using VirusTotalScanner.Models;

namespace VirusTotalScanner.Services;

internal sealed class VirusTotalClient : IVirusTotalClient
{
	private readonly HttpClient _httpClient;
	private readonly TimeSpan _rateLimitRetryDelay;
	private const int MaxRetries = 3;
	private const long LargeFileThreshold = 32L * 1024 * 1024;

	public VirusTotalClient(HttpClient httpClient, TimeSpan? rateLimitRetryDelay = null)
	{
		_httpClient = httpClient;
		_rateLimitRetryDelay = rateLimitRetryDelay ?? TimeSpan.FromSeconds(15);
	}

	public async Task<VirusTotalReport?> GetFileReportAsync(string sha256)
	{
		return await executeWithRetry(async () =>
		{
			var response = await _httpClient.GetAsync($"files/{sha256}");

			if (response.StatusCode == HttpStatusCode.NotFound)
				return null;

			await handleRateLimit(response);
			response.EnsureSuccessStatusCode();

			var json = await response.Content.ReadAsStringAsync();
			var vtResponse = JsonSerializer.Deserialize<VirusTotalResponse>(json);

			return mapToReport(sha256, vtResponse?.Data?.Attributes?.LastAnalysisStats,
				vtResponse?.Data?.Attributes?.LastAnalysisResults);
		}, $"get report for {sha256}");
	}

	public async Task<string> UploadFileAsync(string filePath)
	{
		var fileInfo = new FileInfo(filePath);
		var isLargeFile = fileInfo.Length > LargeFileThreshold;

		return await executeWithRetry(async () =>
		{
			var uploadUrl = isLargeFile
				? await getLargeFileUploadUrl()
				: null;

			using var fileStream = File.OpenRead(filePath);
			using var content = new MultipartFormDataContent();
			content.Add(new StreamContent(fileStream), "file", Path.GetFileName(filePath));

			var response = uploadUrl != null
				? await _httpClient.PostAsync(uploadUrl, content)
				: await _httpClient.PostAsync("files", content);

			await handleRateLimit(response);
			response.EnsureSuccessStatusCode();

			var json = await response.Content.ReadAsStringAsync();
			var uploadResponse = JsonSerializer.Deserialize<VirusTotalUploadResponse>(json);

			return uploadResponse?.Data?.Id
				?? throw new InvalidOperationException("Upload response did not contain analysis ID");
		}, $"upload file {filePath}");
	}

	public async Task<VirusTotalReport?> GetAnalysisAsync(string analysisId)
	{
		return await executeWithRetry(async () =>
		{
			var response = await _httpClient.GetAsync($"analyses/{analysisId}");

			await handleRateLimit(response);
			response.EnsureSuccessStatusCode();

			var json = await response.Content.ReadAsStringAsync();
			var analysisResponse = JsonSerializer.Deserialize<VirusTotalAnalysisResponse>(json);

			var attributes = analysisResponse?.Data?.Attributes;
			if (attributes?.Status != "completed")
				return null;

			return mapToReport(analysisId, attributes.Stats, attributes.Results);
		}, $"get analysis {analysisId}");
	}

	private async Task<string> getLargeFileUploadUrl()
	{
		return await executeWithRetry(async () =>
		{
			var response = await _httpClient.GetAsync("files/upload_url");

			await handleRateLimit(response);
			response.EnsureSuccessStatusCode();

			var json = await response.Content.ReadAsStringAsync();
			var urlResponse = JsonSerializer.Deserialize<JsonElement>(json);

			return urlResponse.GetProperty("data").GetString()
				?? throw new InvalidOperationException("Upload URL response did not contain URL");
		}, "get large file upload URL");
	}

	private async Task handleRateLimit(HttpResponseMessage response)
	{
		if (response.StatusCode != (HttpStatusCode)429)
			return;

		var errorCode = await parseErrorCode(response);

		if (errorCode == "QuotaExceededError")
			throw new QuotaExceededException("VirusTotal daily quota exceeded");

		throw new RateLimitException();
	}

	private async Task<T> executeWithRetry<T>(Func<Task<T>> action, string operationDescription)
	{
		for (int attempt = 0; attempt <= MaxRetries; attempt++)
		{
			try
			{
				return await action();
			}
			catch (RateLimitException) when (attempt < MaxRetries)
			{
				await Task.Delay(_rateLimitRetryDelay);
			}
			catch (HttpRequestException) when (attempt < MaxRetries)
			{
				var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt));
				await Task.Delay(delay);
			}
		}

		throw new HttpRequestException($"Failed to {operationDescription} after {MaxRetries} retries");
	}

	private static async Task<string?> parseErrorCode(HttpResponseMessage response)
	{
		try
		{
			var json = await response.Content.ReadAsStringAsync();
			var errorResponse = JsonSerializer.Deserialize<VirusTotalErrorResponse>(json);
			return errorResponse?.Error?.Code;
		}
		catch (JsonException)
		{
			return null;
		}
	}

	private static VirusTotalReport mapToReport(string identifier, VtAnalysisStats? stats,
		Dictionary<string, VtEngineResult>? results)
	{
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

		return new VirusTotalReport
		{
			SHA256 = identifier,
			TotalEngines = totalEngines,
			Detections = detections,
			Threats = string.Join("\r\n", threats)
		};
	}

	private sealed class RateLimitException : Exception;
}
