using System.Net;
using System.Net.Http.Headers;
using System.Text;
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
			await ensureSuccess(response);

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

			using var content = new FileUploadContent(filePath);

			var response = uploadUrl != null
				? await _httpClient.PostAsync(uploadUrl, content)
				: await _httpClient.PostAsync("files", content);

			await handleRateLimit(response);
			await ensureSuccess(response);

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
			await ensureSuccess(response);

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
			await ensureSuccess(response);

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

	private static async Task ensureSuccess(HttpResponseMessage response)
	{
		if (response.IsSuccessStatusCode)
			return;

		var body = await response.Content.ReadAsStringAsync();
		throw new HttpRequestException(
			$"Response status code does not indicate success: {(int)response.StatusCode} ({response.ReasonPhrase}). " +
			$"Response: {body}");
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

	private sealed class FileUploadContent : HttpContent
	{
		private readonly string _filePath;
		private readonly string _boundary;

		public FileUploadContent(string filePath)
		{
			_filePath = filePath;
			_boundary = Guid.NewGuid().ToString("N");
			Headers.ContentType = MediaTypeHeaderValue.Parse($"multipart/form-data; boundary={_boundary}");
		}

		protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
		{
			var fileName = Path.GetFileName(_filePath);
			var preamble = Encoding.UTF8.GetBytes(
				$"--{_boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fileName}\"\r\nContent-Type: application/octet-stream\r\n\r\n");
			var epilogue = Encoding.UTF8.GetBytes($"\r\n--{_boundary}--\r\n");

			await stream.WriteAsync(preamble);
			await using var fileStream = File.OpenRead(_filePath);
			await fileStream.CopyToAsync(stream);
			await stream.WriteAsync(epilogue);
		}

		protected override bool TryComputeLength(out long length)
		{
			var fileName = Path.GetFileName(_filePath);
			var preamble = $"--{_boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fileName}\"\r\nContent-Type: application/octet-stream\r\n\r\n";
			var epilogue = $"\r\n--{_boundary}--\r\n";

			length = Encoding.UTF8.GetByteCount(preamble)
				+ new FileInfo(_filePath).Length
				+ Encoding.UTF8.GetByteCount(epilogue);
			return true;
		}
	}
}
