using System.Net;
using System.Text.Json;
using VirusTotalScanner.Models;
using VirusTotalScanner.Services;

namespace VirusTotalScanner.Tests.Services;

public sealed class VirusTotalClientTests
{
	private VirusTotalClient createClient(HttpMessageHandler handler)
	{
		var httpClient = new HttpClient(handler)
		{
			BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
		};
		return new VirusTotalClient(httpClient, TimeSpan.Zero);
	}

	[Fact]
	public async Task GetFileReportAsync_WithDetections_ReturnsCorrectResult()
	{
		var vtResponse = new VirusTotalResponse
		{
			Data = new VtData
			{
				Attributes = new VtAttributes
				{
					LastAnalysisStats = new VtAnalysisStats
					{
						Malicious = 3,
						Suspicious = 1,
						Undetected = 60,
						Harmless = 6
					},
					LastAnalysisResults = new Dictionary<string, VtEngineResult>
					{
						["EngineA"] = new() { Category = "malicious", EngineName = "EngineA", Result = "Trojan.Gen" },
						["EngineB"] = new() { Category = "malicious", EngineName = "EngineB", Result = "Malware.X" },
						["EngineC"] = new() { Category = "malicious", EngineName = "EngineC", Result = "Win32.Bad" },
						["EngineD"] = new() { Category = "suspicious", EngineName = "EngineD", Result = "Suspicious.Y" },
						["EngineE"] = new() { Category = "undetected", EngineName = "EngineE", Result = null }
					}
				}
			}
		};

		var json = JsonSerializer.Serialize(vtResponse);
		var handler = new MockHttpHandler(new HttpResponseMessage(HttpStatusCode.OK)
		{
			Content = new StringContent(json)
		});

		var client = createClient(handler);
		var result = await client.GetFileReportAsync("abc123");

		Assert.NotNull(result);
		Assert.Equal(70, result!.TotalEngines);
		Assert.Equal(4, result.Detections);
		Assert.True(result.HasDetections);
		Assert.Contains("EngineA: Trojan.Gen", result.Threats);
		Assert.Contains("EngineD: Suspicious.Y", result.Threats);
	}

	[Fact]
	public async Task GetFileReportAsync_NoDetections_ReturnsZeroDetections()
	{
		var vtResponse = new VirusTotalResponse
		{
			Data = new VtData
			{
				Attributes = new VtAttributes
				{
					LastAnalysisStats = new VtAnalysisStats
					{
						Malicious = 0,
						Suspicious = 0,
						Undetected = 60,
						Harmless = 10
					},
					LastAnalysisResults = new Dictionary<string, VtEngineResult>
					{
						["EngineA"] = new() { Category = "undetected", EngineName = "EngineA", Result = null }
					}
				}
			}
		};

		var json = JsonSerializer.Serialize(vtResponse);
		var handler = new MockHttpHandler(new HttpResponseMessage(HttpStatusCode.OK)
		{
			Content = new StringContent(json)
		});

		var client = createClient(handler);
		var result = await client.GetFileReportAsync("clean_hash");

		Assert.NotNull(result);
		Assert.Equal(0, result!.Detections);
		Assert.False(result.HasDetections);
	}

	[Fact]
	public async Task GetFileReportAsync_NotFound_ReturnsNull()
	{
		var handler = new MockHttpHandler(new HttpResponseMessage(HttpStatusCode.NotFound));

		var client = createClient(handler);
		var result = await client.GetFileReportAsync("unknown_hash");

		Assert.Null(result);
	}

	[Fact]
	public async Task GetFileReportAsync_TooManyRequests_RetriesSuccessfully()
	{
		var vtResponse = new VirusTotalResponse
		{
			Data = new VtData
			{
				Attributes = new VtAttributes
				{
					LastAnalysisStats = new VtAnalysisStats { Undetected = 10 },
					LastAnalysisResults = new Dictionary<string, VtEngineResult>()
				}
			}
		};
		var successJson = JsonSerializer.Serialize(vtResponse);
		var errorJson = JsonSerializer.Serialize(new VirusTotalErrorResponse
		{
			Error = new VtError { Code = "TooManyRequestsError", Message = "Too many requests" }
		});

		var callCount = 0;
		var handler = new MockHttpHandler(() =>
		{
			callCount++;
			if (callCount == 1)
				return new HttpResponseMessage((HttpStatusCode)429)
				{
					Content = new StringContent(errorJson)
				};
			return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(successJson) };
		});

		var client = createClient(handler);
		var result = await client.GetFileReportAsync("rate_limited_hash");

		Assert.NotNull(result);
		Assert.Equal(2, callCount);
	}

	[Fact]
	public async Task GetFileReportAsync_QuotaExceeded_ThrowsQuotaExceededException()
	{
		var errorJson = JsonSerializer.Serialize(new VirusTotalErrorResponse
		{
			Error = new VtError { Code = "QuotaExceededError", Message = "Quota exceeded" }
		});

		var handler = new MockHttpHandler(new HttpResponseMessage((HttpStatusCode)429)
		{
			Content = new StringContent(errorJson)
		});

		var client = createClient(handler);

		await Assert.ThrowsAsync<QuotaExceededException>(
			() => client.GetFileReportAsync("quota_hash"));
	}

	[Fact]
	public async Task GetFileReportAsync_RateLimitedNoBody_RetriesSuccessfully()
	{
		var vtResponse = new VirusTotalResponse
		{
			Data = new VtData
			{
				Attributes = new VtAttributes
				{
					LastAnalysisStats = new VtAnalysisStats { Undetected = 10 },
					LastAnalysisResults = new Dictionary<string, VtEngineResult>()
				}
			}
		};
		var json = JsonSerializer.Serialize(vtResponse);

		var callCount = 0;
		var handler = new MockHttpHandler(() =>
		{
			callCount++;
			if (callCount == 1)
				return new HttpResponseMessage((HttpStatusCode)429);
			return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json) };
		});

		var client = createClient(handler);
		var result = await client.GetFileReportAsync("rate_limited_hash");

		Assert.NotNull(result);
		Assert.Equal(2, callCount);
	}

	[Fact]
	public async Task UploadFileAsync_SmallFile_PostsToFilesEndpoint()
	{
		var tempFile = Path.GetTempFileName();
		try
		{
			File.WriteAllText(tempFile, "small content");

			var uploadResponse = new { data = new { id = "analysis-123" } };
			var json = JsonSerializer.Serialize(uploadResponse);

			string? capturedUri = null;
			var handler = new MockHttpHandler(request =>
			{
				capturedUri = request.RequestUri?.ToString();
				return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json) };
			});

			var client = createClient(handler);
			var result = await client.UploadFileAsync(tempFile);

			Assert.Equal("analysis-123", result);
			Assert.Contains("files", capturedUri);
			Assert.DoesNotContain("upload_url", capturedUri!);
		}
		finally
		{
			File.Delete(tempFile);
		}
	}

	[Fact]
	public async Task GetAnalysisAsync_Completed_ReturnsReport()
	{
		var analysisResponse = new VirusTotalAnalysisResponse
		{
			Data = new VtAnalysisData
			{
				Attributes = new VtAnalysisAttributes
				{
					Status = "completed",
					Stats = new VtAnalysisStats
					{
						Malicious = 2,
						Suspicious = 0,
						Undetected = 60,
						Harmless = 8
					},
					Results = new Dictionary<string, VtEngineResult>
					{
						["EngineA"] = new() { Category = "malicious", EngineName = "EngineA", Result = "Trojan.Gen" },
						["EngineB"] = new() { Category = "malicious", EngineName = "EngineB", Result = "Malware.X" },
						["EngineC"] = new() { Category = "undetected", EngineName = "EngineC", Result = null }
					}
				}
			}
		};

		var json = JsonSerializer.Serialize(analysisResponse);
		var handler = new MockHttpHandler(new HttpResponseMessage(HttpStatusCode.OK)
		{
			Content = new StringContent(json)
		});

		var client = createClient(handler);
		var result = await client.GetAnalysisAsync("analysis-123");

		Assert.NotNull(result);
		Assert.Equal(70, result!.TotalEngines);
		Assert.Equal(2, result.Detections);
		Assert.Contains("EngineA: Trojan.Gen", result.Threats);
		Assert.Contains("EngineB: Malware.X", result.Threats);
	}

	[Fact]
	public async Task GetAnalysisAsync_Queued_ReturnsNull()
	{
		var analysisResponse = new VirusTotalAnalysisResponse
		{
			Data = new VtAnalysisData
			{
				Attributes = new VtAnalysisAttributes
				{
					Status = "queued"
				}
			}
		};

		var json = JsonSerializer.Serialize(analysisResponse);
		var handler = new MockHttpHandler(new HttpResponseMessage(HttpStatusCode.OK)
		{
			Content = new StringContent(json)
		});

		var client = createClient(handler);
		var result = await client.GetAnalysisAsync("analysis-123");

		Assert.Null(result);
	}

	[Fact]
	public async Task GetAnalysisAsync_InProgress_ReturnsNull()
	{
		var analysisResponse = new VirusTotalAnalysisResponse
		{
			Data = new VtAnalysisData
			{
				Attributes = new VtAnalysisAttributes
				{
					Status = "in-progress"
				}
			}
		};

		var json = JsonSerializer.Serialize(analysisResponse);
		var handler = new MockHttpHandler(new HttpResponseMessage(HttpStatusCode.OK)
		{
			Content = new StringContent(json)
		});

		var client = createClient(handler);
		var result = await client.GetAnalysisAsync("analysis-123");

		Assert.Null(result);
	}

	private sealed class MockHttpHandler : HttpMessageHandler
	{
		private readonly Func<HttpRequestMessage, HttpResponseMessage> _requestHandler;

		public MockHttpHandler(HttpResponseMessage response)
			: this(_ => response) { }

		public MockHttpHandler(Func<HttpResponseMessage> responseFactory)
			: this(_ => responseFactory()) { }

		public MockHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> requestHandler)
		{
			_requestHandler = requestHandler;
		}

		protected override Task<HttpResponseMessage> SendAsync(
			HttpRequestMessage request, CancellationToken cancellationToken)
		{
			return Task.FromResult(_requestHandler(request));
		}
	}
}
