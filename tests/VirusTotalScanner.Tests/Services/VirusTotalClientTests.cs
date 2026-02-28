using System.Net;
using System.Text.Json;
using Moq;
using VirusTotalScanner.Infrastructure;
using VirusTotalScanner.Models;
using VirusTotalScanner.Services;

namespace VirusTotalScanner.Tests.Services;

public sealed class VirusTotalClientTests
{
	private readonly Mock<IRateLimiter> _rateLimiter = new();

	public VirusTotalClientTests()
	{
		_rateLimiter.Setup(r => r.WaitAsync()).Returns(Task.CompletedTask);
	}

	private VirusTotalClient createClient(HttpMessageHandler handler)
	{
		var httpClient = new HttpClient(handler)
		{
			BaseAddress = new Uri("https://www.virustotal.com/api/v3/")
		};
		return new VirusTotalClient(httpClient, _rateLimiter.Object);
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
	public async Task GetFileReportAsync_RateLimited_RetriesSuccessfully()
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

	private sealed class MockHttpHandler : HttpMessageHandler
	{
		private readonly Func<HttpResponseMessage> _responseFactory;

		public MockHttpHandler(HttpResponseMessage response)
			: this(() => response) { }

		public MockHttpHandler(Func<HttpResponseMessage> responseFactory)
		{
			_responseFactory = responseFactory;
		}

		protected override Task<HttpResponseMessage> SendAsync(
			HttpRequestMessage request, CancellationToken cancellationToken)
		{
			return Task.FromResult(_responseFactory());
		}
	}
}
