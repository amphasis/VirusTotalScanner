using Moq;
using VirusTotalScanner.Cache;
using VirusTotalScanner.Models;
using VirusTotalScanner.Services;

namespace VirusTotalScanner.Tests.Services;

public sealed class VirusTotalServiceTests
{
	private readonly Mock<IVirusTotalCacheRepository> _cacheRepository = new();
	private readonly Mock<IVirusTotalClient> _vtClient = new();
	private readonly VirusTotalService _service;

	public VirusTotalServiceTests()
	{
		_service = new VirusTotalService(_cacheRepository.Object, _vtClient.Object);
	}

	[Fact]
	public async Task GetFileReportAsync_CacheHit_NotExpired_ReturnsCached()
	{
		var cached = new VirusTotalCacheEntry
		{
			SHA256 = "hash1",
			CreatedAt = DateTime.UtcNow.AddHours(-1),
			TotalEngines = 70,
			Detections = 0,
			Threats = [],
			NotInDatabase = false
		};
		_cacheRepository.Setup(r => r.FindByHash("hash1")).Returns(cached);

		var result = await _service.GetFileReportAsync("hash1");

		Assert.NotNull(result);
		Assert.Equal("hash1", result.SHA256);
		Assert.Equal(70, result.TotalEngines);
		_vtClient.Verify(c => c.GetFileReportAsync(It.IsAny<string>()), Times.Never);
	}

	[Fact]
	public async Task GetFileReportAsync_CacheHit_Expired_CallsApi()
	{
		var cached = new VirusTotalCacheEntry
		{
			SHA256 = "hash1",
			CreatedAt = DateTime.UtcNow.AddDays(-31),
			TotalEngines = 70,
			Detections = 0,
			Threats = [],
			NotInDatabase = false
		};
		_cacheRepository.Setup(r => r.FindByHash("hash1")).Returns(cached);
		_vtClient.Setup(c => c.GetFileReportAsync("hash1")).ReturnsAsync(new VirusTotalReport
		{
			SHA256 = "hash1",
			TotalEngines = 72,
			Detections = 0,
			Threats = ""
		});

		var result = await _service.GetFileReportAsync("hash1");

		Assert.NotNull(result);
		Assert.Equal(72, result.TotalEngines);
		_vtClient.Verify(c => c.GetFileReportAsync("hash1"), Times.Once);
		_cacheRepository.Verify(r => r.Upsert(It.Is<VirusTotalCacheEntry>(e => e.SHA256 == "hash1")), Times.Once);
	}

	[Fact]
	public async Task GetFileReportAsync_CacheMiss_CallsApi_SavesResult()
	{
		_cacheRepository.Setup(r => r.FindByHash("hash1")).Returns((VirusTotalCacheEntry?)null);
		_vtClient.Setup(c => c.GetFileReportAsync("hash1")).ReturnsAsync(new VirusTotalReport
		{
			SHA256 = "hash1",
			TotalEngines = 70,
			Detections = 2,
			Threats = "Engine1: Trojan.Gen, Engine2: Malware.AI"
		});

		var result = await _service.GetFileReportAsync("hash1");

		Assert.NotNull(result);
		Assert.Equal(2, result.Detections);
		_vtClient.Verify(c => c.GetFileReportAsync("hash1"), Times.Once);
		_cacheRepository.Verify(r => r.Upsert(It.Is<VirusTotalCacheEntry>(e =>
			e.SHA256 == "hash1" &&
			e.Detections == 2 &&
			e.Threats.Count == 2)), Times.Once);
	}

	[Fact]
	public async Task GetFileReportAsync_NotInDatabase_AlwaysRequeriesApi()
	{
		// Old NotInDatabase entries from previous cache versions should always be treated as expired
		var cached = new VirusTotalCacheEntry
		{
			SHA256 = "hash1",
			CreatedAt = DateTime.UtcNow.AddMinutes(-5),
			NotInDatabase = true
		};
		_cacheRepository.Setup(r => r.FindByHash("hash1")).Returns(cached);
		_vtClient.Setup(c => c.GetFileReportAsync("hash1")).ReturnsAsync((VirusTotalReport?)null);

		var result = await _service.GetFileReportAsync("hash1");

		Assert.Null(result);
		_vtClient.Verify(c => c.GetFileReportAsync("hash1"), Times.Once);
	}

	[Fact]
	public async Task GetFileReportAsync_NotFound_DoesNotCache()
	{
		_cacheRepository.Setup(r => r.FindByHash("hash1")).Returns((VirusTotalCacheEntry?)null);
		_vtClient.Setup(c => c.GetFileReportAsync("hash1")).ReturnsAsync((VirusTotalReport?)null);

		var result = await _service.GetFileReportAsync("hash1");

		Assert.Null(result);
		_cacheRepository.Verify(r => r.Upsert(It.IsAny<VirusTotalCacheEntry>()), Times.Never);
	}

	[Fact]
	public void CacheReport_SavesReportToCache()
	{
		var report = new VirusTotalReport
		{
			SHA256 = "hash1",
			TotalEngines = 70,
			Detections = 2,
			Threats = "Engine1: Trojan.Gen, Engine2: Malware.AI"
		};

		_service.CacheReport("hash1", report);

		_cacheRepository.Verify(r => r.Upsert(It.Is<VirusTotalCacheEntry>(e =>
			e.SHA256 == "hash1" &&
			e.Detections == 2 &&
			e.TotalEngines == 70 &&
			e.Threats.Count == 2 &&
			!e.NotInDatabase)), Times.Once);
	}

	[Fact]
	public async Task GetFileReportAsync_CleanResult_CachedFor30Days()
	{
		var cached = new VirusTotalCacheEntry
		{
			SHA256 = "hash1",
			CreatedAt = DateTime.UtcNow.AddDays(-29),
			TotalEngines = 70,
			Detections = 0,
			Threats = [],
			NotInDatabase = false
		};
		_cacheRepository.Setup(r => r.FindByHash("hash1")).Returns(cached);

		var result = await _service.GetFileReportAsync("hash1");

		Assert.NotNull(result);
		_vtClient.Verify(c => c.GetFileReportAsync(It.IsAny<string>()), Times.Never);
	}

	[Fact]
	public async Task GetFileReportAsync_WithDetections_CachedFor7Days()
	{
		var cached = new VirusTotalCacheEntry
		{
			SHA256 = "hash1",
			CreatedAt = DateTime.UtcNow.AddDays(-6),
			TotalEngines = 70,
			Detections = 3,
			Threats = ["Trojan.Gen", "Malware.AI", "Adware.X"],
			NotInDatabase = false
		};
		_cacheRepository.Setup(r => r.FindByHash("hash1")).Returns(cached);

		var result = await _service.GetFileReportAsync("hash1");

		Assert.NotNull(result);
		Assert.Equal(3, result.Detections);
		_vtClient.Verify(c => c.GetFileReportAsync(It.IsAny<string>()), Times.Never);

		// After 7 days it should expire
		cached.CreatedAt = DateTime.UtcNow.AddDays(-8);
		_vtClient.Setup(c => c.GetFileReportAsync("hash1")).ReturnsAsync(new VirusTotalReport
		{
			SHA256 = "hash1",
			TotalEngines = 72,
			Detections = 1,
			Threats = "Trojan.Gen"
		});

		result = await _service.GetFileReportAsync("hash1");

		_vtClient.Verify(c => c.GetFileReportAsync("hash1"), Times.Once);
	}

	[Fact]
	public async Task GetFileReportAsync_WithDetections_ReconstructsThreats()
	{
		var cached = new VirusTotalCacheEntry
		{
			SHA256 = "hash1",
			CreatedAt = DateTime.UtcNow.AddHours(-1),
			TotalEngines = 70,
			Detections = 2,
			Threats = ["Engine1: Trojan.Gen", "Engine2: Malware.AI"],
			NotInDatabase = false
		};
		_cacheRepository.Setup(r => r.FindByHash("hash1")).Returns(cached);

		var result = await _service.GetFileReportAsync("hash1");

		Assert.NotNull(result);
		Assert.Equal("Engine1: Trojan.Gen, Engine2: Malware.AI", result.Threats);
	}
}
