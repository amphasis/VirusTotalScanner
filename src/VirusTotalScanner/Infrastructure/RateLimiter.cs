namespace VirusTotalScanner.Infrastructure;

internal sealed class RateLimiter : IRateLimiter
{
	private readonly TimeSpan _minInterval;
	private DateTime _lastRequestTime = DateTime.MinValue;

	public RateLimiter(TimeSpan? minInterval = null)
	{
		_minInterval = minInterval ?? TimeSpan.FromSeconds(15);
	}

	public async Task WaitAsync()
	{
		var elapsed = DateTime.UtcNow - _lastRequestTime;
		if (elapsed < _minInterval)
		{
			await Task.Delay(_minInterval - elapsed);
		}
		_lastRequestTime = DateTime.UtcNow;
	}
}
