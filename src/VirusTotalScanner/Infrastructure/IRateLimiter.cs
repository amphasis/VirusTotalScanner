namespace VirusTotalScanner.Infrastructure;

public interface IRateLimiter
{
    Task WaitAsync();
}
