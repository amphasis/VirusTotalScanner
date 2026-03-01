namespace VirusTotalScanner.Services;

public sealed class QuotaExceededException : Exception
{
	public QuotaExceededException(string message) : base(message)
	{
	}
}
