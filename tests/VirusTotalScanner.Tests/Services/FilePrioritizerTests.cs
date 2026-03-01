using VirusTotalScanner.Services;

namespace VirusTotalScanner.Tests.Services;

public sealed class FilePrioritizerTests
{
	private readonly FilePrioritizer _prioritizer = new();

	[Fact]
	public void Prioritize_MixedExtensions_ReturnsExecutablesFirst()
	{
		var files = new[]
		{
			@"C:\docs\readme.txt",
			@"C:\scripts\run.ps1",
			@"C:\bin\app.exe",
			@"C:\lib\core.dll",
		};

		var result = _prioritizer.Prioritize(files);

		Assert.Equal(new[]
		{
			@"C:\bin\app.exe",
			@"C:\lib\core.dll",
			@"C:\scripts\run.ps1",
			@"C:\docs\readme.txt",
		}, result);
	}

	[Fact]
	public void Prioritize_UnknownExtensions_GoLast()
	{
		var files = new[]
		{
			@"C:\data\file.xyz",
			@"C:\data\file.abc",
			@"C:\bin\app.exe",
		};

		var result = _prioritizer.Prioritize(files);

		Assert.Equal(@"C:\bin\app.exe", result[0]);
		Assert.Equal(@"C:\data\file.xyz", result[1]);
		Assert.Equal(@"C:\data\file.abc", result[2]);
	}

	[Fact]
	public void Prioritize_SamePriority_PreservesOriginalOrder()
	{
		var files = new[]
		{
			@"C:\bin\second.dll",
			@"C:\bin\first.exe",
			@"C:\bin\third.sys",
		};

		var result = _prioritizer.Prioritize(files);

		Assert.Equal(new[]
		{
			@"C:\bin\second.dll",
			@"C:\bin\first.exe",
			@"C:\bin\third.sys",
		}, result);
	}

	[Fact]
	public void Prioritize_CaseInsensitive_MatchesExtensions()
	{
		var files = new[]
		{
			@"C:\docs\readme.txt",
			@"C:\bin\APP.EXE",
			@"C:\bin\Lib.Dll",
		};

		var result = _prioritizer.Prioritize(files);

		Assert.Equal(@"C:\bin\APP.EXE", result[0]);
		Assert.Equal(@"C:\bin\Lib.Dll", result[1]);
		Assert.Equal(@"C:\docs\readme.txt", result[2]);
	}

	[Fact]
	public void Prioritize_EmptyList_ReturnsEmpty()
	{
		var result = _prioritizer.Prioritize(Array.Empty<string>());

		Assert.Empty(result);
	}
}
