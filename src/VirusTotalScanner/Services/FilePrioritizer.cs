namespace VirusTotalScanner.Services;

internal sealed class FilePrioritizer : IFilePrioritizer
{
	private static readonly Dictionary<string, int> ExtensionPriority = new(StringComparer.OrdinalIgnoreCase)
	{
		// Priority 0: Executables & native code
		[".exe"] = 0, [".dll"] = 0, [".sys"] = 0, [".drv"] = 0,
		[".ocx"] = 0, [".cpl"] = 0, [".scr"] = 0, [".com"] = 0,

		// Priority 1: Installers & packages
		[".msi"] = 1, [".msix"] = 1, [".appx"] = 1, [".cab"] = 1, [".apk"] = 1,

		// Priority 2: Scripts
		[".bat"] = 2, [".cmd"] = 2, [".ps1"] = 2, [".psm1"] = 2,
		[".vbs"] = 2, [".vbe"] = 2, [".js"] = 2, [".jse"] = 2,
		[".wsf"] = 2, [".wsh"] = 2, [".sh"] = 2, [".py"] = 2,
		[".rb"] = 2, [".pl"] = 2, [".lua"] = 2,

		// Priority 3: Documents (macro-capable)
		[".doc"] = 3, [".docm"] = 3, [".xls"] = 3, [".xlsm"] = 3,
		[".ppt"] = 3, [".pptm"] = 3, [".docx"] = 3, [".xlsx"] = 3,
		[".pptx"] = 3, [".pdf"] = 3, [".rtf"] = 3,

		// Priority 4: Archives
		[".zip"] = 4, [".rar"] = 4, [".7z"] = 4, [".tar"] = 4,
		[".gz"] = 4, [".iso"] = 4, [".img"] = 4,
	};

	private const int DefaultPriority = 5;

	public IReadOnlyList<string> Prioritize(IEnumerable<string> filePaths)
	{
		return filePaths.OrderBy(getPriority).ToList();
	}

	private static int getPriority(string filePath)
	{
		var extension = Path.GetExtension(filePath);
		return ExtensionPriority.GetValueOrDefault(extension, DefaultPriority);
	}
}
