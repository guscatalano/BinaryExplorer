using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BinaryExplorer.Core;
using BinaryExplorer.Inspectors;
using Xunit;

namespace BinaryExplorer.Tests;

public class MsiTests
{
    private static string FixturePath() =>
        Path.Combine(AppContext.BaseDirectory, "fixtures", "sample.msi");

    [Fact]
    public void Fixture_msi_exists_and_is_compound_file()
    {
        string path = FixturePath();
        Assert.True(File.Exists(path), $"Fixture not found: {path}");

        var bytes = File.ReadAllBytes(path);
        // CFB magic: D0 CF 11 E0 A1 B1 1A E1.
        Assert.True(bytes.Length >= 8);
        Assert.Equal(0xD0, bytes[0]);
        Assert.Equal(0xCF, bytes[1]);
        Assert.Equal(0x11, bytes[2]);
        Assert.Equal(0xE0, bytes[3]);
    }

    [Fact]
    public async Task MsiInspector_reads_product_info()
    {
        var ctx = new BinaryContext(FixturePath());
        var result = await new MsiInspector().InspectAsync(ctx);

        Assert.Equal("MSI", result.InspectorName);
        Assert.True(string.IsNullOrEmpty(result.Error), $"Unexpected error: {result.Error}");
        Assert.DoesNotContain("failed", result.Headline ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Not an MSI", result.Headline ?? "", StringComparison.Ordinal);

        var byTitle = result.Findings.ToDictionary(f => f.Title, f => f.Value);
        Assert.Equal("BinaryExplorerTestFixture", byTitle["ProductName"]);
        Assert.Equal("1.0.0.0", byTitle["ProductVersion"]);
        Assert.Equal("BinaryExplorer Tests", byTitle["Manufacturer"]);

        string code = byTitle["ProductCode"] ?? "";
        Assert.StartsWith("{", code);
        Assert.EndsWith("}", code);

        Assert.Contains("Files", byTitle.Keys);
        Assert.Contains("Components", byTitle.Keys);
        Assert.Equal("1", byTitle["Components"]);
    }

    [Fact]
    public async Task LanguageInspector_reports_non_PE_for_msi()
    {
        var ctx = new BinaryContext(FixturePath());
        var result = await new LanguageInspector().InspectAsync(ctx);

        Assert.Equal("Language", result.InspectorName);
        Assert.True(string.IsNullOrEmpty(result.Error));
        Assert.Contains("MSI", result.Headline ?? "", StringComparison.Ordinal);
    }
}
