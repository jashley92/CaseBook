using System.Text.RegularExpressions;
using IncidentManager.Web.Components.Shared;
using Microsoft.JSInterop;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>A component's disposal that throws ends the whole circuit, so a teardown call to the page's script must never
/// throw when the call can't happen.</summary>
public partial class JsTeardownTests
{
    [Theory]
    [InlineData(typeof(JSDisconnectedException))]
    [InlineData(typeof(TaskCanceledException))]       // the circuit cancelling the call on its way down
    [InlineData(typeof(OperationCanceledException))]
    [InlineData(typeof(InvalidOperationException))]   // a prerender
    [InlineData(typeof(JSException))]                 // the script failed: its element already gone
    public async Task StopAsync_swallows_a_call_that_cant_happen(Type failure)
    {
        var js = new FailingJs((Exception)Activator.CreateInstance(failure, "gone")!);
        await js.StopAsync("imIdle.stop");
        Assert.Equal("imIdle.stop", js.Called);
    }

    [Fact]
    public void Every_components_disposal_calls_the_script_through_StopAsync()
    {
        var dir = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(dir, "IncidentManager.sln"))) dir = Path.GetDirectoryName(dir)!;
        var components = Path.Combine(dir, "src", "IncidentManager.Web", "Components");
        var withTeardown = new List<string>();
        var offenders = new List<string>();
        foreach (var file in Directory.EnumerateFiles(components, "*.razor", SearchOption.AllDirectories)
                     .Concat(Directory.EnumerateFiles(components, "*.cs", SearchOption.AllDirectories)))
        {
            var dispose = DisposeBody().Match(File.ReadAllText(file));
            if (!dispose.Success) continue;
            var body = dispose.Groups["body"].Value;
            if (body.Contains("JS.StopAsync", StringComparison.Ordinal)) withTeardown.Add(Path.GetFileName(file));
            if (body.Contains("JS.Invoke", StringComparison.Ordinal)) offenders.Add(Path.GetFileName(file));
        }
        Assert.True(offenders.Count == 0,
            "A disposal's script call goes through JsTeardown.StopAsync, which can't end the circuit:\n" + string.Join("\n", offenders));
        // The scan has to find the disposals, or it proves nothing.
        Assert.Contains("AttackMatrixPicker.razor", withTeardown);
        Assert.Contains("DateFieldBase.cs", withTeardown);
        Assert.True(withTeardown.Count >= 9, string.Join(", ", withTeardown));
    }

    // A DisposeAsync method's body, braces balanced.
    [GeneratedRegex(@"ValueTask DisposeAsync\(\)\s*\{(?<body>(?:[^{}]|\{(?<d>)|\}(?<-d>))*)\}", RegexOptions.None, matchTimeoutMilliseconds: 2000)]
    private static partial Regex DisposeBody();

    private sealed class FailingJs(Exception failure) : IJSRuntime
    {
        public string? Called { get; private set; }

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
        {
            Called = identifier;
            return ValueTask.FromException<TValue>(failure);
        }

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args) =>
            InvokeAsync<TValue>(identifier, args);
    }
}
