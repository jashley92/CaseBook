using FluentAssertions;
using IncidentManager.Web.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace IncidentManager.IntegrationTests;

/// <summary>
/// The passwordless dev sign-in (every visitor gets the DevAuth roles, all five by default) runs only in
/// Development, or in a non-Production environment that explicitly opts in. A Staging or QA server without
/// <c>Auth:Mode=Windows</c> must refuse to start rather than sign everyone in as an administrator.
/// </summary>
public sealed class AuthModeGuardTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "casebook-authmode", Guid.NewGuid().ToString("N"));

    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => (string?)v.Value)).Build();

    private sealed class Env(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "CaseBook";
        public string ContentRootPath { get; set; } = "";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Staging")]
    [InlineData("QA")]
    [InlineData("Production")]
    public void Windows_mode_is_allowed_everywhere(string environment) =>
        AuthModeGuard.UseWindows(new Env(environment), Config(("Auth:Mode", "Windows"))).Should().BeTrue();

    [Fact]
    public void Development_uses_dev_sign_in_when_the_mode_is_not_Windows()
    {
        AuthModeGuard.UseWindows(new Env("Development"), Config(("Auth:Mode", "Dev"))).Should().BeFalse();
        AuthModeGuard.UseWindows(new Env("Development"), Config()).Should().BeFalse();
    }

    [Theory]
    [InlineData("Staging")]
    [InlineData("QA")]
    [InlineData("Test")]
    public void Any_other_environment_without_Windows_refuses_to_start(string environment)
    {
        var act = () => AuthModeGuard.UseWindows(new Env(environment), Config(("Auth:Mode", "Dev")));
        act.Should().Throw<InvalidOperationException>().WithMessage($"*'{environment}'*Auth:Mode=Windows*");

        var missing = () => AuthModeGuard.UseWindows(new Env(environment), Config());
        missing.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void A_non_Production_environment_can_opt_in_explicitly()
    {
        AuthModeGuard.UseWindows(new Env("Staging"),
            Config(("Auth:Mode", "Dev"), (AuthModeGuard.AllowOutsideDevelopmentKey, "true"))).Should().BeFalse();
        var notTrue = () => AuthModeGuard.UseWindows(new Env("Staging"),
            Config(("Auth:Mode", "Dev"), (AuthModeGuard.AllowOutsideDevelopmentKey, "false")));
        notTrue.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Production_refuses_dev_sign_in_even_with_the_opt_in()
    {
        var act = () => AuthModeGuard.UseWindows(new Env("Production"),
            Config(("Auth:Mode", "Dev"), (AuthModeGuard.AllowOutsideDevelopmentKey, "true")));
        act.Should().Throw<InvalidOperationException>().WithMessage("*Production requires Auth:Mode=Windows*");
    }

    [Fact]
    public void The_real_host_refuses_to_start_in_Staging_with_dev_sign_in()
    {
        // Through Program.cs, so the guard can't be bypassed by wiring authentication some other way.
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Staging");
            b.UseSetting("Auth:Mode", "Dev");
            b.UseSetting("ConnectionStrings:Default", $"Data Source={Path.Combine(_dir, "casebook.db")}");
            b.UseSetting("Database:Provider", "Sqlite");
        });
        var act = () => factory.CreateClient();
        act.Should().Throw<InvalidOperationException>().WithMessage("*'Staging'*");
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
