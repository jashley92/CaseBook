using FluentAssertions;
using IncidentManager.Application.Security;
using Xunit;

namespace IncidentManager.UnitTests;

public class LockReturnPageTests
{
    private const string Base = "https://casebook.corp.example/";

    [Theory]
    [InlineData("https://casebook.corp.example/cases/IR-2026-0042", "cases/IR-2026-0042")]
    [InlineData("https://casebook.corp.example/cases?status=open&sort=sla", "cases?status=open&sort=sla")]
    [InlineData("https://casebook.corp.example/cases/IR-2026-0042#timeline", "cases/IR-2026-0042#timeline")]
    [InlineData("https://CASEBOOK.corp.example/admin/settings/security", "admin/settings/security")]
    public void A_page_of_the_app_is_resumed_on(string stored, string expected) =>
        LockReturnPage.Resolve(stored, Base).Should().Be(expected);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("cases/IR-1")]                                         // not an address
    [InlineData("https://evil.example/cases/IR-1")]                    // another site
    [InlineData("http://casebook.corp.example/cases/IR-1")]            // another scheme
    [InlineData("https://casebook.corp.example:8443/cases/IR-1")]      // another port
    [InlineData("https://casebook.corp.example.evil.example/cases")]   // a look-alike host
    [InlineData("https://casebook.corp.example//evil.example/x")]      // would leave the app as "//host"
    [InlineData("javascript:alert(1)")]
    [InlineData("https://casebook.corp.example/")]                     // home: the default already
    [InlineData("https://casebook.corp.example/session-expired")]      // the lock page itself
    [InlineData("https://casebook.corp.example/session-expired?locked=1")]
    [InlineData("https://casebook.corp.example/Session-Expired/")]
    public void Anything_else_resumes_on_the_home_page(string? stored) =>
        LockReturnPage.Resolve(stored, Base).Should().BeNull();

    [Fact]
    public void An_overlong_value_is_not_followed() =>
        LockReturnPage.Resolve(Base + "cases/" + new string('a', LockReturnPage.MaxLength), Base).Should().BeNull();

    [Fact]
    public void Under_a_virtual_directory_only_its_own_pages_are_resumed_on()
    {
        const string app = "https://intranet.corp.example/casebook/";
        LockReturnPage.Resolve("https://intranet.corp.example/casebook/cases/IR-1", app).Should().Be("cases/IR-1");
        LockReturnPage.Resolve("https://intranet.corp.example/payroll/run", app).Should().BeNull();
        LockReturnPage.Resolve("https://intranet.corp.example/casebook/session-expired", app).Should().BeNull();
    }
}
