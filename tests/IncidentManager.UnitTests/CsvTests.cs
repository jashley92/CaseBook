using System.Globalization;
using System.Linq.Expressions;
using System.Reflection;
using FluentAssertions;
using IncidentManager.Application.Common;
using Xunit;

namespace IncidentManager.UnitTests;

/// <summary>
/// The shared CSV encoder (S-01): RFC-4180 quoting plus spreadsheet formula-injection (CSV / DDE)
/// neutralisation. Every export routes fields through <see cref="Csv.Escape"/>.
/// </summary>
public class CsvTests
{
    [Theory]
    // Plain data passes through untouched.
    [InlineData("plain text", "plain text")]
    [InlineData("2026-05_FS_01", "2026-05_FS_01")]   // a case number (leads with a digit)
    [InlineData("", "")]
    // Formula/DDE leaders are neutralised with a leading apostrophe.
    [InlineData("=1+1", "'=1+1")]
    [InlineData("=cmd|' /c calc'!A1", "'=cmd|' /c calc'!A1")]
    [InlineData("@SUM(A1:A9)", "'@SUM(A1:A9)")]
    [InlineData("+1+1", "'+1+1")]                     // '+' not leading a plain number
    [InlineData("-1+1", "'-1+1")]                     // '-' not leading a plain number
    [InlineData("=", "'=")]
    // Genuine signed numbers stay numeric — not turned into text.
    [InlineData("-5", "-5")]
    [InlineData("+5", "+5")]
    [InlineData("-5.5", "-5.5")]
    public void Escapes_formula_leaders_but_leaves_real_numbers(string input, string expected)
        => Csv.Escape(input).Should().Be(expected);

    [Theory]
    // BUG-579: a ';'-separator Excel starts a new cell after each ';', so each piece is guarded as a field start is.
    [InlineData("x;=1+1", "x;'=1+1")]
    [InlineData("x;@SUM(A1)", "x;'@SUM(A1)")]
    [InlineData("a;b;-1+1", "a;b;'-1+1")]
    [InlineData("=1;=2", "'=1;'=2")]
    [InlineData("x;\"=1", "\"x;'\"\"=1\"")]            // a quote opening the piece is looked past
    // Plain pieces and numbers are left alone.
    [InlineData("NY; CA", "NY; CA")]
    [InlineData("a;-5;b", "a;-5;b")]
    [InlineData("2026-01_A; 2026-02_B", "2026-01_A; 2026-02_B")]
    [InlineData("x;", "x;")]
    public void Guards_a_formula_after_each_semicolon(string input, string expected)
        => Csv.Escape(input).Should().Be(expected);

    [Theory]
    [InlineData("=1+1")]
    [InlineData("x;=1+1")]
    [InlineData("=1;@2;-3+3")]
    [InlineData("x;\"=1")]
    [InlineData("plain; text")]
    [InlineData("-5")]
    public void Unguard_gives_back_what_was_escaped(string value)
    {
        var cell = Csv.Escape(value);
        if (cell.StartsWith('"')) cell = cell[1..^1].Replace("\"\"", "\"");
        Csv.Unguard(cell).Should().Be(value);
    }

    [Fact]
    public void Null_becomes_empty()
        => Csv.Escape(null).Should().BeEmpty();

    [Fact]
    public void A_comma_triggers_rfc4180_quoting()
        => Csv.Escape("a,b").Should().Be("\"a,b\"");

    [Fact]
    public void Embedded_quotes_are_doubled_and_the_field_quoted()
        => Csv.Escape("say \"hi\"").Should().Be("\"say \"\"hi\"\"\"");

    [Fact]
    public void A_formula_leader_and_a_comma_are_both_handled()
        => Csv.Escape("=1,2").Should().Be("\"'=1,2\"");   // guarded first, then quoted for the comma

    [Fact]
    public void A_tab_leader_is_guarded()
        => Csv.Escape("\t=1").Should().Be("'\t=1");        // tab isn't a quote trigger, so no quoting

    [Fact]
    public void A_carriage_return_leader_is_guarded_and_quoted()
        => Csv.Escape("\r=1").Should().Be("\"'\r=1\"");    // CR is both a leader and a quote trigger

    // ── Hostile corpus over every CSV builder (BUG-579, C13) ─────────────────────────────────────────────────

    private static readonly string[] Hostile =
    [
        "=1+1", "@SUM(A1:A9)", "+1+1", "-1+1", "\t=1", "=cmd|' /c calc'!A1",
        "x;=1+1", "x;@SUM(A1)", "x;+1+1", "x;-1+1", "x;\t=1", "a,b;=1+1", "x;\"=1+1", "say \"hi\";=1", "=1;=2,=3",
    ];

    /// <summary>CSV builders that don't take the corpus, with the reason. Everything else that builds a CSV in the
    /// Application layer is found by reflection and run with every string it reads set to each hostile value.</summary>
    private static readonly Dictionary<string, string> NotInCorpus = new()
    {
        // The compliance bundle's chain CSVs are the verifier's input: every field must be byte-exact for the hashes
        // to recompute, so they are RFC-4180-quoted only (REPORTED as a C13 open question: an examiner opening
        // audit-chain.csv in Excel gets no formula guard).
        ["ComplianceBundlePack.AuditChainCsv"] = "verifier input, byte-exact",
        ["ComplianceBundlePack.WriteAuditChainCsv"] = "verifier input, byte-exact",
        ["ComplianceBundlePack.SealsCsv"] = "verifier input, byte-exact",
        ["AccessLogCsv.ExportLabel"] = "an access-log label, not a CSV",
        // Needs a database; every field goes through Csv.Escape (LessonsService.cs, `.Select(Csv.Escape)`).
        ["LessonsService.ExportRegisterCsvAsync"] = "instance method over the database; fields via Csv.Escape",
    };

    private static IEnumerable<MethodInfo> CsvBuilders() =>
        typeof(Csv).Assembly.GetTypes()
            .Where(t => t != typeof(Csv) && !t.IsNested)
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(m => !m.IsSpecialName)
                .Where(m => t.Name.EndsWith("Csv", StringComparison.Ordinal) || m.Name.Contains("Csv", StringComparison.Ordinal))
                .Where(m => !m.Name.StartsWith("Parse", StringComparison.Ordinal) && !m.Name.StartsWith("From", StringComparison.Ordinal))
                .Where(m => m.ReturnType == typeof(string) || m.ReturnType == typeof(Task<string>)
                            || (m.ReturnType == typeof(void) && m.GetParameters().Any(p => p.ParameterType == typeof(TextWriter)))));

    [Fact]
    public void Every_csv_builder_is_in_the_hostile_corpus_or_exempt_with_a_reason()
    {
        var found = CsvBuilders().Select(m => $"{m.DeclaringType!.Name}.{m.Name}").Distinct().ToList();
        found.Should().Contain(["AccessLogCsv.Build", "AuditCsv.Build", "IocFeedCsv.Build", "MetricsCsv.Build",
            "LegalRegisterService.ToCsv", "ProgramReportService.ToCsv"], "the registry must see the known builders");
        var notRunnable = CsvBuilders().Where(m => !m.IsStatic || m.ReturnType != typeof(string))
            .Select(m => $"{m.DeclaringType!.Name}.{m.Name}")
            .Where(n => !NotInCorpus.ContainsKey(n))
            .ToList();
        notRunnable.Should().BeEmpty("a CSV builder the corpus can't call needs its own hostile test and an entry in NotInCorpus");
    }

    public static TheoryData<string> HostileValues()
    {
        var d = new TheoryData<string>();
        foreach (var h in Hostile) d.Add(h);
        return d;
    }

    [Theory]
    [MemberData(nameof(HostileValues))]
    public void No_csv_builder_lets_a_hostile_value_start_a_cell_in_either_separator(string hostile)
    {
        var problems = new List<string>();
        var builders = CsvBuilders()
            .Where(m => m.IsStatic && m.ReturnType == typeof(string))
            .Where(m => !NotInCorpus.ContainsKey($"{m.DeclaringType!.Name}.{m.Name}"))
            .ToList();
        builders.Should().NotBeEmpty();
        foreach (var m in builders)
        {
            var args = m.GetParameters().Select(p => Build(p.ParameterType, hostile, 0)).ToArray();
            var csv = (string)m.Invoke(null, args)!;
            csv.Should().Contain(hostile[^2..], $"{m.DeclaringType!.Name}.{m.Name} should carry the value");
            foreach (var sep in new[] { ',', ';' })
                foreach (var cell in Cells(csv, sep).Where(Dangerous))
                    problems.Add($"{m.DeclaringType!.Name}.{m.Name} ('{sep}'): {cell}");
        }
        problems.Should().BeEmpty();
    }

    // A cell a spreadsheet would evaluate: it opens with a formula trigger and isn't a plain signed number.
    private static bool Dangerous(string cell) =>
        cell.Length > 0 && (cell[0] is '=' or '@' or '\t' or '\r'
            || (cell[0] is '+' or '-' && !double.TryParse(cell, NumberStyles.Number, CultureInfo.InvariantCulture, out _)));

    /// <summary>The cells a spreadsheet makes of <paramref name="csv"/> when it splits on <paramref name="sep"/>: a quote
    /// is honoured only at the start of a cell (as Excel does), and text after a closing quote is kept.</summary>
    private static IEnumerable<string> Cells(string csv, char sep)
    {
        var cell = new System.Text.StringBuilder();
        var i = 0;
        var atStart = true;
        var quoted = false;
        while (i < csv.Length)
        {
            var c = csv[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < csv.Length && csv[i + 1] == '"') { cell.Append('"'); i += 2; continue; }
                if (c == '"') { quoted = false; i++; continue; }
                cell.Append(c); i++; continue;
            }
            if (atStart && c == '"') { quoted = true; atStart = false; i++; continue; }
            if (c == sep || c == '\n' || (c == '\r' && i + 1 < csv.Length && csv[i + 1] == '\n'))
            {
                yield return cell.ToString();
                cell.Clear();
                atStart = true;
                i += c == '\r' ? 2 : 1;
                continue;
            }
            atStart = false;
            cell.Append(c); i++;
        }
        if (cell.Length > 0) yield return cell.ToString();
    }

    /// <summary>A value of <paramref name="type"/> whose every string is <paramref name="hostile"/>.</summary>
    private static object? Build(Type type, string hostile, int depth)
    {
        if (type == typeof(string)) return hostile;
        if (Nullable.GetUnderlyingType(type) is { } inner) return Build(inner, hostile, depth);
        if (type.IsEnum) return Enum.GetValues(type).GetValue(0);
        if (type == typeof(bool)) return true;
        if (type == typeof(int)) return 2;
        if (type == typeof(long)) return 2L;
        if (type == typeof(double)) return 2.5;
        if (type == typeof(decimal)) return 2.5m;
        if (type == typeof(DateTimeOffset)) return new DateTimeOffset(2026, 10, 15, 9, 30, 0, TimeSpan.Zero);
        if (type == typeof(DateTime)) return new DateTime(2026, 10, 15, 9, 30, 0, DateTimeKind.Utc);
        if (type == typeof(DateOnly)) return new DateOnly(2026, 10, 15);
        if (type == typeof(TimeSpan)) return TimeSpan.FromHours(2);
        if (type == typeof(Guid)) return Guid.Parse("3fb9669b-0000-0000-0000-000000000001");
        if (type == typeof(TimeZoneInfo)) return TimeZoneInfo.Utc;
        if (depth > 6) return null;
        if (type.IsGenericType && type.GetGenericTypeDefinition().FullName!.StartsWith("System.Func`", StringComparison.Ordinal))
        {
            var ps = type.GetGenericArguments()[..^1].Select(Expression.Parameter).ToArray();
            var ret = type.GetGenericArguments()[^1];
            return Expression.Lambda(type, Expression.Constant(Build(ret, hostile, depth + 1), ret), ps).Compile();
        }
        var element = type.IsArray ? type.GetElementType()
            : type.IsGenericType && type.GetGenericArguments().Length == 1 && typeof(System.Collections.IEnumerable).IsAssignableFrom(type)
                ? type.GetGenericArguments()[0] : null;
        if (element is not null)
        {
            var array = Array.CreateInstance(element, 2);
            for (var k = 0; k < 2; k++) array.SetValue(Build(element, hostile, depth + 1), k);
            return type.IsAssignableFrom(array.GetType()) ? array : Activator.CreateInstance(type, array);
        }
        var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).FirstOrDefault();
        if (ctor is null) return null;
        var value = ctor.Invoke(ctor.GetParameters().Select(p => Build(p.ParameterType, hostile, depth + 1)).ToArray());
        if (ctor.GetParameters().Length == 0)
            foreach (var prop in type.GetProperties().Where(p => p.CanWrite && p.SetMethod!.IsPublic))
                if (prop.PropertyType.IsValueType || prop.PropertyType == typeof(string) || Nullable.GetUnderlyingType(prop.PropertyType) is not null)
                    prop.SetValue(value, Build(prop.PropertyType, hostile, depth + 1));
        return value;
    }
}
