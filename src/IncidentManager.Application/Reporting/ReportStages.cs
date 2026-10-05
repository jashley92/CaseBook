namespace IncidentManager.Application.Reporting;

/// <summary>RD-23: the stages a report's generation goes through, in order, as its progress reports them.</summary>
public static class ReportStages
{
    public const string Reading = "Reading the case";
    public const string Writing = "Writing the document";
    public const string Storing = "Storing and hashing it";

    public static readonly string[] All = [Reading, Writing, Storing];

    /// <summary>How far along a stage is, 0 to 1 (a stage counts as half done while it runs).</summary>
    public static double Fraction(string? stage) =>
        stage is null ? 0 : Array.IndexOf(All, stage) is var i and >= 0 ? (i + 0.5) / All.Length : 0;
}
