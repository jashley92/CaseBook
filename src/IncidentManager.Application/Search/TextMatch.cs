using System.Linq.Expressions;
using IncidentManager.Application.Abstractions;

namespace IncidentManager.Application.Search;

/// <summary>CAP-22: the full-text search one query may use: the provider's predicate and the columns indexed when it began.</summary>
public sealed record FullTextPlan(IFullTextSearch Search, FullTextStatus Status);

/// <summary>
/// CAP-22: a text column's match, written once in a query and turned into SQL by <see cref="Prepare{T}"/>: by word on SQL
/// Server where that column is full-text indexed (<c>CONTAINS(column, '"term*"')</c>), and otherwise as the substring match
/// it always was (<c>LOWER(column) LIKE '%term%'</c>). A query's predicate names each column through
/// <see cref="Has(string?, string, string?)"/> and is passed through <see cref="Prepare{T}"/> before it's used.
/// </summary>
public static class TextMatch
{
    /// <summary>
    /// Whether <paramref name="column"/> holds <paramref name="term"/> (lower case): only a marker for
    /// <see cref="Prepare{T}"/>, which replaces it; called directly (in memory) it's the substring match.
    /// <paramref name="condition"/> is the term's <see cref="FullTextCondition"/>, null when it's matched by substring.
    /// </summary>
    public static bool Has(string? column, string term, string? condition) =>
        column is not null && column.Contains(term, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// <paramref name="predicate"/> with each <see cref="Has"/> replaced: by the full-text predicate when
    /// <paramref name="plan"/> is given and covers that column, otherwise by the substring match. Pass a null plan for a
    /// term with no full-text condition (<see cref="FullTextCondition.For"/> returned null).
    /// </summary>
    public static Expression<Func<T, bool>> Prepare<T>(Expression<Func<T, bool>> predicate, FullTextPlan? plan) =>
        (Expression<Func<T, bool>>)new Rewriter(plan).Visit(predicate);

    private static readonly System.Reflection.MethodInfo HasMethod =
        typeof(TextMatch).GetMethod(nameof(Has), [typeof(string), typeof(string), typeof(string)])!;

#pragma warning disable CA1304, CA1311, CA1862 // EF Core translates ToLower()/Contains() to SQL; culture overloads don't translate.
    private static readonly Expression<Func<string?, string, bool>> Like = (column, term) => column != null && column.ToLower().Contains(term);
#pragma warning restore CA1304, CA1311, CA1862

    private sealed class Rewriter(FullTextPlan? plan) : ExpressionVisitor
    {
        protected override Expression VisitMethodCall(MethodCallExpression node)
        {
            if (node.Method != HasMethod) return base.VisitMethodCall(node);
            var column = Visit(node.Arguments[0]);
            if (plan is not null && column is MemberExpression { Expression: { } owner } member
                                 && plan.Status.Covers(owner.Type, member.Member.Name))
                return Inline(plan.Search.ContainsTemplate, column, Visit(node.Arguments[2]));
            return Inline(Like, column, Visit(node.Arguments[1]));
        }
    }

    // The template's body with its two parameters replaced by these expressions.
    private static Expression Inline(Expression<Func<string?, string, bool>> template, Expression first, Expression second) =>
        new Substitute(template.Parameters[0], first, template.Parameters[1], second).Visit(template.Body);

    private sealed class Substitute(ParameterExpression a, Expression aTo, ParameterExpression b, Expression bTo) : ExpressionVisitor
    {
        protected override Expression VisitParameter(ParameterExpression node) =>
            node == a ? aTo : node == b ? bTo : base.VisitParameter(node);
    }
}
