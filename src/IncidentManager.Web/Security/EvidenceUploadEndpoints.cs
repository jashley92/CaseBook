using System.Buffers;
using IncidentManager.Application.Evidence;
using IncidentManager.Application.Security;
using Microsoft.AspNetCore.Antiforgery;

namespace IncidentManager.Web.Security;

/// <summary>
/// PROD-56: the large-upload endpoints the Evidence tab uses for files over 100 MB, sent in 8 MB parts so no request is
/// near IIS's limit and a lost part is just sent again. Every request is the signed-in person's own (cookie and Windows
/// sign-in), carries the page's antiforgery token in a header (a cross-site page can't make one), is refused as a passive
/// or cross-site load, and is rate-limited; <see cref="EvidenceService"/> re-checks the permission and the case on each.
/// </summary>
public static class EvidenceUploadEndpoints
{
    /// <summary>The header the page sends its antiforgery token in (the antiforgery default).</summary>
    public const string TokenHeader = "RequestVerificationToken";

    public sealed record BeginRequest(Guid CaseId, string Name, string? ContentType, long Size, string? Description);

    public static void MapEvidenceUploads(this IEndpointRouteBuilder app)
    {
        var uploads = app.MapGroup("/evidence/uploads")
            .RequireAuthorization(Policies.EditCases)
            .RequireRateLimiting("uploads")
            .RefusePassiveLoads()
            .AddEndpointFilter(async (context, next) =>
            {
                var antiforgery = context.HttpContext.RequestServices.GetRequiredService<IAntiforgery>();
                if (!await antiforgery.IsRequestValidAsync(context.HttpContext))
                    return Problem(StatusCodes.Status400BadRequest, "The page's security token is missing or out of date. Reload the page and try again.");
                return await next(context);
            });

        uploads.MapPost("/", (BeginRequest request, EvidenceService evidence, HttpContext http, CancellationToken ct) =>
            Run(http, async () =>
            {
                var started = await evidence.BeginUploadAsync(request.CaseId, request.Name ?? "", request.ContentType ?? "",
                    request.Size, request.Description, ct);
                return Results.Json(new { started.Id, started.PartBytes, started.Parts });
            }));

        uploads.MapPut("/{id}/{part:int}", (string id, int part, HttpRequest request, EvidenceService evidence, CancellationToken ct) =>
            Run(request.HttpContext, async () =>
            {
                var buffer = ArrayPool<byte>.Shared.Rent(EvidenceUploadSessions.PartBytes + 1);
                try
                {
                    // A part is read whole before any byte is written, so a request cut off mid-way writes nothing.
                    var length = 0;
                    int n;
                    while ((n = await request.Body.ReadAsync(buffer.AsMemory(length, buffer.Length - length), ct)) > 0)
                    {
                        length += n;
                        if (length > EvidenceUploadSessions.PartBytes)
                            return Problem(StatusCodes.Status413PayloadTooLarge, "That part is larger than a part can be.");
                    }
                    var received = await evidence.AppendPartAsync(id, part, buffer.AsMemory(0, length), ct);
                    return Results.Json(new { received });
                }
                finally { ArrayPool<byte>.Shared.Return(buffer); }
            }));

        uploads.MapPost("/{id}/complete", (string id, EvidenceService evidence, HttpContext http, CancellationToken ct) =>
            Run(http, async () =>
            {
                var recorded = await evidence.CompleteUploadAsync(id, ct);
                return Results.Json(new { recorded.Id, recorded.OriginalFileName, recorded.SizeBytes, recorded.Sha256 });
            }));

        uploads.MapDelete("/{id}", (string id, EvidenceService evidence, HttpContext http, CancellationToken ct) =>
            Run(http, async () =>
            {
                await evidence.AbandonUploadAsync(id, ct);
                return Results.NoContent();
            }));
    }

    // CaseBook's refusals keep their wording (the page shows them); anything else is logged and answered plainly.
    private static async Task<IResult> Run(HttpContext http, Func<Task<IResult>> step)
    {
        try { return await step(); }
        catch (ForbiddenException) { return Problem(StatusCodes.Status403Forbidden, "You can't add evidence to this case."); }
        catch (Application.Common.NotFoundException ex) { return Problem(StatusCodes.Status404NotFound, ex.Message); }
        catch (ArgumentException ex) { return Problem(StatusCodes.Status400BadRequest, ex.Message); }
        catch (IncidentManager.Application.Abstractions.EvidenceKeyUnavailableException ex) { return Problem(StatusCodes.Status503ServiceUnavailable, ex.Message); }
        catch (InvalidOperationException ex) when (ex.Message.StartsWith("Case not found", StringComparison.Ordinal))
        {
            return Problem(StatusCodes.Status404NotFound, "That case isn't there, or you can't see it.");
        }
        catch (InvalidOperationException ex) { return Problem(StatusCodes.Status409Conflict, ex.Message); }
        catch (IOException ex)
        {
            http.RequestServices.GetRequiredService<ILogger<EvidenceUploadSessions>>()
                .LogError(ex, "A large evidence upload couldn't be written to the evidence store.");
            return Problem(StatusCodes.Status503ServiceUnavailable,
                "The evidence store couldn't be written. Try again; if it keeps failing, ask an administrator to check the store.");
        }
    }

    private static IResult Problem(int status, string message) => Results.Json(new { error = message }, statusCode: status);
}
