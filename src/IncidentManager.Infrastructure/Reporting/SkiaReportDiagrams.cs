using IncidentManager.Application.Reporting;
using IncidentManager.Domain.Enums;
using SkiaSharp;

namespace IncidentManager.Infrastructure.Reporting;

/// <summary>
/// PROD-46: draws the report pictures with SkiaSharp, using the bundled DejaVu Sans faces so output is identical on
/// Windows/IIS and Linux CI. Images are drawn at 2× for print sharpness; the renderers size them to page width.
/// Colours come from <see cref="DiagramPalette"/>, the same palette the app's screens use.
/// </summary>
public sealed class SkiaReportDiagrams : IReportDiagrams
{
    private const float Scale = 2f;              // pixels per logical unit (print sharpness)
    private const float Width = 1000f;           // logical width; the renderers fit this to the page
    private const int StepsPerImage = 6;         // longer chains wrap into several images

    private static readonly Lazy<SKTypeface> Regular = new(() => LoadFace("DejaVuSans.ttf"));
    private static readonly Lazy<SKTypeface> Bold = new(() => LoadFace("DejaVuSans-Bold.ttf"));

    private static SKTypeface LoadFace(string face)
    {
        var bytes = EmbeddedFonts.Get(face);
        return SKTypeface.FromData(SKData.CreateCopy(bytes)) ?? SKTypeface.Default;
    }

    // ── Attack chain ─────────────────────────────────────────────────────────────────────────────

    public IReadOnlyList<byte[]> AttackChain(IReadOnlyList<DiagramStep> steps)
    {
        if (steps.Count == 0) return [];

        // Lanes: the tactics the chain touches, in ATT&CK matrix order, the same in every wrapped image.
        var primary = steps.ToDictionary(s => s.Order, Primary);
        var lanes = primary.Values.Distinct().OrderBy(DiagramPalette.TacticRank).ToList();

        var images = new List<byte[]>();
        foreach (var chunk in steps.Chunk(StepsPerImage))
            images.Add(DrawChain(chunk, lanes, primary, continues: chunk[^1].Order < steps[^1].Order));
        return images;
    }

    private static MitreTactic Primary(DiagramStep s) =>
        s.Tactics.Where(t => t != MitreTactic.Unspecified).OrderBy(DiagramPalette.TacticRank).DefaultIfEmpty(MitreTactic.Unspecified).First();

    private static byte[] DrawChain(DiagramStep[] steps, List<MitreTactic> lanes, Dictionary<int, MitreTactic> primary, bool continues)
    {
        // Sized for print: 1000 units become 17 cm, so 14-unit text prints at about 8.5 pt.
        const float labelW = 180f, top = 38f, laneH = 76f, pad = 8f;
        var height = top + lanes.Count * laneH + 10f;
        var colW = Math.Min(260f, (Width - labelW - 16f) / Math.Max(steps.Length, 1));

        return Draw(Width, height, canvas =>
        {
            using var laneLabel = Font(Bold.Value, 14f);
            using var small = Font(Regular.Value, 12.5f);
            using var boxTitle = Font(Bold.Value, 14.5f);
            using var boxText = Font(Regular.Value, 13f);

            // Lanes: alternating bands, a colour bar and the tactic name.
            for (var i = 0; i < lanes.Count; i++)
            {
                var y = top + i * laneH;
                using var band = Fill(i % 2 == 0 ? "#f5f6f8" : "#ffffff");
                canvas.DrawRect(0, y, Width, laneH, band);
                using var bar = Fill(DiagramPalette.TacticColor(lanes[i]));
                canvas.DrawRect(0, y, 5, laneH, bar);
                using var ink = Fill("#343a40");
                canvas.DrawText(Fit(DiagramPalette.TacticLabel(lanes[i]), labelW - 20, laneLabel), 14, y + laneH / 2 + 4, SKTextAlign.Left, laneLabel, ink);
            }

            // Step headers and boxes.
            var boxes = new SKRect[steps.Length];
            for (var i = 0; i < steps.Length; i++)
            {
                var s = steps[i];
                var x = labelW + i * colW;
                using var muted = Fill("#6c757d");
                canvas.DrawText($"#{s.Order} · {s.OccurredAtUtc:MM-dd HH:mm}", x + colW / 2, top - 12, SKTextAlign.Center, small, muted);

                var lane = lanes.IndexOf(primary[s.Order]);
                var rect = new SKRect(x + pad, top + lane * laneH + 7, x + colW - pad, top + (lane + 1) * laneH - 7);
                boxes[i] = rect;
                var color = DiagramPalette.TacticColor(primary[s.Order]);
                using (var fill = Fill(color, alpha: 38)) canvas.DrawRoundRect(rect, 6, 6, fill);
                using (var stroke = Stroke(color, 2f)) canvas.DrawRoundRect(rect, 6, 6, stroke);

                using var ink = Fill("#212529");
                var extra = s.Tactics.Count(t => t != MitreTactic.Unspecified) - 1;
                var title = $"#{s.Order}" + (string.IsNullOrWhiteSpace(s.TechniqueId) ? "" : $"  {s.TechniqueId}") + (extra > 0 ? $"  +{extra}" : "");
                canvas.DrawText(Fit(title, rect.Width - 10, boxTitle), rect.Left + 7, rect.Top + 21, SKTextAlign.Left, boxTitle, ink);
                var who = (s.Actor, s.Target) switch
                {
                    ("", "") => "",
                    (var a, "") => a,
                    ("", var t) => "→ " + t,
                    var (a, t) => $"{a} → {t}"
                };
                if (who.Length > 0)
                    DrawWrapped(canvas, who, rect.Left + 7, rect.Top + 40, rect.Width - 12, boxText, ink, maxLines: 2);
            }

            // Arrows between consecutive steps (an elbow when the lane changes).
            using var arrow = Stroke("#495057", 1.6f);
            using var head = Fill("#495057");
            for (var i = 0; i + 1 < boxes.Length; i++)
            {
                var a = boxes[i];
                var b = boxes[i + 1];
                var start = new SKPoint(a.Right, a.MidY);
                var end = new SKPoint(b.Left, b.MidY);
                var midX = (start.X + end.X) / 2;
                using var builder = new SKPathBuilder();
                builder.MoveTo(start);
                builder.LineTo(midX, start.Y);
                builder.LineTo(midX, end.Y);
                builder.LineTo(end.X - 6, end.Y);
                using var path = builder.Detach();
                canvas.DrawPath(path, arrow);
                ArrowHead(canvas, new SKPoint(end.X - 6, end.Y), end, head);
            }
            if (continues && boxes.Length > 0)
            {
                using var muted = Fill("#6c757d");
                canvas.DrawText("continued →", Width - 8, top - 12, SKTextAlign.Right, small, muted);
            }
        });
    }

    // ── Entity graph ─────────────────────────────────────────────────────────────────────────────

    public byte[]? EntityGraph(IReadOnlyList<DiagramNode> nodes, IReadOnlyList<DiagramEdge> edges)
    {
        // Draw the connected part: isolated entities are in the table and would only clutter the picture.
        var used = edges.SelectMany(e => new[] { e.From, e.To }).ToHashSet();
        var shown = nodes.Where(n => used.Contains(n.Id)).ToList();
        if (shown.Count == 0) return null;

        const float height = 540f, marginX = 120f, marginTop = 40f, marginBottom = 80f, radius = 20f;
        var pos = Layout(shown, marginX, marginTop, Width - marginX, height - marginBottom);

        return Draw(Width, height, canvas =>
        {
            using var edgeInk = Stroke("#868e96", 1.5f);
            using var headInk = Fill("#868e96");
            using var edgeFont = Font(Regular.Value, 13f);
            using var nodeFont = Font(Bold.Value, 11f);
            using var labelFont = Font(Regular.Value, 14f);

            foreach (var e in edges)
            {
                if (!pos.TryGetValue(e.From, out var a) || !pos.TryGetValue(e.To, out var b) || e.From == e.To) continue;
                var dir = Normalize(b - a);
                var from = a + Mul(dir, radius);
                var to = b - Mul(dir, radius + 2);
                canvas.DrawLine(from, to, edgeInk);
                ArrowHead(canvas, from, to, headInk);

                // The relationship name on a white pill at the midpoint.
                var mid = new SKPoint((from.X + to.X) / 2, (from.Y + to.Y) / 2);
                var text = Fit(e.Label, 170, edgeFont);
                var w = edgeFont.MeasureText(text) + 10;
                using var pill = Fill("#ffffff", alpha: 235);
                canvas.DrawRoundRect(new SKRect(mid.X - w / 2, mid.Y - 10, mid.X + w / 2, mid.Y + 7), 4, 4, pill);
                using var ink = Fill("#495057");
                canvas.DrawText(text, mid.X, mid.Y + 4, SKTextAlign.Center, edgeFont, ink);
            }

            foreach (var n in shown)
            {
                var p = pos[n.Id];
                using var fill = Fill(DiagramPalette.DispositionColor(n.Disposition));
                canvas.DrawCircle(p, radius, fill);
                using var white = Fill("#ffffff");
                canvas.DrawText(TypeAbbrev(n.Type), p.X, p.Y + 4f, SKTextAlign.Center, nodeFont, white);
                using var ink = Fill("#212529");
                canvas.DrawText(Fit(n.Label, 220, labelFont), p.X, p.Y + radius + 18, SKTextAlign.Center, labelFont, ink);
            }

            // Legend: what the colours mean.
            var lx = 14f;
            var ly = height - 18f;
            foreach (var d in new[] { EntityDisposition.Malicious, EntityDisposition.Suspicious, EntityDisposition.Compromised,
                         EntityDisposition.Benign, EntityDisposition.Unknown })
            {
                using var dot = Fill(DiagramPalette.DispositionColor(d));
                canvas.DrawCircle(lx + 5, ly - 4, 5, dot);
                using var ink = Fill("#495057");
                var label = d.ToString();
                canvas.DrawText(label, lx + 14, ly, SKTextAlign.Left, edgeFont, ink);
                lx += 24 + edgeFont.MeasureText(label);
            }
        });
    }

    /// <summary>The analyst's saved layout scaled into the frame when every node has one; otherwise a circle by type.</summary>
    private static Dictionary<Guid, SKPoint> Layout(List<DiagramNode> nodes, float left, float top, float right, float bottom)
    {
        var result = new Dictionary<Guid, SKPoint>();
        if (nodes.All(n => n.X is not null && n.Y is not null) && nodes.Count > 1)
        {
            double minX = nodes.Min(n => n.X!.Value), maxX = nodes.Max(n => n.X!.Value);
            double minY = nodes.Min(n => n.Y!.Value), maxY = nodes.Max(n => n.Y!.Value);
            var spanX = Math.Max(maxX - minX, 1);
            var spanY = Math.Max(maxY - minY, 1);
            var s = Math.Min((right - left) / spanX, (bottom - top) / spanY);   // keep the drawn proportions
            var offX = left + ((right - left) - spanX * s) / 2;
            var offY = top + ((bottom - top) - spanY * s) / 2;
            foreach (var n in nodes)
                result[n.Id] = new SKPoint((float)(offX + (n.X!.Value - minX) * s), (float)(offY + (n.Y!.Value - minY) * s));
            return result;
        }

        var ordered = nodes.OrderBy(n => n.Type).ThenBy(n => n.Label, StringComparer.OrdinalIgnoreCase).ToList();
        var cx = (left + right) / 2;
        var cy = (top + bottom) / 2;
        var rx = (right - left) / 2;
        var ry = (bottom - top) / 2;
        for (var i = 0; i < ordered.Count; i++)
        {
            var angle = -Math.PI / 2 + 2 * Math.PI * i / ordered.Count;
            result[ordered[i].Id] = ordered.Count == 1
                ? new SKPoint(cx, cy)
                : new SKPoint((float)(cx + rx * Math.Cos(angle)), (float)(cy + ry * Math.Sin(angle)));
        }
        return result;
    }

    private static string TypeAbbrev(EntityType t) => t switch
    {
        EntityType.IpAddress => "IP",
        EntityType.Domain => "DOM",
        EntityType.Url => "URL",
        EntityType.EmailAddress => "MAIL",
        EntityType.FileHash => "HASH",
        EntityType.FileName => "FILE",
        EntityType.Host => "HOST",
        EntityType.Account => "ACCT",
        EntityType.Process => "PROC",
        EntityType.RegistryKey => "REG",
        _ => "?"
    };

    // ── Drawing helpers ──────────────────────────────────────────────────────────────────────────

    private static byte[] Draw(float width, float height, Action<SKCanvas> paint)
    {
        var info = new SKImageInfo((int)Math.Ceiling(width * Scale), (int)Math.Ceiling(height * Scale));
        using var surface = SKSurface.Create(info);
        var canvas = surface.Canvas;
        canvas.Clear(SKColors.White);
        canvas.Scale(Scale);
        paint(canvas);
        using var image = surface.Snapshot();
        using var data = image.Encode(SKEncodedImageFormat.Png, 100);
        return data.ToArray();
    }

    private static SKFont Font(SKTypeface face, float size) => new(face, size) { Subpixel = true };

    private static SKPaint Fill(string hex, byte alpha = 255) =>
        new() { Color = SKColor.Parse(hex).WithAlpha(alpha), Style = SKPaintStyle.Fill, IsAntialias = true };

    private static SKPaint Stroke(string hex, float width) =>
        new() { Color = SKColor.Parse(hex), Style = SKPaintStyle.Stroke, StrokeWidth = width, IsAntialias = true };

    private static void ArrowHead(SKCanvas canvas, SKPoint from, SKPoint to, SKPaint paint)
    {
        var dir = Normalize(to - from);
        var normal = new SKPoint(-dir.Y, dir.X);
        using var builder = new SKPathBuilder();
        builder.MoveTo(to);
        builder.LineTo(to - Mul(dir, 8) + Mul(normal, 4));
        builder.LineTo(to - Mul(dir, 8) - Mul(normal, 4));
        builder.Close();
        using var path = builder.Detach();
        canvas.DrawPath(path, paint);
    }

    private static SKPoint Normalize(SKPoint v)
    {
        var len = (float)Math.Sqrt(v.X * v.X + v.Y * v.Y);
        return len < 0.001f ? new SKPoint(1, 0) : new SKPoint(v.X / len, v.Y / len);
    }

    private static SKPoint Mul(SKPoint v, float k) => new(v.X * k, v.Y * k);

    /// <summary>Word-wrapped text over at most <paramref name="maxLines"/> lines, the last cut with an ellipsis.</summary>
    private static void DrawWrapped(SKCanvas canvas, string text, float x, float y, float maxWidth, SKFont font, SKPaint paint, int maxLines)
    {
        var lines = new List<string>();
        var current = "";
        foreach (var word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = current.Length == 0 ? word : current + " " + word;
            if (font.MeasureText(candidate) <= maxWidth || current.Length == 0) { current = candidate; continue; }
            lines.Add(current);
            current = word;
        }
        if (current.Length > 0) lines.Add(current);
        if (lines.Count > maxLines)
            lines = [.. lines.Take(maxLines - 1), string.Join(' ', lines.Skip(maxLines - 1))];
        var lineHeight = font.Size * 1.2f;
        for (var i = 0; i < lines.Count; i++)
            canvas.DrawText(Fit(lines[i], maxWidth, font), x, y + i * lineHeight, SKTextAlign.Left, font, paint);
    }

    /// <summary>The text, cut with an ellipsis to fit <paramref name="maxWidth"/>.</summary>
    private static string Fit(string text, float maxWidth, SKFont font)
    {
        if (string.IsNullOrEmpty(text) || font.MeasureText(text) <= maxWidth) return text ?? "";
        var s = text;
        while (s.Length > 1 && font.MeasureText(s + "…") > maxWidth) s = s[..^1];
        return s + "…";
    }
}
