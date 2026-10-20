using Lanora.Data;
using Lanora.Risk;
using Lanora.Scanning;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;
using PdfSharp.Fonts;

namespace Lanora.Reports;

/// <summary>FR23: Local PDF report with PDFsharp/MigraDoc. Chart colors are accompanied by text and a numeric table.</summary>
public static class PdfReport
{
    private static readonly Color Ink = Color.FromRgb(0x20, 0x3d, 0x35);
    private static readonly Color Muted = Color.FromRgb(0x6b, 0x78, 0x71);
    private static readonly Color Line = Color.FromRgb(0xdd, 0xe4, 0xdf);
    private static readonly Color HeadFill = Color.FromRgb(0xed, 0xf3, 0xe8);

    public static byte[] Render(ReportData d)
    {
        FontSetup.Ensure();
        var t = d.T;
        var s = d.Scan;
        var doc = new Document();
        doc.Info.Title = "LANORA – " + t["title"];
        doc.Info.Author = "LANORA";

        var normal = doc.Styles[StyleNames.Normal]!;
        normal.Font.Name = FontSetup.Family;
        normal.Font.Size = 9;
        normal.Font.Color = Color.FromRgb(0x33, 0x45, 0x3f);
        normal.ParagraphFormat.SpaceAfter = Unit.FromPoint(3);
        var h1 = doc.Styles[StyleNames.Heading1]!;
        h1.Font.Size = 18; h1.Font.Bold = true; h1.Font.Color = Ink;
        h1.ParagraphFormat.SpaceAfter = Unit.FromPoint(6);
        var h2 = doc.Styles[StyleNames.Heading2]!;
        h2.Font.Size = 13; h2.Font.Bold = true; h2.Font.Color = Ink;
        h2.ParagraphFormat.SpaceBefore = Unit.FromPoint(12); h2.ParagraphFormat.SpaceAfter = Unit.FromPoint(5);
        h2.ParagraphFormat.KeepWithNext = true;
        var h3 = doc.Styles[StyleNames.Heading3]!;
        h3.Font.Size = 10.5; h3.Font.Bold = true; h3.Font.Color = Ink;
        h3.ParagraphFormat.SpaceBefore = Unit.FromPoint(8); h3.ParagraphFormat.SpaceAfter = Unit.FromPoint(3);
        h3.ParagraphFormat.KeepWithNext = true;

        var sec = doc.AddSection();
        sec.PageSetup = doc.DefaultPageSetup.Clone();
        sec.PageSetup.PageFormat = PageFormat.A4;
        sec.PageSetup.TopMargin = Unit.FromMillimeter(18);
        sec.PageSetup.BottomMargin = Unit.FromMillimeter(18);
        sec.PageSetup.LeftMargin = Unit.FromMillimeter(16);
        sec.PageSetup.RightMargin = Unit.FromMillimeter(16);
        var footer = sec.Footers.Primary.AddParagraph();
        footer.Format.Font.Size = 7.5;
        footer.Format.Font.Color = Muted;
        footer.AddText($"LANORA · {t["title"]} · {t["generated"]}: {d.GeneratedAt.ToString("g", t.Culture)} · {t["page"]} ");
        footer.AddPageField();
        footer.AddText(" / ");
        footer.AddNumPagesField();

        var kicker = sec.AddParagraph("LANORA");
        kicker.Format.Font.Size = 8; kicker.Format.Font.Color = Muted; kicker.Format.Font.Bold = true;
        sec.AddParagraph(t["title"], StyleNames.Heading1);
        var stateLine = d.Active ? t.ScanState("running") : t.ScanState(s.State);
        var sub = sec.AddParagraph($"{s.NetworkCidr} · {t.Date(s.StartedAt)} · {t.Profile(s.ProfileId)} · {stateLine}");
        sub.Format.Font.Color = Muted;

        if (d.Active)
            Callout(sec, t.F("running_note", d.GeneratedAt.ToString("g", t.Culture)));
        else if (s.State != ScanStates.Completed)
            Callout(sec, t["partial_note"] + (s.ReasonCode is null ? "" : $" ({t["reason"]}: {s.ReasonCode})"));
        if (s.Advanced && s.AnyExternal)
            Callout(sec, t["external_note"]);

        // Summary
        sec.AddParagraph(t["summary"], StyleNames.Heading2);
        var score = sec.AddParagraph();
        score.Format.Font.Size = 14;
        score.AddFormattedText($"{t["score"]}: ", TextFormat.Bold);
        score.AddText(ReportBuilder.ScoreText(s, t));
        sec.AddParagraph(t["score_basis"] + " " + t["score_limit"]).Format.Font.Color = Muted;
        sec.AddParagraph(t.F("coverage_note", s.DefinitePairs, s.PlannedPairs)).Format.Font.Color = Muted;

        var rows = new List<(string, string)>
        {
            (t["network"], $"{s.NetworkCidr}" + (s.Gateway is null ? "" : $" · {t["gateway"]} {s.Gateway}")),
            (t["interface"], $"{s.InterfaceName} ({s.InterfaceKind}) · {s.LocalIp}"),
            (t["started"], t.Date(s.StartedAt)),
            (t["ended"], s.EndedAt is null ? "—" : t.Date(s.EndedAt)),
            (t["state"], $"{stateLine} ({s.State})"),
            (s.Advanced ? t["engine_mode"] : t["profile"], s.Advanced ? t["advanced_engine"] + (s.Technique is null ? "" : $" · {s.Technique}") : $"{t.Profile(s.ProfileId)} · {s.PortCount} TCP"),
            (t["addresses_probed"], s.AddressesProbed.ToString(t.Culture)),
            (t["hosts_responded"], s.HostsResponded.ToString(t.Culture)),
            (t["unverified"], Math.Max(0, s.AddressesProbed - s.HostsResponded).ToString(t.Culture)),
            (t["coverage"], s.Coverage is null ? "—" : $"{s.Coverage.Value * 100:0}% ({s.DefinitePairs}/{s.PlannedPairs})"),
            (t["findings"], $"{s.PriorityFindings} ({t.Severity("high")}: {s.HighFindings})"),
            (t["engine"], s.EngineVersion),
            (t["ruleset"], s.RulesetVersion),
            (t["port_list"], s.PortListVersion ?? "—"),
        };
        if (s.ReasonCode is not null) rows.Add((t["reason"], s.ReasonCode));
        var kv = NewTable(sec, new[] { 55.0, 123.0 }, header: null);
        foreach (var (k, v) in rows)
        {
            var r = kv.AddRow();
            r.Cells[0].AddParagraph(k).Format.Font.Bold = true;
            r.Cells[1].AddParagraph(v);
        }

        // Status chart + numeric table
        sec.AddParagraph(t["state_chart"], StyleNames.Heading2);
        var dist = ReportBuilder.StateDistribution(d);
        var max = Math.Max(1, dist.Max(x => x.Count));
        var chart = NewTable(sec, new[] { 45.0, 18.0, 115.0 }, new[] { t["state"], t["count"], "" });
        foreach (var (code, count) in dist)
        {
            var r = chart.AddRow();
            r.Cells[0].AddParagraph($"{t.State(code)} ({code})");
            r.Cells[1].AddParagraph(count.ToString(t.Culture)).Format.Alignment = ParagraphAlignment.Right;
            var bar = r.Cells[2].AddParagraph();
            var n = count == 0 ? 0 : Math.Max(1, (int)Math.Round(count * 40.0 / max));
            var ft = bar.AddFormattedText(new string('█', n));
            ft.Color = StateColor(code);
            ft.Size = 8;
        }

        // Devices
        sec.AddParagraph(t["devices"], StyleNames.Heading2);
        if (d.Hosts.Count == 0)
        {
            sec.AddParagraph(t["no_devices"]);
        }
        else
        {
            var dev = NewTable(sec, new[] { 31.0, 22.0, 28.0, 30.0, 29.0, 19.0, 19.0 },
                new[] { t["device"], t["ip"], t["mac"], t["vendor"], t["os"], t["device_score"], t["coverage"] });
            foreach (var h in d.Hosts)
            {
                var r = dev.AddRow();
                r.Cells[0].AddParagraph(ReportBuilder.HostName(h, t));
                if (h.Hostname is not null) r.Cells[0].AddParagraph(h.Hostname).Format.Font.Size = 7;
                r.Cells[1].AddParagraph(h.Ip);
                r.Cells[2].AddParagraph(h.Mac ?? "—");
                r.Cells[3].AddParagraph(ReportBuilder.VendorText(h, t));
                r.Cells[4].AddParagraph(ReportBuilder.OsText(h, t));
                r.Cells[5].AddParagraph(h.Score?.ToString(t.Culture) ?? t["insufficient_coverage"]);
                r.Cells[6].AddParagraph($"{h.Coverage * 100:0}%");
            }
            var missing = d.Hosts.Where(h => h.Mac is null).ToList();
            if (missing.Count > 0)
            {
                var p = sec.AddParagraph($"{t["missing"]}: {t["missing_mac"]} ({string.Join(", ", missing.Select(h => h.Ip))})");
                p.Format.Font.Color = Muted; p.Format.Font.Size = 8;
            }
        }

        // Port findings, evidence and recommendations
        sec.AddParagraph(t["findings"], StyleNames.Heading2);
        var anyPriority = false;
        foreach (var h in d.Hosts)
        {
            var open = h.Open.Where(o => o.State == PortState.Open).ToList();
            if (open.Count == 0 && h.Findings.All(f => f.Port == 0)) continue;
            sec.AddParagraph($"{ReportBuilder.HostName(h, t)} · {h.Ip}", StyleNames.Heading3);
            if (open.Count > 0)
            {
                var pt = NewTable(sec, new[] { 16.0, 16.0, 30.0, 70.0, 22.0, 24.0 },
                    new[] { t["port"], t["state"], t["service"], t["evidence"], t["rule"], t["severity"] });
                foreach (var o in open)
                {
                    var f = h.Findings.FirstOrDefault(x => x.Port == o.Port && x.Protocol == o.Protocol);
                    var r = pt.AddRow();
                    r.Cells[0].AddParagraph($"{o.Protocol.ToUpperInvariant()} {o.Port}");
                    r.Cells[1].AddParagraph(t.State(o.State));
                    r.Cells[2].AddParagraph($"{o.ServiceName ?? "—"} ({o.ServiceMethod ?? "port_table"})");
                    r.Cells[3].AddParagraph(o.EvidenceSummary ?? "—").Format.Font.Size = 7.5;
                    r.Cells[4].AddParagraph(f?.RuleId ?? "—");
                    var sevText = r.Cells[5].AddParagraph().AddFormattedText(f is null ? "—" : t.Severity(f.Severity));
                    if (f is not null) sevText.Color = SeverityColor(f.Severity);
                }
            }

            foreach (var f in h.Findings.Where(f => RiskEngine.IsPriority(f.Severity) || f.RuleId == "R08"))
            {
                anyPriority |= RiskEngine.IsPriority(f.Severity);
                var head = sec.AddParagraph();
                head.Format.SpaceBefore = Unit.FromPoint(5);
                head.Format.KeepWithNext = true;
                var title = head.AddFormattedText($"{f.RuleId} · {ReportBuilder.RuleText(d, f.RuleId, "title", f)} · {t.Severity(f.Severity)}", TextFormat.Bold);
                title.Color = SeverityColor(f.Severity);
                foreach (var (label, part) in new[] { ("what_observed", "observed"), ("what_means", "meaning"), ("what_do", "action"), ("how_verify", "verify") })
                {
                    var p = sec.AddParagraph();
                    p.Format.LeftIndent = Unit.FromMillimeter(3);
                    p.AddFormattedText(t[label] + ": ", TextFormat.Bold);
                    p.AddText(ReportBuilder.RuleText(d, f.RuleId, part, f));
                }
                if (f.Evidence is not null)
                {
                    var p = sec.AddParagraph($"{t["evidence"]}: {f.Evidence}");
                    p.Format.LeftIndent = Unit.FromMillimeter(3); p.Format.Font.Size = 7.5; p.Format.Font.Color = Muted;
                }
                if (f.Required)
                {
                    var p = sec.AddParagraph(t["required_note"]);
                    p.Format.LeftIndent = Unit.FromMillimeter(3); p.Format.Font.Color = Muted;
                }
            }
        }
        if (!anyPriority) sec.AddParagraph(t["no_findings"]).Format.Font.Color = Muted;

        var end = sec.AddParagraph(t["score_limit"] + " " + t["downloaded_note"]);
        end.Format.SpaceBefore = Unit.FromPoint(14);
        end.Format.Font.Size = 7.5;
        end.Format.Font.Color = Muted;

        var renderer = new PdfDocumentRenderer { Document = doc };
        renderer.RenderDocument();
        using var ms = new MemoryStream();
        renderer.PdfDocument.Save(ms, false);
        return ms.ToArray();
    }

    private static void Callout(Section sec, string text)
    {
        var p = sec.AddParagraph(text);
        p.Format.Shading.Color = Color.FromRgb(0xfa, 0xf3, 0xec);
        p.Format.Borders.Color = Color.FromRgb(0xe8, 0xd5, 0xc0);
        p.Format.Borders.Width = 0.5;
        p.Format.Borders.Distance = Unit.FromPoint(5);
        p.Format.SpaceBefore = Unit.FromPoint(6);
        p.Format.SpaceAfter = Unit.FromPoint(8);
        p.Format.Font.Color = Color.FromRgb(0x8a, 0x5a, 0x2b);
    }

    private static Table NewTable(Section sec, double[] widthsMm, string[]? header)
    {
        var table = sec.AddTable();
        table.Borders.Color = Line;
        table.Borders.Width = 0.5;
        table.Rows.LeftIndent = 0;
        table.Format.Font.Size = 8;
        foreach (var w in widthsMm) table.AddColumn(Unit.FromMillimeter(w));
        if (header is not null)
        {
            var r = table.AddRow();
            r.HeadingFormat = true;
            r.Shading.Color = HeadFill;
            r.Format.Font.Bold = true;
            for (var i = 0; i < header.Length; i++) r.Cells[i].AddParagraph(header[i]);
        }
        table.TopPadding = Unit.FromPoint(2);
        table.BottomPadding = Unit.FromPoint(2);
        sec.AddParagraph().Format.SpaceAfter = 0;
        return table;
    }

    /// <summary>FR17 colors: closed green; uncertain/not tested grey; open yellow (priority red is shown on the finding).</summary>
    private static Color StateColor(string code) => code switch
    {
        PortState.Closed => Color.FromRgb(0x2d, 0x76, 0x59),
        PortState.Open => Color.FromRgb(0xb1, 0x80, 0x35),
        PortState.Error => Color.FromRgb(0xc5, 0x61, 0x4f),
        _ => Color.FromRgb(0x9a, 0xa3, 0x9e),
    };

    private static Color SeverityColor(string sev) => sev switch
    {
        "high" => Color.FromRgb(0xc5, 0x61, 0x4f),
        "medium" => Color.FromRgb(0xa2, 0x74, 0x39),
        _ => Color.FromRgb(0x8b, 0x80, 0x58),
    };
}

/// <summary>
/// PDFsharp font resolver. Windows Arial (or Segoe UI) files are used for Turkish/German characters.
/// Can be replaced by embedding a suitably licensed font in the release package.
/// </summary>
public sealed class FontSetup : IFontResolver
{
    public const string Family = "LanoraSans";
    private static readonly object Gate = new();
    private static bool _done;
    private readonly Dictionary<string, string> _files;

    private FontSetup(Dictionary<string, string> files) => _files = files;

    public static void Ensure()
    {
        lock (Gate)
        {
            if (_done) return;
            var dir = Environment.GetFolderPath(Environment.SpecialFolder.Fonts);
            string Pick(params string[] names) => names.Select(n => Path.Combine(dir, n)).FirstOrDefault(File.Exists)
                ?? throw new FileNotFoundException("No suitable font found in " + dir);
            var regular = Pick("arial.ttf", "segoeui.ttf", "calibri.ttf");
            var files = new Dictionary<string, string>
            {
                ["r"] = regular,
                ["b"] = Pick("arialbd.ttf", "segoeuib.ttf", "calibrib.ttf"),
                ["i"] = new[] { "ariali.ttf", "segoeuii.ttf" }.Select(n => Path.Combine(dir, n)).FirstOrDefault(File.Exists) ?? regular,
                ["bi"] = new[] { "arialbi.ttf", "segoeuiz.ttf" }.Select(n => Path.Combine(dir, n)).FirstOrDefault(File.Exists) ?? regular,
            };
            if (GlobalFontSettings.FontResolver is null) GlobalFontSettings.FontResolver = new FontSetup(files);
            _done = true;
        }
    }

    public FontResolverInfo? ResolveTypeface(string familyName, bool bold, bool italic) =>
        new(bold && italic ? "bi" : bold ? "b" : italic ? "i" : "r");

    public byte[]? GetFont(string faceName) => File.ReadAllBytes(_files.TryGetValue(faceName, out var f) ? f : _files["r"]);
}
