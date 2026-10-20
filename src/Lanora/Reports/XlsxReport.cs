using System.Text.Json;
using ClosedXML.Excel;
using Lanora.Data;
using Lanora.Infrastructure;
using Lanora.Scanning;

namespace Lanora.Reports;

/// <summary>
/// FR24: Workbook built with ClosedXML (Summary, Devices, Ports, Findings, Comparison). Dates are real date cells;
/// IP, MAC and versions are text cells. Values starting with = + - @ never run as formulas (SEC05).
/// </summary>
public static class XlsxReport
{
    public static byte[] Render(ReportData d)
    {
        var t = d.T;
        var s = d.Scan;
        using var wb = new XLWorkbook();
        wb.Properties.Title = "LANORA – " + t["title"];
        wb.Properties.Author = "LANORA";

        // Summary
        var sum = wb.Worksheets.Add(SheetName(t["summary"]));
        Header(sum, t["field"], t["code"], t["value"]);
        var r = 2;
        void Row(string label, string code, object? value)
        {
            Put(sum.Cell(r, 1), label);
            Put(sum.Cell(r, 2), code);
            Put(sum.Cell(r, 3), value);
            r++;
        }
        Row(t["title"], "report", "LANORA");
        Row(t["state"], "state", $"{(d.Active ? t.ScanState("running") : t.ScanState(s.State))} ({s.State})");
        Row(t["reason"], "reason_code", s.ReasonCode);
        Row(t["network"], "network_cidr", s.NetworkCidr);
        Row(t["gateway"], "gateway", s.Gateway);
        Row(t["interface"], "interface", $"{s.InterfaceName} ({s.InterfaceKind})");
        Row(t["started"], "started_at", Clock.Parse(s.StartedAt).ToLocalTime().DateTime);
        Row(t["ended"], "ended_at", s.EndedAt is null ? null : Clock.Parse(s.EndedAt).ToLocalTime().DateTime);
        Row(t["profile"], "profile_id", $"{t.Profile(s.ProfileId)} ({s.ProfileId})");
        if (s.Advanced)
        {
            Row(t["engine_mode"], "engine", t["advanced_engine"] + (s.Technique is null ? "" : $" · {s.Technique}"));
            if (s.AnyExternal) Row(t["engine_mode"], "external_note", t["external_note"]);
        }
        Row(t["port_count"], "port_count", s.PortCount);
        Row(t["addresses_probed"], "addresses_probed", s.AddressesProbed);
        Row(t["hosts_responded"], "hosts_responded", s.HostsResponded);
        Row(t["score"], "network_score", s.NetworkScore);
        Row(t["score"], "network_state", $"{ReportBuilder.ScoreText(s, t)} ({s.NetworkState})");
        Row(t["provisional"], "provisional", s.Provisional ? t["yes"] : t["no"]);
        Row(t["coverage"], "coverage", s.Coverage is null ? null : Math.Round(s.Coverage.Value, 4));
        Row(t["coverage"], "definite_pairs", s.DefinitePairs);
        Row(t["coverage"], "planned_pairs", s.PlannedPairs);
        Row(t["devices"], "device_count", d.Hosts.Count);
        Row(t["open_ports"], "open_port_count", d.Hosts.Sum(h => h.StateCounts.TryGetValue(PortState.Open, out var n) ? n : 0));
        Row(t["findings"], "priority_findings", s.PriorityFindings);
        Row(t["engine"], "engine_version", s.EngineVersion);
        Row(t["ruleset"], "ruleset_version", s.RulesetVersion);
        Row(t["port_list"], "port_list_version", s.PortListVersion);
        Row(t["generated"], "generated_at", d.GeneratedAt.LocalDateTime);
        Row(t["description"], "scope_note", t["score_basis"] + " " + t["score_limit"]);
        if (d.Active) Row(t["state"], "snapshot_note", t.F("running_note", d.GeneratedAt.ToString("g", t.Culture)));
        else if (s.State != ScanStates.Completed) Row(t["state"], "partial_note", t["partial_note"]);
        foreach (var (code, count) in ReportBuilder.StateDistribution(d)) Row(t.State(code), "state_" + code, count);
        sum.Column(3).Style.Alignment.WrapText = true;
        Finish(sum, new[] { 32, 22, 80 });

        // Devices
        var dev = wb.Worksheets.Add(SheetName(t["devices"]));
        Header(dev, "device_id", t["device"], t["ip"], t["hostname"], t["mac"], "mac_kind", t["vendor"], "type_guess", "os_candidate", "os_source", "os_confidence",
            t["discovery"], t["identity"], t["device_score"], "raw_score", "penalty", t["coverage"], t["open_ports"], "ipv6", "distance", "first_seen", "last_seen");
        r = 2;
        foreach (var h in d.Hosts)
        {
            var c = 1;
            Put(dev.Cell(r, c++), h.DeviceId);
            Put(dev.Cell(r, c++), ReportBuilder.HostName(h, t));
            Put(dev.Cell(r, c++), h.Ip);
            Put(dev.Cell(r, c++), h.Hostname);
            Put(dev.Cell(r, c++), h.Mac);
            Put(dev.Cell(r, c++), h.MacKind);
            Put(dev.Cell(r, c++), ReportBuilder.VendorText(h, t));
            Put(dev.Cell(r, c++), h.TypeGuess);
            Put(dev.Cell(r, c++), h.OsCandidate ?? t["unknown"]);
            Put(dev.Cell(r, c++), h.OsSource);
            Put(dev.Cell(r, c++), h.OsConfidence);
            Put(dev.Cell(r, c++), h.DiscoveryEvidence);
            Put(dev.Cell(r, c++), h.IdentityStatus);
            Put(dev.Cell(r, c++), h.Score);
            Put(dev.Cell(r, c++), h.RawScore);
            Put(dev.Cell(r, c++), h.Penalty);
            Put(dev.Cell(r, c++), Math.Round(h.Coverage, 4));
            Put(dev.Cell(r, c++), string.Join(", ", h.Open.Where(o => o.State == PortState.Open).Select(o => o.Port)));
            Put(dev.Cell(r, c++), h.Ipv6);
            Put(dev.Cell(r, c++), h.Distance);
            Put(dev.Cell(r, c++), h.DeviceFirstSeen is null ? null : Clock.Parse(h.DeviceFirstSeen).ToLocalTime().DateTime);
            Put(dev.Cell(r, c++), h.DeviceLastSeen is null ? null : Clock.Parse(h.DeviceLastSeen).ToLocalTime().DateTime);
            r++;
        }
        Finish(dev, new[] { 38, 24, 15, 24, 18, 11, 28, 12, 20, 20, 11, 13, 11, 11, 9, 9, 9, 26, 24, 9, 16, 16 });

        // Portlar
        var ports = wb.Worksheets.Add(SheetName(t["ports"]));
        Header(ports, t["ip"], t["device"], t["protocol"], t["port"], t["state_code"], t["state"], t["reason_code"], t["method"],
            t["service"], t["service_method"], t["product"], t["version"], t["evidence"], t["observed_at"]);
        r = 2;
        foreach (var h in d.Hosts)
        {
            foreach (var o in h.Open)
            {
                var c = 1;
                Put(ports.Cell(r, c++), h.Ip);
                Put(ports.Cell(r, c++), ReportBuilder.HostName(h, t));
                Put(ports.Cell(r, c++), o.Protocol);
                Put(ports.Cell(r, c++), o.Port);
                Put(ports.Cell(r, c++), o.State);
                Put(ports.Cell(r, c++), t.State(o.State));
                Put(ports.Cell(r, c++), o.ReasonCode);
                Put(ports.Cell(r, c++), o.Method);
                Put(ports.Cell(r, c++), o.ServiceName);
                Put(ports.Cell(r, c++), o.ServiceMethod);
                Put(ports.Cell(r, c++), o.ServiceProduct);
                Put(ports.Cell(r, c++), o.ServiceVersion);
                Put(ports.Cell(r, c++), o.EvidenceSummary);
                Put(ports.Cell(r, c++), Clock.Parse(o.ObservedAt).ToLocalTime().DateTime);
                r++;
            }
        }
        Finish(ports, new[] { 16, 26, 9, 8, 13, 20, 16, 13, 16, 15, 18, 12, 60, 18 });

        // Bulgular
        var fnd = wb.Worksheets.Add(SheetName(t["findings"]));
        Header(fnd, t["ip"], t["device"], t["protocol"], t["port"], t["rule"], "severity", t["severity"], t["penalty"],
            t["what_observed"], t["what_means"], t["what_do"], t["how_verify"], t["evidence"], "required");
        r = 2;
        foreach (var h in d.Hosts)
        {
            foreach (var f in h.Findings)
            {
                var c = 1;
                Put(fnd.Cell(r, c++), h.Ip);
                Put(fnd.Cell(r, c++), ReportBuilder.HostName(h, t));
                Put(fnd.Cell(r, c++), f.Protocol);
                Put(fnd.Cell(r, c++), f.Port == 0 ? null : f.Port);
                Put(fnd.Cell(r, c++), f.RuleId);
                Put(fnd.Cell(r, c++), f.Severity);
                Put(fnd.Cell(r, c++), t.Severity(f.Severity));
                Put(fnd.Cell(r, c++), f.Penalty);
                Put(fnd.Cell(r, c++), ReportBuilder.RuleText(d, f.RuleId, "observed", f));
                Put(fnd.Cell(r, c++), ReportBuilder.RuleText(d, f.RuleId, "meaning", f));
                Put(fnd.Cell(r, c++), ReportBuilder.RuleText(d, f.RuleId, "action", f));
                Put(fnd.Cell(r, c++), ReportBuilder.RuleText(d, f.RuleId, "verify", f));
                Put(fnd.Cell(r, c++), f.Evidence);
                Put(fnd.Cell(r, c++), f.Required ? t["yes"] : t["no"]);
                r++;
            }
        }
        Finish(fnd, new[] { 16, 26, 9, 8, 8, 10, 14, 8, 45, 45, 45, 45, 40, 10 });

        // Comparison
        var cmp = wb.Worksheets.Add(SheetName(t["comparison"]));
        Header(cmp, "device_id", t["device"], t["before"] + " IP", t["after"] + " IP", t["change"], t["before"], t["after"],
            t["newly_opened"], t["closed_evidence"], t["no_longer"], t["not_measured"]);
        r = 2;
        if (d.Comparison is not JsonElement c0)
        {
            Put(cmp.Cell(r, 1), t["compare_none"]);
        }
        else
        {
            var compatible = c0.GetProperty("compatible").GetBoolean();
            foreach (var dv in c0.GetProperty("devices").EnumerateArray())
            {
                var c = 1;
                Put(cmp.Cell(r, c++), Str(dv, "device_id"));
                Put(cmp.Cell(r, c++), Str(dv, "label") ?? Str(dv, "vendor") ?? t["unknown"]);
                Put(cmp.Cell(r, c++), Str(dv, "ip_before"));
                Put(cmp.Cell(r, c++), Str(dv, "ip_after"));
                Put(cmp.Cell(r, c++), Str(dv, "status"));
                Put(cmp.Cell(r, c++), Int(dv, "score_before"));
                Put(cmp.Cell(r, c++), Int(dv, "score_after"));
                Put(cmp.Cell(r, c++), Ports(dv, "newly_opened"));
                Put(cmp.Cell(r, c++), Ports(dv, "closed_with_evidence"));
                Put(cmp.Cell(r, c++), Ports(dv, "no_longer_responding"));
                Put(cmp.Cell(r, c++), Ports(dv, "not_measured"));
                r++;
            }
            r++;
            Put(cmp.Cell(r++, 1), $"{t["compare_with"]}: {Str(c0, "previous_scan_id")}");
            if (!compatible)
            {
                var mism = string.Join(", ", c0.GetProperty("mismatches").EnumerateArray().Select(x => x.GetString()));
                Put(cmp.Cell(r++, 1), t.F("compare_incompatible", mism));
            }
        }
        Finish(cmp, new[] { 38, 26, 16, 16, 14, 10, 10, 18, 18, 18, 18 });

        using var ms = new MemoryStream();
        wb.SaveAs(ms);
        return ms.ToArray();
    }

    private static string? Str(JsonElement e, string p) => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static int? Int(JsonElement e, string p) => e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : null;
    private static string Ports(JsonElement e, string p) => string.Join(", ", e.GetProperty(p).EnumerateArray().Select(x => x.GetInt32()));

    private static string SheetName(string name)
    {
        var clean = new string(name.Where(ch => !"[]:*?/\\".Contains(ch)).ToArray());
        return clean[..Math.Min(31, clean.Length)];
    }

    private static void Header(IXLWorksheet ws, params string[] names)
    {
        for (var i = 0; i < names.Length; i++)
        {
            var c = ws.Cell(1, i + 1);
            Put(c, names[i]);
            c.Style.Font.Bold = true;
            c.Style.Font.FontColor = XLColor.White;
            c.Style.Fill.BackgroundColor = XLColor.FromHtml("#24523E");
        }
    }

    private static void Finish(IXLWorksheet ws, int[] widths)
    {
        for (var i = 0; i < widths.Length; i++) ws.Column(i + 1).Width = widths[i];
        ws.SheetView.FreezeRows(1);
        var used = ws.RangeUsed();
        if (used is not null && used.RowCount() > 1) used.SetAutoFilter();
    }

    /// <summary>Writes a safe value to a cell: text is never interpreted as a formula.</summary>
    internal static void Put(IXLCell cell, object? value)
    {
        switch (value)
        {
            case null:
                cell.Clear(XLClearOptions.Contents);
                break;
            case string s:
                cell.SetValue(s);
                cell.Style.NumberFormat.Format = "@";
                if (s.Length > 0 && (s[0] is '=' or '+' or '-' or '@' or '\t' or '\r')) cell.Style.IncludeQuotePrefix = true;
                break;
            case int i:
                cell.SetValue(i);
                break;
            case long l:
                cell.SetValue(l);
                break;
            case double dbl:
                cell.SetValue(dbl);
                break;
            case DateTime dt:
                cell.SetValue(dt);
                cell.Style.DateFormat.Format = "yyyy-mm-dd hh:mm";
                break;
            default:
                cell.SetValue(value.ToString());
                cell.Style.NumberFormat.Format = "@";
                break;
        }
    }
}
