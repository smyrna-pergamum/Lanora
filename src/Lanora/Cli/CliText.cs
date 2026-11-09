using System.Globalization;
using System.Text;
using System.Text.Json;
using Lanora.Data;
using Lanora.Infrastructure;
using Lanora.Risk;
using Lanora.Scanning;

namespace Lanora.Cli;

/// <summary>Text, table and CSV output of the command line (English, like log and evidence texts).</summary>
internal static class CliText
{
    public static string Phase(string phase) => phase switch
    {
        Phases.Discovery => "Discovering devices",
        Phases.PortScan => "Checking ports",
        Phases.Enrichment => "Identifying services",
        Phases.Scoring => "Assessing",
        Phases.Saving => "Saving",
        _ => phase,
    };

    public static string LocalTime(string? iso) =>
        iso is null ? "—" : Clock.Parse(iso).ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    /// <summary>Readable message for API error codes the command line can hit; other codes are shown as code + details.</summary>
    public static string Error(ApiException ex)
    {
        var d = ex.Details is null ? default : JsonSerializer.SerializeToElement(ex.Details, Json.Options);
        string D(string name) => d.ValueKind == JsonValueKind.Object && d.TryGetProperty(name, out var v) ? v.ToString() : "?";
        return ex.Code switch
        {
            "TARGET_EMPTY" => "No address to scan.",
            "TARGET_INVALID" => $"Invalid target \"{D("target")}\". Use an IPv4 address, CIDR (192.168.1.0/24) or range (192.168.1.20-40).",
            "TARGET_LIMIT" => $"Too many addresses; at most {D("max")} per scan.",
            "TARGET_NOT_PRIVATE" => $"{D("target")} is not a private address. Only your own local network can be scanned here.",
            "TARGET_OUT_OF_SCOPE" => $"{D("target")} is outside the adapter's network {D("network")}. Choose another adapter with --interface.",
            "NETWORK_NOT_SELECTABLE" => "This adapter's network cannot be scanned.",
            "INTERFACE_NOT_FOUND" => "The adapter is no longer available.",
            "PORT_LIMIT" => $"Too many ports; at most {D("max")}.",
            "ATTEMPT_BUDGET_EXCEEDED" => $"Too many address/port combinations for this profile (planned {D("planned")}, at most {D("max")}). Scan fewer addresses.",
            "PROFILE_INVALID" => "Unknown profile.",
            "SCAN_ACTIVE" => "A scan is already running in this process.",
            "MIGRATION_FAILED" => "Scanning is disabled because the database could not be upgraded.",
            _ => ex.Details is null ? ex.Code : $"{ex.Code} {Json.Serialize(ex.Details)}",
        };
    }

    /// <summary>Left-aligned plain-text table (no box characters, so it works in every console font).</summary>
    public static string Table(IReadOnlyList<string> headers, IReadOnlyList<string[]> rows)
    {
        var widths = headers.Select((h, i) => Math.Max(h.Length, rows.Count == 0 ? 0 : rows.Max(r => r[i].Length))).ToArray();
        var sb = new StringBuilder();
        void Line(IReadOnlyList<string> cells)
        {
            for (var i = 0; i < cells.Count; i++)
            {
                sb.Append(i == cells.Count - 1 ? cells[i] : cells[i].PadRight(widths[i] + 2));
            }
            sb.Append(Environment.NewLine);
        }
        Line(headers);
        Line(widths.Select(w => new string('-', w)).ToArray());
        foreach (var r in rows) Line(r);
        return sb.ToString();
    }

    private static string Severity(string s) => s switch { "high" => "HIGH", "medium" => "MEDIUM", "info" => "info", _ => s };

    private static string Ports(HostDto h) =>
        h.Open.Count(o => o.State == PortState.Open) == 0 ? "—"
            : string.Join(", ", h.Open.Where(o => o.State == PortState.Open).OrderBy(o => o.Port)
                .Select(o => o.Protocol == "udp" ? $"{o.Port}/udp" : o.Port.ToString(CultureInfo.InvariantCulture)));

    public static string ScanText(ScanSummary s, IReadOnlyList<HostDto> hosts, Ruleset rules)
    {
        var sb = new StringBuilder();
        var nl = Environment.NewLine;
        var state = s.State switch
        {
            ScanStates.Completed => "completed",
            ScanStates.Cancelled => "cancelled — partial result",
            ScanStates.Partial => $"partial result ({s.ReasonCode})",
            ScanStates.Failed => $"failed ({s.ReasonCode})",
            _ => s.State,
        };
        var duration = s.EndedAt is null ? "" : $" · {(Clock.Parse(s.EndedAt) - Clock.Parse(s.StartedAt)):mm\\:ss}";
        sb.Append($"LANORA {ScanOrchestrator.AppVersion} — scan {s.Id[..8]} {state}").Append(nl);
        sb.Append($"Network {s.NetworkCidr} via {s.InterfaceName ?? "?"} ({s.LocalIp ?? "?"}) · profile {s.ProfileId} · {s.AddressesProbed} addresses · {s.HostsResponded} devices{duration}").Append(nl);
        var score = s.NetworkScore is { } n ? $"{n}/100" : "not evaluable (too few definite results)";
        sb.Append($"Security indicator: {score}{(s.Provisional ? " (provisional)" : "")} · coverage {(s.Coverage ?? 0):P0}").Append(nl).Append(nl);

        if (hosts.Count == 0)
        {
            sb.Append("No responding devices were found. This does not mean the network is empty: some devices do not answer.").Append(nl);
            return sb.ToString();
        }

        var rows = hosts.Select(h => new[]
        {
            h.Ip + (h.IsGateway ? " (gateway)" : h.IsLocal ? " (this PC)" : ""),
            h.Label ?? h.Hostname ?? "—",
            h.Vendor ?? (h.Mac is null ? "—" : h.MacKind == "local_admin" ? "random MAC" : "unknown"),
            h.UserType ?? h.TypeGuess ?? "—",
            h.Score?.ToString(CultureInfo.InvariantCulture) ?? "—",
            Ports(h),
        }).ToList();
        sb.Append(Table(new[] { "Device", "Name", "Manufacturer", "Type", "Score", "Open ports" }, rows)).Append(nl);

        var findings = hosts.SelectMany(h => h.Findings.Where(f => f.Port > 0 && RiskEngine.IsPriority(f.Severity)).Select(f => (Host: h, Finding: f)))
            .OrderByDescending(x => x.Finding.Penalty).ThenBy(x => x.Host.Ip).ToList();
        if (findings.Count == 0)
        {
            sb.Append("No priority findings on the scanned ports.").Append(nl);
        }
        else
        {
            sb.Append($"Priority findings ({findings.Count}):").Append(nl);
            foreach (var (h, f) in findings)
            {
                var rule = rules.File.Rules.FirstOrDefault(r => r.Id == f.RuleId);
                var title = rule?.Title.FirstOrDefault() ?? f.RuleId;
                var action = rule?.Action.FirstOrDefault();
                sb.Append($"  {Severity(f.Severity),-6}  {h.Ip}  {f.Port}/{f.Protocol}  {title}{(f.Required ? " (marked as required)" : "")}").Append(nl);
                if (!string.IsNullOrWhiteSpace(action)) sb.Append($"          What to do: {action.Replace("{port}", f.Port.ToString(CultureInfo.InvariantCulture))}").Append(nl);
            }
        }
        sb.Append(nl).Append($"Saved to the LANORA history as {s.Id}. Open the LANORA window for details and reports.").Append(nl);
        return sb.ToString();
    }

    /// <summary>One row per observed open port (a device without open ports gets one row without a port).</summary>
    public static string ScanCsv(ScanSummary s, IReadOnlyList<HostDto> hosts)
    {
        var sb = new StringBuilder("scan_id,scan_state,ip,mac,manufacturer,name,device_type,device_score,protocol,port,state,service,product,version,priority,rule_id\r\n");
        foreach (var h in hosts)
        {
            var name = h.Label ?? h.Hostname;
            var type = h.UserType ?? h.TypeGuess;
            var open = h.Open.Where(o => o.State == PortState.Open).OrderBy(o => o.Port).ThenBy(o => o.Protocol).ToList();
            if (open.Count == 0)
            {
                Csv.Row(sb, s.Id, s.State, h.Ip, h.Mac, h.Vendor, name, type, h.Score?.ToString(CultureInfo.InvariantCulture), null, null, null, null, null, null, null, null);
                continue;
            }
            foreach (var o in open)
            {
                var f = h.Findings.Where(x => x.Port == o.Port && x.Protocol == o.Protocol).OrderByDescending(x => x.Penalty).FirstOrDefault();
                Csv.Row(sb, s.Id, s.State, h.Ip, h.Mac, h.Vendor, name, type, h.Score?.ToString(CultureInfo.InvariantCulture),
                    o.Protocol, o.Port.ToString(CultureInfo.InvariantCulture), o.State, o.ServiceName, o.ServiceProduct, o.ServiceVersion, f?.Severity, f?.RuleId);
            }
        }
        return sb.ToString();
    }
}

/// <summary>RFC 4180 CSV with spreadsheet formula neutralisation (device names and banners are untrusted text).</summary>
internal static class Csv
{
    public static void Row(StringBuilder sb, params string?[] cells)
    {
        for (var i = 0; i < cells.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append(Cell(cells[i]));
        }
        sb.Append("\r\n");
    }

    internal static string Cell(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        // A leading = + - @ (or tab/CR) would make Excel evaluate the cell as a formula.
        if (value[0] is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        return value.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0 ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }
}
