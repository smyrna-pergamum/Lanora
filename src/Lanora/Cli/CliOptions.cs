using System.Globalization;

namespace Lanora.Cli;

/// <summary>Parsed command line of <c>lanora</c> (the console launcher passes its arguments after <c>--cli</c>).</summary>
internal sealed record CliOptions
{
    public const string Usage = """
        LANORA command line: scan your local network and print the results.

        Usage:
          lanora scan [targets...] [options]   Scan devices and open ports, then print the result
          lanora interfaces                    List network adapters that can be scanned
          lanora history [--limit N]           List saved scans
          lanora show <scan-id>                Print a saved scan again
          lanora version                       Print the version
          lanora help                          Show this help

        Targets (default: the suggested range of the selected adapter):
          192.168.1.0/24   192.168.1.20-40   192.168.1.5   (private addresses of your own network only)

        Options:
          -i, --interface <id|name|ip>   Adapter to scan from (default: the adapter of the targets / default route)
          -p, --profile <quick|standard> Port profile (default: the profile chosen in the LANORA settings)
              --ports <list>             Custom TCP ports, e.g. 22,80,443,8000-8010 (uses the custom profile)
          -f, --format <text|json|csv>   Output format (default: text)
              --fail-on <high|medium>    Exit code 3 if a finding of this priority or higher is found
              --limit <N>                Number of scans for "history" (default: 10)
              --data-dir <folder>        Use another data folder (default: %LOCALAPPDATA%\Lanora)
              --no-progress              Do not show progress

        Exit codes: 0 completed, 1 error, 2 invalid usage, 3 findings at --fail-on level, 4 cancelled or partial result.
        Scans are saved to the same history as the LANORA window. Press Ctrl+C to cancel a running scan.
        Only scan networks you own or are allowed to test.
        """;

    public string Command { get; init; } = "help";
    public List<string> Targets { get; init; } = new();
    public string? Interface { get; init; }
    public string? Profile { get; init; }
    public List<int>? Ports { get; init; }
    public string Format { get; init; } = "text";
    public string? FailOn { get; init; }
    public int Limit { get; init; } = 10;
    public string? ScanId { get; init; }
    public string? DataDir { get; init; }
    public bool Progress { get; init; }
    /// <summary>Usage error; when set, the command is not run (exit code 2).</summary>
    public string? Error { get; init; }

    private static readonly string[] Commands = { "scan", "interfaces", "history", "show", "version", "help" };

    public static CliOptions Parse(IReadOnlyList<string> args)
    {
        if (args.Count == 0) return new CliOptions { Command = "help" };
        var command = args[0].ToLowerInvariant() switch
        {
            "-h" or "--help" or "/?" => "help",
            "-v" or "--version" => "version",
            var c => c,
        };
        if (!Commands.Contains(command)) return new CliOptions { Error = $"Unknown command \"{args[0]}\". Run \"lanora help\"." };

        var targets = new List<string>();
        string? iface = null, profile = null, failOn = null, scanId = null, dataDir = null;
        List<int>? ports = null;
        var format = "text";
        var limit = 10;
        var progress = false;

        for (var i = 1; i < args.Count; i++)
        {
            var a = args[i];
            string? Value()
            {
                if (i + 1 >= args.Count || args[i + 1].StartsWith("--", StringComparison.Ordinal)) return null;
                return args[++i];
            }
            CliOptions Missing() => new() { Error = $"Option {a} needs a value." };

            switch (a)
            {
                case "-i" or "--interface": iface = Value(); if (iface is null) return Missing(); break;
                case "-p" or "--profile":
                    profile = Value()?.ToLowerInvariant();
                    if (profile is null) return Missing();
                    if (profile is not ("quick" or "standard" or "custom")) return new() { Error = "Profile must be quick, standard or custom." };
                    break;
                case "--ports":
                    var list = Value();
                    if (list is null) return Missing();
                    if (!TryParsePorts(list, out ports, out var portError)) return new() { Error = portError };
                    break;
                case "-f" or "--format":
                    format = Value()?.ToLowerInvariant() ?? "";
                    if (format is not ("text" or "json" or "csv")) return new() { Error = "Format must be text, json or csv." };
                    break;
                case "--json": format = "json"; break;
                case "--csv": format = "csv"; break;
                case "--fail-on":
                    failOn = Value()?.ToLowerInvariant();
                    if (failOn is not ("high" or "medium")) return new() { Error = "--fail-on must be high or medium." };
                    break;
                case "--limit":
                    if (!int.TryParse(Value(), NumberStyles.None, CultureInfo.InvariantCulture, out limit) || limit is < 1 or > 1000)
                        return new() { Error = "--limit must be a number from 1 to 1000." };
                    break;
                case "--data-dir": dataDir = Value(); if (dataDir is null) return Missing(); break;
                case "--progress": progress = true; break;      // added by the console launcher when stderr is a terminal
                case "--no-progress": progress = false; break;
                default:
                    if (a.StartsWith('-')) return new() { Error = $"Unknown option \"{a}\". Run \"lanora help\"." };
                    if (command == "show") { if (scanId is not null) return new() { Error = "show takes one scan id." }; scanId = a; }
                    else if (command == "scan") targets.AddRange(a.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                    else return new() { Error = $"\"{command}\" takes no argument \"{a}\"." };
                    break;
            }
        }

        if (command == "show" && scanId is null) return new() { Error = "show needs a scan id (see \"lanora history\")." };
        if (ports is not null && profile is not (null or "custom")) return new() { Error = "--ports cannot be combined with the quick or standard profile." };
        if (profile == "custom" && ports is null) return new() { Error = "The custom profile needs --ports." };

        return new CliOptions
        {
            Command = command, Targets = targets, Interface = iface, Profile = ports is not null ? "custom" : profile, Ports = ports,
            Format = format, FailOn = failOn, Limit = limit, ScanId = scanId, DataDir = dataDir, Progress = progress,
        };
    }

    /// <summary>"22,80,8000-8010" → sorted, distinct TCP ports (1–65535, at most 1024 like the custom profile).</summary>
    internal static bool TryParsePorts(string text, out List<int>? ports, out string? error)
    {
        var set = new SortedSet<int>();
        ports = null;
        error = null;
        foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = part.IndexOf('-');
            if (dash > 0 && TryPort(part[..dash], out var from) && TryPort(part[(dash + 1)..], out var to) && from <= to)
            {
                if (to - from + 1 + set.Count > 1024) { error = "At most 1024 ports can be scanned."; return false; }
                for (var p = from; p <= to; p++) set.Add(p);
            }
            else if (dash < 0 && TryPort(part, out var single)) set.Add(single);
            else { error = $"Invalid port \"{part}\" (use 1-65535, e.g. 22,80,8000-8010)."; return false; }
        }
        if (set.Count == 0) { error = "--ports needs at least one port."; return false; }
        if (set.Count > 1024) { error = "At most 1024 ports can be scanned."; return false; }
        ports = set.ToList();
        return true;
    }

    private static bool TryPort(string s, out int port) =>
        int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
}
