using System.Diagnostics;
using System.Drawing;
using System.Security.Principal;
using System.Windows.Forms;
using Lanora.Infrastructure;

namespace Lanora;

internal sealed record LaunchOptions(bool NoBrowser, string? DataDir, string? DevUrlFile)
{
    public static LaunchOptions Parse(string[] args)
    {
        bool noBrowser = false;
        string? dataDir = null, urlFile = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--no-browser": noBrowser = true; break;
                case "--data-dir" when i + 1 < args.Length: dataDir = args[++i]; break;
                // Development/test only: writes the launch URL to a local file.
                case "--dev-url-file" when i + 1 < args.Length: urlFile = args[++i]; break;
            }
        }
        return new LaunchOptions(noBrowser, dataDir, urlFile);
    }
}

internal static class Program
{
    /// <summary>DesktopHost: single instance, system tray, browser launch and shutdown (SEC06).</summary>
    [STAThread]
    private static int Main(string[] args)
    {
        var opts = LaunchOptions.Parse(args);
        var sid = WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName;
        var suffix = opts.DataDir is null ? sid : sid + "." + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(opts.DataDir)))[..12];
        using var mutex = new Mutex(true, $"Local\\Lanora.Instance.{suffix}", out var createdNew);
        if (!createdNew)
        {
            // A second launch does not open a new API; it tells the running instance to show the interface.
            try
            {
                using var existing = EventWaitHandle.OpenExisting($"Local\\Lanora.Show.{suffix}");
                existing.Set();
            }
            catch (WaitHandleCannotBeOpenedException)
            {
            }
            return 0;
        }

        using var showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, $"Local\\Lanora.Show.{suffix}");
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        var paths = new AppPaths(opts.DataDir);
        AppLog.Init(paths.Logs);
        AppLog.Info("startup", $"LANORA {Scanning.ScanOrchestrator.AppVersion} starting");

        LanoraHost host;
        try
        {
            host = LanoraHost.StartAsync(paths).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            AppLog.Error("startup", ex);
            MessageBox.Show("LANORA could not be started. Details are in the log file: " + paths.Logs, "LANORA", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }

        using var tray = new TrayContext(host, opts, showEvent);
        Application.Run(tray);
        return 0;
    }
}

internal sealed class TrayContext : ApplicationContext
{
    private readonly LanoraHost _host;
    private readonly LaunchOptions _opts;
    private readonly NotifyIcon _icon;
    private readonly SynchronizationContext _ui;
    private readonly RegisteredWaitHandle _wait;
    private bool _exiting;

    public TrayContext(LanoraHost host, LaunchOptions opts, EventWaitHandle showEvent)
    {
        _host = host;
        _opts = opts;
        _ui = new WindowsFormsSynchronizationContext();
        SynchronizationContext.SetSynchronizationContext(_ui);

        var lang = SafeLang();
        var menu = new ContextMenuStrip();
        menu.Items.Add(Text(lang, "Open interface", "Arayüzü aç", "Oberfläche öffnen"), null, (_, _) => OpenUi());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(Text(lang, "Exit (cancels scan)", "Çıkış (taramayı iptal eder)", "Beenden (bricht Scan ab)"), null, async (_, _) => await ExitAsync());
        _icon = new NotifyIcon
        {
            Icon = CreateIcon(),
            Text = "LANORA",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _icon.DoubleClick += (_, _) => OpenUi();

        _wait = ThreadPool.RegisterWaitForSingleObject(showEvent, (_, _) => _ui.Post(_ => OpenUi(), null), null, Timeout.Infinite, false);

        OpenUi();
    }

    private string SafeLang()
    {
        try { return _host.Settings.Get().Lang; } catch { return "en"; }
    }

    /// <summary>English is the primary language; Turkish and German are secondary.</summary>
    private static string Text(string lang, string en, string tr, string de) => lang switch { "tr" => tr, "de" => de, _ => en };

    private void OpenUi()
    {
        if (_exiting) return;
        var url = _host.CreateLaunchUrl();
        if (_opts.DevUrlFile is not null) File.WriteAllText(_opts.DevUrlFile, url);
        if (_opts.NoBrowser) return;
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            AppLog.Error("tray", ex);
        }
    }

    private async Task ExitAsync()
    {
        if (_exiting) return;
        _exiting = true;
        _icon.Visible = false;
        _wait.Unregister(null);
        await _host.DisposeAsync();
        ExitThread();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _icon.Dispose();
            if (!_exiting) _host.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        base.Dispose(disposing);
    }

    private static Icon CreateIcon()
    {
        using var stream = typeof(TrayContext).Assembly.GetManifestResourceStream("brand/Lanora.ico")
            ?? throw new InvalidOperationException("The embedded LANORA icon is missing.");
        using var icon = new Icon(stream, 32, 32);
        return (Icon)icon.Clone();
    }
}
