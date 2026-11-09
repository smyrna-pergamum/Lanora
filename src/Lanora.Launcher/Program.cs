using System.Diagnostics;
using System.Text;

namespace Lanora.Launcher;

/// <summary>
/// "lanora" console command. Lanora.exe is a window application, so a console cannot wait for it or show its output.
/// This launcher starts "Lanora.exe --cli ...", streams its output to the console, forwards Ctrl+C as a cancel request
/// and returns its exit code.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var app = Path.Combine(AppContext.BaseDirectory, "Lanora.exe");
        if (!File.Exists(app))
        {
            Console.Error.WriteLine($"lanora: Lanora.exe was not found next to this command ({AppContext.BaseDirectory}). Reinstall LANORA.");
            return 1;
        }

        // An update that could not replace Lanora.exe (e.g. because LANORA was running) leaves an older Lanora.exe next to
        // this launcher. An older version does not know --cli and would open the window instead, so stop with a clear message.
        var mismatch = VersionMismatch(app);
        if (mismatch is not null)
        {
            Console.Error.WriteLine("lanora: " + mismatch);
            return 1;
        }

        var start = new ProcessStartInfo(app)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false),
            WorkingDirectory = Environment.CurrentDirectory,
        };
        start.ArgumentList.Add("--cli");
        foreach (var a in args) start.ArgumentList.Add(a);
        // Progress lines only make sense on a terminal, not in a redirected file.
        if (!Console.IsErrorRedirected && !args.Contains("--no-progress")) start.ArgumentList.Add("--progress");

        // The app writes UTF-8; switch the console to UTF-8 while it runs so names such as "Arayüzü" are shown correctly.
        var restoreOutput = !Console.IsOutputRedirected || !Console.IsErrorRedirected ? Console.OutputEncoding : null;
        try
        {
            if (restoreOutput is not null) Console.OutputEncoding = new UTF8Encoding(false);
        }
        catch (IOException)
        {
            restoreOutput = null;
        }

        try
        {
            using var child = Process.Start(start);
            if (child is null)
            {
                Console.Error.WriteLine("lanora: LANORA could not be started.");
                return 1;
            }

            var cancelRequests = 0;
            Console.CancelKeyPress += (_, e) =>
            {
                // First Ctrl+C: ask for a clean cancel (results found so far are saved). Second: stop immediately.
                if (Interlocked.Increment(ref cancelRequests) == 1)
                {
                    e.Cancel = true;
                    try { child.StandardInput.WriteLine("cancel"); child.StandardInput.Flush(); } catch (IOException) { } catch (InvalidOperationException) { }
                }
                else
                {
                    try { child.Kill(); } catch (InvalidOperationException) { }
                }
            };

            var output = Pump(child.StandardOutput.BaseStream, Console.OpenStandardOutput());
            var error = Pump(child.StandardError.BaseStream, Console.OpenStandardError());
            child.WaitForExit();
            Task.WaitAll(output, error);
            return child.ExitCode;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Console.Error.WriteLine("lanora: LANORA could not be started: " + ex.Message);
            return 1;
        }
        finally
        {
            if (restoreOutput is not null)
            {
                try { Console.OutputEncoding = restoreOutput; } catch (IOException) { }
            }
        }
    }

    /// <summary>Error text if Lanora.exe is not the same LANORA version (major.minor.patch) as this launcher, otherwise null.</summary>
    internal static string? VersionMismatch(string appPath)
    {
        var own = typeof(Program).Assembly.GetName().Version;
        var info = FileVersionInfo.GetVersionInfo(appPath);
        if (own is null || info.FileMajorPart == 0 && info.FileMinorPart == 0 && info.FileBuildPart == 0) return null; // unknown: do not block
        var expected = $"{own.Major}.{own.Minor}.{own.Build}";
        var found = $"{info.FileMajorPart}.{info.FileMinorPart}.{info.FileBuildPart}";
        return expected == found ? null
            : $"Lanora.exe is version {found}, but this command belongs to LANORA {expected}. "
              + "The last update was not completed, probably because LANORA was running. "
              + "Choose Exit in the LANORA tray menu and run the LANORA installer again.";
    }

    /// <summary>Copies bytes as they arrive (no line buffering, so the "\r" progress line updates in place).</summary>
    private static Task Pump(Stream from, Stream to) => Task.Run(() =>
    {
        var buffer = new byte[8192];
        try
        {
            int n;
            while ((n = from.Read(buffer, 0, buffer.Length)) > 0)
            {
                to.Write(buffer, 0, n);
                to.Flush();
            }
        }
        catch (IOException)
        {
            // The console or the pipe was closed (e.g. "lanora scan | more" ended early).
        }
    });
}
