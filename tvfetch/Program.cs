using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("libc", SetLastError = true)]
    static extern int statvfs(string path, out Statvfs buf);

    // 32-bit ARM glibc layout: all fields are 32-bit, with a hidden
    // padding int between f_fsid and f_flag (glibc's __f_unused).
    [StructLayout(LayoutKind.Sequential)]
    struct Statvfs
    {
        public uint f_bsize;
        public uint f_frsize;
        public uint f_blocks;
        public uint f_bfree;
        public uint f_bavail;
        public uint f_files;
        public uint f_ffree;
        public uint f_favail;
        public uint f_fsid;
        public int __f_unused;
        public uint f_flag;
        public uint f_namemax;
    }

    static string Read(string path)
    {
        try { return File.ReadAllText(path); } catch { return ""; }
    }

    static string Exec(string cmd, string args)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo(cmd, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            using var p = System.Diagnostics.Process.Start(psi);
            string o = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd(); // drain and discard so it never hits the terminal
            p.WaitForExit();
            return o.Trim();
        }
        catch { return ""; }
    }

    // ---------- Memory ----------

    // Parses "Key:   123 kB" lines (first occurrence wins). Values are ints (kB fits
    // easily) to stay away from 64-bit paths on this runtime.
    static Dictionary<string, int> ParseMemInfo(string meminfo)
    {
        var d = new Dictionary<string, int>();
        foreach (var raw in meminfo.Split('\n'))
        {
            string line = raw.Trim();
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            string key = line.Substring(0, colon);
            if (d.ContainsKey(key)) continue;

            string rest = line.Substring(colon + 1).Trim();
            int sp = rest.IndexOf(' ');
            string num = sp > 0 ? rest.Substring(0, sp) : rest;
            int v;
            if (int.TryParse(num, out v)) d[key] = v;
        }
        return d;
    }

    static int Get(Dictionary<string, int> d, string key)
    {
        int v;
        return d.TryGetValue(key, out v) ? v : 0;
    }

    static string MemoryString(string meminfo)
    {
        var d = ParseMemInfo(meminfo);
        int totalKb = Get(d, "MemTotal");
        int availKb = Get(d, "MemAvailable");
        if (availKb == 0)
            availKb = Get(d, "MemFree") + Get(d, "Buffers") + Get(d, "Cached");

        if (totalKb <= 0)
        {
            string first = meminfo.Split('\n')[0].Trim();
            return "unknown (meminfo first line: \"" + first + "\", " + d.Count + " keys parsed)";
        }

        int usedKb = totalKb - availKb;
        if (usedKb < 0) usedKb = 0;
        return (usedKb / 1024) + "MiB / " + (totalKb / 1024) + "MiB";
    }

    // ---------- Disk ----------

    static string DiskString(string path)
    {
        try
        {
            Statvfs sv;
            if (statvfs(path, out sv) == 0 && sv.f_blocks > 0)
            {
                ulong frsize = sv.f_frsize != 0 ? sv.f_frsize : sv.f_bsize;
                ulong total = (ulong)sv.f_blocks * frsize;
                ulong free = (ulong)sv.f_bavail * frsize;
                ulong used = total - (ulong)sv.f_bfree * frsize;
                if (free > total) free = 0;
                return $"{used / 1024 / 1024}MiB / {total / 1024 / 1024}MiB";
            }
        }
        catch { }

        return null;
    }

    // ---------- SoC / GPU ----------

    static string SocName()
    {
        string model = Read("/proc/device-tree/model").Trim('\0', ' ', '\n');
        if (!string.IsNullOrEmpty(model)) return model;
        string compat = Read("/proc/device-tree/compatible").Split('\0')[0].Trim();
        return compat;
    }

    // Parses e.g. "Mali-G52 1 cores r1p0 0x7402" into "Mali-G52 (1 core, r1p0)".
    static string FormatGpuInfo(string raw)
    {
        string line = raw.Split('\n')[0].Trim();
        var p = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (p.Length >= 4 && p[0].StartsWith("Mali") && (p[2] == "cores" || p[2] == "core"))
        {
            string cores = p[1] == "1" ? "1 core" : p[1] + " cores";
            return p[0] + " (" + cores + ", " + p[3] + ")";
        }
        return line;
    }

    // The kernel driver's own report; the only trustworthy source (the userspace
    // libmali blob lists many GPU models, so scanning it is a guess).
    static string GpuFromSysfs()
    {
        var paths = new List<string> {
            "/sys/devices/platform/soc/mali.0/gpuinfo",
            "/sys/class/misc/mali0/device/gpuinfo",
            "/sys/devices/platform/mali.0/gpuinfo",
            "/sys/kernel/debug/mali0/gpuinfo",
            "/proc/gpuinfo",
        };
        try
        {
            foreach (var d in Directory.GetDirectories("/sys/devices/platform"))
                paths.Add(Path.Combine(d, "mali.0", "gpuinfo"));
            foreach (var d in Directory.GetDirectories("/sys/devices/platform/soc"))
                paths.Add(Path.Combine(d, "gpuinfo"));
        }
        catch { }

        foreach (var p in paths)
        {
            string r = Read(p);
            if (!string.IsNullOrWhiteSpace(r)) return FormatGpuInfo(r);
        }
        return null;
    }

    static bool MaliModuleLoaded()
    {
        foreach (var line in Read("/proc/modules").Split('\n'))
        {
            string l = line.ToLower();
            if (l.StartsWith("mali ") || l.StartsWith("mali_") || l.StartsWith("midgard") || l.StartsWith("bifrost"))
                return true;
        }
        return false;
    }

    static readonly string[] Gpu3dHints = {
        "mali", "panfrost", "lima", "vc4", "v3d", "etnaviv", "nvidia", "amdgpu", "radeon", "i915"
    };

    static string DetectGpu()
    {
        // 1. Kernel driver's gpuinfo.
        string info = GpuFromSysfs();
        if (info != null) return info;

        // 2. DRM cards (only counts if they look like a 3D core).
        var found = new List<string>();
        try
        {
            if (Directory.Exists("/sys/class/drm"))
            {
                foreach (var d in Directory.GetDirectories("/sys/class/drm"))
                {
                    string name = Path.GetFileName(d);
                    if (!name.StartsWith("card") || name.Contains("-")) continue;

                    string uevent = Read(Path.Combine(d, "device", "uevent"));
                    string driver = "", modalias = "";
                    foreach (var line in uevent.Split('\n'))
                    {
                        if (line.StartsWith("DRIVER=")) driver = line.Replace("DRIVER=", "").Trim();
                        else if (line.StartsWith("OF_COMPATIBLE_0=")) modalias = line.Replace("OF_COMPATIBLE_0=", "").Trim();
                    }

                    string entry = !string.IsNullOrEmpty(driver)
                        ? (!string.IsNullOrEmpty(modalias) ? $"{driver} ({modalias})" : driver)
                        : modalias;
                    if (!string.IsNullOrEmpty(entry)) found.Add(entry);
                }
            }
        }
        catch { }

        foreach (var e in found)
            foreach (var hint in Gpu3dHints)
                if (e.ToLower().Contains(hint)) return e;

        // 3. devfreq names.
        try
        {
            if (Directory.Exists("/sys/class/devfreq"))
                foreach (var d in Directory.GetDirectories("/sys/class/devfreq"))
                {
                    string n = Path.GetFileName(d).ToLower();
                    foreach (var hint in Gpu3dHints)
                        if (n.Contains(hint)) return Path.GetFileName(d);
                }
        }
        catch { }

        // 4. Kernel module says Mali but no model string was found.
        if (MaliModuleLoaded()) return "Mali (model unknown)";

        if (found.Count > 0) return string.Join(", ", found) + " (display controller(s); no 3D core detected)";

        if (Directory.Exists("/dev/dri"))
        {
            try
            {
                var nodes = Directory.GetFileSystemEntries("/dev/dri");
                if (nodes.Length > 0) return "DRM device present (driver unknown)";
            }
            catch { }
        }

        return "Unknown";
    }

    // ---------- Misc ----------

    static string DetectWm()
    {
        string ps = Exec("ps", "-ef");
        if (string.IsNullOrEmpty(ps)) ps = Exec("ps", "aux");
        if (string.IsNullOrEmpty(ps)) ps = Exec("ps", "");
        if (ps.ToLower().Contains("enlightenment")) return "Enlightenment";
        return "Unknown";
    }

    static string ToyboxVersion()
    {
        string v = Exec("toybox", "--version");
        return string.IsNullOrEmpty(v) ? "not found" : v;
    }

    static string BashVersion()
    {
        string v = Exec("bash", "--version");
        if (string.IsNullOrEmpty(v)) return "unknown";
        return v.Split('\n')[0]; // first line carries the version string
    }

    static void Main()
    {
        string user = Environment.GetEnvironmentVariable("USER");
        if (string.IsNullOrEmpty(user)) user = Exec("id", "-un");
        if (string.IsNullOrEmpty(user)) user = "root";
        string host = Read("/proc/sys/kernel/hostname").Trim();
        if (string.IsNullOrEmpty(host)) host = "tizen-tv";

        string cpuinfo = Read("/proc/cpuinfo");
        string meminfo = Read("/proc/meminfo");
        string uptimeRaw = Read("/proc/uptime");
        string osrelease = Read("/etc/os-release");
        string version = Read("/proc/version");

        string model = "";
        int cores = 0;
        foreach (var line in cpuinfo.Split('\n'))
        {
            if (line.StartsWith("model name") || line.StartsWith("Hardware"))
                model = line.Contains(':') ? line.Split(':')[1].Trim() : model;
            if (line.StartsWith("processor")) cores++;
        }
        if (string.IsNullOrEmpty(model)) model = "Unknown ARM";

        string soc = SocName();
        string cpuStr = !string.IsNullOrEmpty(soc) && !model.Contains(soc)
            ? $"{soc} ({model}) ({cores})"
            : $"{model} ({cores})";

        string memStr = MemoryString(meminfo);

        double upSeconds = 0;
        double.TryParse(uptimeRaw.Split(' ')[0], NumberStyles.Float, CultureInfo.InvariantCulture, out upSeconds);
        var up = TimeSpan.FromSeconds(upSeconds);
        string upStr = up.Days > 0 ? $"{up.Days}d {up.Hours}h {up.Minutes}m" : $"{up.Hours}h {up.Minutes}m";

        string osName = "Tizen", osVersion = "";
        foreach (var line in osrelease.Split('\n'))
        {
            if (line.StartsWith("NAME=")) osName = line.Replace("NAME=", "").Trim('"');
            if (line.StartsWith("VERSION=")) osVersion = line.Replace("VERSION=", "").Trim('"');
        }

        string kernelVer = "unknown";
        var kv = version.Split(' ');
        if (kv.Length > 2) kernelVer = kv[2];

        string shell = Environment.GetEnvironmentVariable("SHELL") ?? "/bin/bash";

        string diskRoot = DiskString("/") ?? "N/A";
        string diskOpt = DiskString("/opt/usr");

        string localIp = "N/A";
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up ||
                    ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                    { localIp = addr.Address.ToString(); break; }
                if (localIp != "N/A") break;
            }
        }
        catch { }

        string gpu = DetectGpu();
        string wm = DetectWm();
        string toybox = ToyboxVersion();

        const string RESET = "\u001b[0m", BOLD = "\u001b[1m", CYAN = "\u001b[36m";

        // Raw logo lines, exactly as provided (art.txt), no reflow/rejoin.
        string[] logoRaw = {
            "                      .==.                        ",
            "                   ..====.                        ",
            "                ..+++++==.                        ",
            "                +++++++++.                        ",
            "               ++++++++++.                        ",
            "              .**++++++++.                        ",
            "              @#***++++++.@@@@@@@@@@***++++.      ",
            "             .@%#*****+. ########%****+++++++.    ",
            "             @%%##**-    %%######****+++++++++==. ",
            "            .@%###%.     %%%%%%=:***+++++++++=====",
            "=====..     @%###%%%.    %%%%%.  ..*+++++++++=..  ",
            ".====+++++..%###%%%%%@.  @%%@.       .++.         ",
            " =++++++++++: ..%%%%%%%  .%:      *%##%.          ",
            "  +++++++++++        ..     .@%%%%%%##%@.         ",
            "  .++++++++***              %%%%%%%%###%@         ",
            "   .+++++*****...%%%@%%  ...    .#%%###%%@        ",
            "     .*****####%%%%%%%.  @%%=      .**#%%@.       ",
            "       .-@@%%###%%%%%    %%%%%    .*******@.      ",
            "           =@%%###%.     %%%%%%. .++++++++**      ",
            "              =@%#.      %%%%###*.++++++++++      ",
            "                .++++****######%@.++++++++++      ",
            "               +++++++***###%%@    +++++++++      ",
            "             .++++++++***%%@@.      .++++++.      ",
            "            :=+++++++++**@+.         .====.       ",
            "          .====++++++++*.              ===        ",
            "      .-*.=====++++++*.                 ..        ",
        };

        // Trans pride flag: five horizontal bands across the logo.
        // 24-bit ANSI colors use the flag's actual hex colors:
        // light blue #5BCEFA, pink #F5A9B8, and white #FFFFFF.
        string[] transFlag = {
            "\u001b[38;2;91;206;250m",   // Light blue
            "\u001b[38;2;245;169;184m",  // Pink
            "\u001b[38;2;255;255;255m",  // White
            "\u001b[38;2;245;169;184m",  // Pink
            "\u001b[38;2;91;206;250m",   // Light blue
        };

        // 26 logo rows split into five horizontal flag stripes (5, 5, 6, 5, 5).
        string[] logo = new string[logoRaw.Length];
        for (int i = 0; i < logoRaw.Length; i++)
        {
            int stripe = i < 5 ? 0 : i < 10 ? 1 : i < 16 ? 2 : i < 21 ? 3 : 4;
            logo[i] = transFlag[stripe] + logoRaw[i] + RESET;
        }

        string title = $"{BOLD}{CYAN}{user}{RESET}@{BOLD}{CYAN}{host}{RESET}";
        string sep = new string('-', (user + "@" + host).Length);

        var info = new List<string>
        {
            title, sep,
            $"{BOLD}{CYAN}OS{RESET}: {osName} {osVersion}",
            $"{BOLD}{CYAN}Kernel{RESET}: {kernelVer}",
            $"{BOLD}{CYAN}Uptime{RESET}: {upStr}",
            $"{BOLD}{CYAN}Shell{RESET}: {shell} ({BashVersion()})",
            $"{BOLD}{CYAN}WM{RESET}: {wm}",
            $"{BOLD}{CYAN}CPU{RESET}: {cpuStr}",
            $"{BOLD}{CYAN}GPU{RESET}: {gpu}",
            $"{BOLD}{CYAN}Memory{RESET}: {memStr}",
            $"{BOLD}{CYAN}Disk (/){RESET}: {diskRoot}",
        };
        if (diskOpt != null)
            info.Add($"{BOLD}{CYAN}Disk (/opt/usr){RESET}: {diskOpt}");
        info.Add($"{BOLD}{CYAN}Local IP{RESET}: {localIp}");
        info.Add($"{BOLD}{CYAN}Toybox{RESET}: {toybox}");

        int n = Math.Max(logo.Length, info.Count);
        for (int i = 0; i < n; i++)
        {
            string l = i < logo.Length ? logo[i] : new string(' ', logoRaw[0].Length);
            string r = i < info.Count ? info[i] : "";
            Console.WriteLine($"{l}  {r}");
        }

        Console.Write(new string(' ', logoRaw[0].Length + 2));
        foreach (var c in new[] { "40", "41", "42", "43", "44", "45", "46", "47" })
            Console.Write($"\u001b[{c}m   {RESET}");
        Console.WriteLine();
    }
}
