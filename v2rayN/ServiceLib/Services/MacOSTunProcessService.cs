using Microsoft.Win32.SafeHandles;

namespace ServiceLib.Services;

/// <summary>
/// A core owned by the macOS launch daemon. The native library connects from the GUI
/// process itself, so the helper can authenticate the actual caller, not a CLI proxy.
/// </summary>
public sealed class MacOSTunProcessService : ICoreProcess
{
    private readonly NativeSession _session;
    private readonly Func<bool, string, Task>? _updateFunc;
    private readonly bool _displayLog;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private Task? _monitor;
    private volatile bool _hasExited;
    private int _disposed;

    // Generated in memory; never written to the ordinary GUI configuration. A local
    // unauthenticated Clash API would otherwise bypass the helper's config validation.
    public static string ApiSecret { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    public bool HasExited => _hasExited;

    private MacOSTunProcessService(NativeSession session, bool displayLog, Func<bool, string, Task>? updateFunc)
    {
        _session = session;
        _displayLog = displayLog;
        _updateFunc = updateFunc;
    }

    public static Task PrepareAsync() => Task.Run(() => ServiceControl("register"));

    public static string ServiceStatus() => ServiceControl("status");

    public static string UnregisterService() => ServiceControl("unregister");

    /// <summary>Fixed, non-launching IPC smoke test from the real GUI executable.</summary>
    public static string VerifyServiceConnection()
    {
        ServiceControl("register");
        using var session = new NativeSession(Native.Open());
        if (session.IsInvalid)
        {
            throw new InvalidOperationException("Unable to connect to the macOS TUN service.");
        }
        using var reply = ReadReply(Native.Request(session, "{\"operation\":\"status\"}"));
        CheckReply(reply.RootElement);
        return reply.RootElement.GetRawText();
    }

    private static string ServiceControl(string operation)
    {
        EnsureMacOS();
        try
        {
            using var reply = ReadReply(Native.Service(operation));
            CheckReply(reply.RootElement);
            return reply.RootElement.GetRawText();
        }
        catch (DllNotFoundException ex)
        {
            throw new InvalidOperationException("Install the approved NativeAOT macOS TUN package to use TUN mode. The privileged helper is missing.", ex);
        }
    }

    public static async Task<MacOSTunProcessService> StartAsync(ECoreType coreType, string configPath,
        bool displayLog, Func<bool, string, Task>? updateFunc)
    {
        await PrepareAsync();
        var request = await MacOSTunRequest.CreateStartAsync(coreType, configPath, ApiSecret);
        var session = new NativeSession(Native.Open());
        if (session.IsInvalid)
        {
            session.Dispose();
            throw new InvalidOperationException("Unable to connect to the macOS TUN service.");
        }

        var service = new MacOSTunProcessService(session, displayLog, updateFunc);
        try
        {
            using var reply = await service.RequestAsync(request);
            CheckReply(reply.RootElement);
            service._monitor = service.MonitorAsync();
            return service;
        }
        catch
        {
            service.Dispose(); // Disconnect also tears down a launch whose reply was lost.
            throw;
        }
    }

    private async Task<JsonDocument> RequestAsync(string request)
    {
        await _gate.WaitAsync();
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            return await Task.Run(() => ReadReply(Native.Request(_session, request)));
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task MonitorAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                using var reply = await RequestAsync("{\"operation\":\"status\"}");
                var root = reply.RootElement;
                CheckReply(root);
                _hasExited = !root.GetProperty("running").GetBoolean();
                if (_displayLog && root.TryGetProperty("log", out var log) && log.GetString() is { Length: > 0 } text
                    && _updateFunc != null)
                {
                    await _updateFunc(false, text);
                }
                if (_hasExited)
                {
                    break;
                }
                await Task.Delay(250, _cts.Token);
            }
        }
        catch (OperationCanceledException) when (_cts.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (_disposed != 0) { }
        catch (Exception ex)
        {
            _hasExited = true;
            Dispose();
            // A broken/timeout connection is canceled in the native client. The
            // helper stops the core rather than reconnecting/replaying a launch.
            if (_updateFunc != null)
            {
                await _updateFunc(true, $"macOS TUN service: {ex.Message}");
            }
        }
    }

    public async Task StopAsync()
    {
        if (_disposed != 0)
        {
            return;
        }
        _cts.Cancel();
        try
        {
            using var reply = await RequestAsync("{\"operation\":\"stop\"}");
            CheckReply(reply.RootElement);
        }
        finally
        {
            _hasExited = true;
            // Even when the stop reply is lost, disconnect makes the daemon stop
            // this connection's own core. No caller-supplied PID is ever accepted.
            Dispose();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _hasExited = true;
        _cts.Cancel();
        _session.Dispose();
        // Do not dispose the gate/CTS while an in-flight monitor uses them.
    }

    private static void EnsureMacOS()
    {
        if (!OperatingSystem.IsMacOSVersionAtLeast(13))
        {
            throw new PlatformNotSupportedException("The privileged TUN service requires macOS 13 or later.");
        }
    }

    private static JsonDocument ReadReply(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero)
        {
            throw new InvalidOperationException("The macOS TUN service returned no response.");
        }
        try
        {
            return JsonDocument.Parse(Marshal.PtrToStringUTF8(pointer) ?? "{}");
        }
        finally
        {
            Native.Free(pointer);
        }
    }

    private static void CheckReply(JsonElement reply)
    {
        if (!reply.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
        {
            throw new InvalidOperationException(reply.TryGetProperty("error", out var error)
                ? error.GetString() : "The macOS TUN service rejected the request.");
        }
    }

    private sealed class NativeSession : SafeHandleZeroOrMinusOneIsInvalid
    {
        public NativeSession(IntPtr handle) : base(ownsHandle: true) => SetHandle(handle);

        protected override bool ReleaseHandle()
        {
            Native.Close(handle);
            return true;
        }
    }

    private static class Native
    {
        // Fixed bundle-relative location; do not resolve a dylib from the user data
        // directory, current directory, PATH, or an environment override.
        private const string Library = "@executable_path/../Frameworks/libV2rayNTun.dylib";

        [DllImport(Library, EntryPoint = "v2rayn_tun_service")]
        internal static extern IntPtr Service([MarshalAs(UnmanagedType.LPUTF8Str)] string action);

        [DllImport(Library, EntryPoint = "v2rayn_tun_open")]
        internal static extern IntPtr Open();

        [DllImport(Library, EntryPoint = "v2rayn_tun_request")]
        internal static extern IntPtr Request(NativeSession session, [MarshalAs(UnmanagedType.LPUTF8Str)] string json);

        [DllImport(Library, EntryPoint = "v2rayn_tun_close")]
        internal static extern void Close(IntPtr session);

        [DllImport(Library, EntryPoint = "v2rayn_tun_free")]
        internal static extern void Free(IntPtr pointer);
    }
}
