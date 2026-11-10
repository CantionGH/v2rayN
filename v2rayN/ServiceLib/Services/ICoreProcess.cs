namespace ServiceLib.Services;

/// <summary>A locally owned process or a connection-scoped privileged core.</summary>
public interface ICoreProcess : IDisposable
{
    bool HasExited { get; }

    Task StopAsync();
}
