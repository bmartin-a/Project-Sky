using Microsoft.AspNetCore.SignalR;

namespace ProjectSky.Infrastructure.Realtime;

/// <summary>
/// SignalR hub that streams live scan progress to the UI. Clients call
/// <see cref="Subscribe"/> with a scan id to join that scan's group and then
/// receive "ScanProgress" messages.
/// </summary>
public sealed class ScanProgressHub : Hub
{
    public static string GroupFor(Guid scanId) => $"scan:{scanId}";

    public Task Subscribe(Guid scanId) =>
        Groups.AddToGroupAsync(Context.ConnectionId, GroupFor(scanId));

    public Task Unsubscribe(Guid scanId) =>
        Groups.RemoveFromGroupAsync(Context.ConnectionId, GroupFor(scanId));
}
