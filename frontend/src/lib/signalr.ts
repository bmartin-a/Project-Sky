import {
  HubConnection,
  HubConnectionBuilder,
  HubConnectionState,
  LogLevel,
} from "@microsoft/signalr";
import type { ScanProgress } from "./types";

const BASE = import.meta.env.VITE_API_BASE ?? "";

/**
 * Opens a SignalR connection, subscribes to a scan's progress group, and
 * invokes `onProgress` for each update. Returns a disposer.
 */
export function subscribeToScan(
  scanId: string,
  onProgress: (p: ScanProgress) => void,
): () => void {
  const connection: HubConnection = new HubConnectionBuilder()
    .withUrl(`${BASE}/hubs/scan`)
    .withAutomaticReconnect()
    .configureLogging(LogLevel.Warning)
    .build();

  connection.on("ScanProgress", (p: ScanProgress) => onProgress(p));

  connection.onreconnected(() => {
    void connection.invoke("Subscribe", scanId);
  });

  connection
    .start()
    .then(() => connection.invoke("Subscribe", scanId))
    .catch(() => {
      /* connection errors are non-fatal; polling still refreshes state */
    });

  return () => {
    if (connection.state !== HubConnectionState.Disconnected) {
      void connection.stop();
    }
  };
}
