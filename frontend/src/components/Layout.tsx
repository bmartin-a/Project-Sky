import { NavLink, Outlet } from "react-router-dom";
import {
  LayoutDashboard,
  Radar,
  ShieldCheck,
  Crosshair,
} from "lucide-react";
import type { ReactNode } from "react";
import { config } from "../lib/config";
import { OidcSignOut } from "./AuthGate";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/scans", label: "Scans", icon: Radar, end: false },
  { to: "/targets", label: "Targets", icon: Crosshair, end: false },
  { to: "/policies", label: "Scan policies", icon: ShieldCheck, end: false },
];

function NavItem({
  to,
  label,
  icon: Icon,
  end,
}: {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  end: boolean;
}): ReactNode {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
          isActive
            ? "bg-sky-600/15 text-sky-300"
            : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
        }`
      }
    >
      <Icon size={18} />
      {label}
    </NavLink>
  );
}

export default function Layout() {
  return (
    <div className="flex h-full">
      <aside className="flex w-60 flex-col border-r border-slate-800 bg-slate-950/60 px-3 py-5">
        <div className="mb-6 flex items-center gap-2 px-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-600 text-sm font-bold text-white">
            PS
          </div>
          <div>
            <div className="text-sm font-semibold text-slate-100">
              Project-Sky
            </div>
            <div className="text-[11px] text-slate-500">Vulnerability scanner</div>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-1">
          {nav.map((n) => (
            <NavItem key={n.to} {...n} />
          ))}
        </nav>
        <div className="flex flex-col gap-1 px-2 text-[11px] text-slate-600">
          {config.authMode === "oidc" ? <OidcSignOut /> : null}
          <span>Authorized use only.</span>
        </div>
      </aside>

      <main className="flex-1 overflow-auto">
        <div className="mx-auto max-w-6xl px-8 py-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
