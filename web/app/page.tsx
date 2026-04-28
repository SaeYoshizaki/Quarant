"use client";

import { useEffect, useState } from "react";
import {
  RefreshCw,
  Search,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  AlertCircle,
  Info,
  Server,
  Clock,
  Activity,
  ArrowRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

type EventSeverity = "CRITICAL" | "HIGH" | "WARNING" | "INFO" | string;

type UserAction = {
  id?: string;
  label?: string;
  description?: string;
  difficulty?: string;
  priority?: number;
  fallback?: string;
};

type Event = {
  ts: string;
  type?: string;
  severity?: EventSeverity;
  rule_id?: string;
  category?: string;
  flow_key?: string;
  evidence?: string;
  observed_fact?: string;
  inference?: string;
  limitation?: string;
  recommendation?: string;
  user_title?: string;
  user_message?: string;
  user_impact?: string;
  action_ids?: string[];
  user_actions?: UserAction[];
  recommended_action?: string;
  dry_run?: boolean;
  suggested_firewall_action?: string;
  device_key?: string;
  device_label?: string;
  device_status?: string;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  message?: string;
};

type KV = {
  key: string;
  count: number;
};

type Report = {
  generated_at: string;
  source: string;
  total_events: number;
  user_notifications: number;
  quarantine_candidates: number;
  unknown_devices: number;
  window?: {
    start?: string;
    end?: string;
  };
  severity: KV[];
  rules: KV[];
  categories: KV[];
  sources: KV[];
  events: Event[];
};

type Summary = {
  critical: number;
  high: number;
  warning: number;
  info: number;
  sources: number;
  total: number;
};

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8080";

function formatTime(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ja-JP", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatTimeShort(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString("ja-JP", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function endpoint(ip?: string, port?: number): string {
  if (!ip) return "-";
  return port ? `${ip}:${port}` : ip;
}

function severityRank(severity?: EventSeverity): number {
  switch (severity) {
    case "CRITICAL":
      return 4;
    case "HIGH":
      return 3;
    case "WARNING":
      return 2;
    case "INFO":
      return 1;
    default:
      return 0;
  }
}

function summarize(filteredEvents: Event[]): Summary {
  return {
    critical: filteredEvents.filter((e) => e.severity === "CRITICAL").length,
    high: filteredEvents.filter((e) => e.severity === "HIGH").length,
    warning: filteredEvents.filter((e) => e.severity === "WARNING").length,
    info: filteredEvents.filter((e) => e.severity === "INFO").length,
    sources: new Set(filteredEvents.map((e) => e.src_ip).filter(Boolean)).size,
    total: filteredEvents.length,
  };
}

function SummaryCard({
  label,
  value,
  icon: Icon,
  variant = "default",
}: {
  label: string;
  value: number;
  icon: React.ElementType;
  variant?: "default" | "critical" | "high" | "warning" | "info";
}) {
  const variantStyles = {
    default: "border-border",
    critical:
      "border-[var(--severity-critical)]/30 bg-[var(--severity-critical-bg)]",
    high: "border-[var(--severity-high)]/30 bg-[var(--severity-high-bg)]",
    warning:
      "border-[var(--severity-warning)]/30 bg-[var(--severity-warning-bg)]",
    info: "border-[var(--severity-info)]/30 bg-[var(--severity-info-bg)]",
  };

  const iconStyles = {
    default: "text-muted-foreground",
    critical: "text-[var(--severity-critical)]",
    high: "text-[var(--severity-high)]",
    warning: "text-[var(--severity-warning)]",
    info: "text-[var(--severity-info)]",
  };

  return (
    <div
      className={cn(
        "flex items-center gap-3 rounded-md border bg-card px-4 py-3",
        variantStyles[variant]
      )}
    >
      <Icon className={cn("size-5 shrink-0", iconStyles[variant])} />
      <div className="min-w-0">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-xl font-semibold tabular-nums">{value}</p>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity?: EventSeverity }) {
  if (!severity) {
    return (
      <Badge variant="secondary" className="font-mono text-xs">
        UNKNOWN
      </Badge>
    );
  }

  const styles: Record<string, string> = {
    CRITICAL:
      "bg-[var(--severity-critical)] text-white hover:bg-[var(--severity-critical)]",
    HIGH: "bg-[var(--severity-high)] text-white hover:bg-[var(--severity-high)]",
    WARNING:
      "bg-[var(--severity-warning)] text-white hover:bg-[var(--severity-warning)]",
    INFO: "bg-[var(--severity-info)] text-white hover:bg-[var(--severity-info)]",
  };

  return (
    <Badge
      className={cn("font-mono text-xs", styles[severity] || "")}
      variant={styles[severity] ? "default" : "secondary"}
    >
      {severity}
    </Badge>
  );
}

function EventRow({ event, index }: { event: Event; index: number }) {
  const [isOpen, setIsOpen] = useState(false);
  const rule = event.rule_id || event.type || "-";

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <CollapsibleTrigger asChild>
        <button
          className={cn(
            "grid w-full grid-cols-[100px_80px_1fr_180px_2fr] items-center gap-3 border-b border-border px-3 py-2.5 text-left text-sm transition-colors hover:bg-muted/50",
            isOpen && "bg-muted/30"
          )}
        >
          <span className="font-mono text-xs text-muted-foreground">
            {formatTimeShort(event.ts)}
          </span>
          <SeverityBadge severity={event.severity} />
          <span className="truncate font-medium" title={rule}>
            {rule}
          </span>
          <span className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
            <span className="truncate" title={event.src_ip}>
              {event.src_ip || "-"}
            </span>
            <ArrowRight className="size-3 shrink-0" />
            <span className="truncate" title={event.dst_ip}>
              {event.dst_ip || "-"}
            </span>
          </span>
          <span className="flex items-center gap-2">
            <span className="truncate text-muted-foreground">
              {event.message || "No message"}
            </span>
            {isOpen ? (
              <ChevronDown className="size-4 shrink-0 text-muted-foreground" />
            ) : (
              <ChevronRight className="size-4 shrink-0 text-muted-foreground" />
            )}
          </span>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="border-b border-border bg-muted/20 px-3 py-3">
          <div className="grid gap-3 text-sm md:grid-cols-2 lg:grid-cols-4">
            <div>
              <p className="text-xs font-medium text-muted-foreground">
                Source
              </p>
              <p className="font-mono">
                {endpoint(event.src_ip, event.src_port)}
              </p>
            </div>
            <div>
              <p className="text-xs font-medium text-muted-foreground">
                Destination
              </p>
              <p className="font-mono">
                {endpoint(event.dst_ip, event.dst_port)}
              </p>
            </div>
            <div>
              <p className="text-xs font-medium text-muted-foreground">Type</p>
              <p>{event.type || "-"}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-muted-foreground">
                Category
              </p>
              <p>{event.category || "-"}</p>
            </div>
            {event.flow_key && (
              <div className="md:col-span-2">
                <p className="text-xs font-medium text-muted-foreground">
                  Flow Key
                </p>
                <p className="font-mono text-xs">{event.flow_key}</p>
              </div>
            )}
            {event.evidence && (
              <div className="md:col-span-2 lg:col-span-4">
                <p className="text-xs font-medium text-muted-foreground">
                  Evidence
                </p>
                <p className="mt-1 whitespace-pre-wrap rounded bg-card p-2 font-mono text-xs">
                  {event.evidence}
                </p>
              </div>
            )}
            {event.observed_fact && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">
                  Observed Fact
                </p>
                <p>{event.observed_fact}</p>
              </div>
            )}
            {event.inference && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">
                  Inference
                </p>
                <p>{event.inference}</p>
              </div>
            )}
            {event.limitation && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">
                  Limitation
                </p>
                <p>{event.limitation}</p>
              </div>
            )}
            {event.recommendation && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">
                  Recommendation
                </p>
                <p>{event.recommendation}</p>
              </div>
            )}
          </div>
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

function DeviceStatusBadge({ status }: { status?: string }) {
  const value = status || "unknown";
  const styles: Record<string, string> = {
    allowed: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700",
    unknown: "border-amber-500/30 bg-amber-500/10 text-amber-700",
    blocked_candidate: "border-rose-500/30 bg-rose-500/10 text-rose-700",
    ignored: "border-slate-500/30 bg-slate-500/10 text-slate-700",
  };

  return (
    <Badge variant="outline" className={cn("text-[11px]", styles[value] || "")}>
      {value}
    </Badge>
  );
}

function UserNotificationCard({ event }: { event: Event }) {
  const [isOpen, setIsOpen] = useState(false);
  const title = event.user_title || event.rule_id || event.type || "Notification";
  const deviceLabel = event.device_label || event.device_key || event.src_ip || "-";
  const actions = (event.user_actions || []).slice().sort((a, b) => {
    return (a.priority || 999) - (b.priority || 999);
  });

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={event.severity} />
              <DeviceStatusBadge status={event.device_status} />
              {event.dry_run && (
                <Badge variant="secondary" className="text-[11px]">
                  dry-run
                </Badge>
              )}
            </div>
            <h3 className="text-base font-semibold tracking-tight">{title}</h3>
            <p className="text-sm text-muted-foreground">
              {deviceLabel} / {formatTimeShort(event.ts)}
            </p>
          </div>
        </div>

        {event.user_message && (
          <p className="mt-3 text-sm leading-6">{event.user_message}</p>
        )}
        {event.user_impact && (
          <p className="mt-2 text-sm leading-6 text-muted-foreground">
            {event.user_impact}
          </p>
        )}

        {actions.length > 0 && (
          <div className="mt-4 rounded-lg bg-muted/40 p-3">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
              First Actions
            </p>
            <div className="mt-2 space-y-2">
              {actions.slice(0, 4).map((action) => (
                <div key={action.id} className="rounded-md bg-background p-3">
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-sm font-medium">{action.label}</p>
                    {action.difficulty && (
                      <Badge variant="outline" className="text-[11px]">
                        {action.difficulty}
                      </Badge>
                    )}
                  </div>
                  {action.description && (
                    <p className="mt-1 text-sm text-muted-foreground">
                      {action.description}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        <CollapsibleTrigger asChild>
          <button className="mt-4 flex items-center gap-2 text-sm font-medium text-foreground/80 hover:text-foreground">
            {isOpen ? (
              <ChevronDown className="size-4" />
            ) : (
              <ChevronRight className="size-4" />
            )}
            技術的な根拠を見る
          </button>
        </CollapsibleTrigger>

        <CollapsibleContent>
          <div className="mt-3 grid gap-3 rounded-lg border border-border bg-muted/20 p-3 text-sm md:grid-cols-2">
            {event.observed_fact && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">
                  Observed Fact
                </p>
                <p className="mt-1">{event.observed_fact}</p>
              </div>
            )}
            {event.inference && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">
                  Inference
                </p>
                <p className="mt-1">{event.inference}</p>
              </div>
            )}
            {event.limitation && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">
                  Limitation
                </p>
                <p className="mt-1">{event.limitation}</p>
              </div>
            )}
            {event.recommendation && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">
                  Recommendation
                </p>
                <p className="mt-1">{event.recommendation}</p>
              </div>
            )}
            {event.evidence && (
              <div className="md:col-span-2">
                <p className="text-xs font-medium text-muted-foreground">
                  Evidence
                </p>
                <p className="mt-1 whitespace-pre-wrap rounded bg-background p-2 font-mono text-xs">
                  {event.evidence}
                </p>
              </div>
            )}
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  );
}

function FilterBar({
  severity,
  setSeverity,
  rule,
  setRule,
  query,
  setQuery,
  severityOptions,
  ruleOptions,
}: {
  severity: string;
  setSeverity: (value: string) => void;
  rule: string;
  setRule: (value: string) => void;
  query: string;
  setQuery: (value: string) => void;
  severityOptions: KV[];
  ruleOptions: KV[];
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Select value={severity} onValueChange={setSeverity}>
        <SelectTrigger className="h-8 w-[140px] text-xs">
          <SelectValue placeholder="All Severity" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All Severity</SelectItem>
          {severityOptions.map((item) => (
            <SelectItem key={item.key} value={item.key}>
              {item.key} ({item.count})
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select value={rule} onValueChange={setRule}>
        <SelectTrigger className="h-8 w-[180px] text-xs">
          <SelectValue placeholder="All Rules" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All Rules</SelectItem>
          {ruleOptions.map((item) => (
            <SelectItem key={item.key} value={item.key}>
              {item.key} ({item.count})
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          type="search"
          placeholder="Search events..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="h-8 w-[200px] pl-8 text-xs"
        />
      </div>
    </div>
  );
}

function TopListCollapsible({
  title,
  items,
  defaultOpen = false,
}: {
  title: string;
  items: KV[];
  defaultOpen?: boolean;
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <CollapsibleTrigger className="flex w-full items-center justify-between rounded-md px-3 py-2 text-sm font-medium hover:bg-muted/50">
        <span>{title}</span>
        {isOpen ? (
          <ChevronDown className="size-4 text-muted-foreground" />
        ) : (
          <ChevronRight className="size-4 text-muted-foreground" />
        )}
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="space-y-1 px-3 pb-2">
          {items.length > 0 ? (
            items.slice(0, 5).map((item) => (
              <div
                key={item.key}
                className="flex items-center justify-between py-1 text-sm"
              >
                <span className="truncate text-muted-foreground">
                  {item.key}
                </span>
                <span className="ml-2 tabular-nums">{item.count}</span>
              </div>
            ))
          ) : (
            <p className="py-1 text-sm text-muted-foreground">No data</p>
          )}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

export default function QuarantDashboard() {
  const [report, setReport] = useState<Report | null>(null);
  const [severity, setSeverity] = useState<string>("all");
  const [rule, setRule] = useState<string>("all");
  const [query, setQuery] = useState<string>("");
  const [autoRefresh, setAutoRefresh] = useState<boolean>(false);
  const [status, setStatus] = useState<string>("Loading...");
  const [error, setError] = useState<string>("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  async function loadReport(): Promise<void> {
    try {
      setIsRefreshing(true);
      setError("");

      const response = await fetch(`${API_BASE_URL}/api/report`, {
        cache: "no-store",
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const nextReport: Report = await response.json();
      setReport(nextReport);
      setLastUpdated(new Date());
      setStatus("Connected");
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      setError(message);
      setStatus("Error");
    } finally {
      setIsRefreshing(false);
    }
  }

  useEffect(() => {
    void loadReport();
  }, []);

  useEffect(() => {
    if (!autoRefresh) return undefined;

    const id = window.setInterval(() => {
      void loadReport();
    }, 5000);

    return () => window.clearInterval(id);
  }, [autoRefresh]);

  const filteredEvents = (report?.events || []).filter((event) => {
    if (severity !== "all" && event.severity !== severity) return false;

    const eventRule = event.rule_id || event.type || "";
    if (rule !== "all" && eventRule !== rule) return false;

    const trimmedQuery = query.trim().toLowerCase();
    if (!trimmedQuery) return true;

    const haystack = [
      event.type,
      event.rule_id,
      event.category,
      event.flow_key,
      event.device_key,
      event.device_label,
      event.device_status,
      event.user_title,
      event.user_message,
      event.user_impact,
      event.src_ip,
      event.dst_ip,
      event.message,
      event.evidence,
    ]
      .join(" ")
      .toLowerCase();

    return haystack.includes(trimmedQuery);
  });

  const stats = summarize(filteredEvents);
  const userFacingEvents = filteredEvents
    .filter((event) => Boolean(event.user_title))
    .slice()
    .sort((a, b) => {
      if (severityRank(a.severity) !== severityRank(b.severity)) {
        return severityRank(b.severity) - severityRank(a.severity);
      }
      return new Date(b.ts).getTime() - new Date(a.ts).getTime();
    });

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-10 border-b border-border bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/80">
        <div className="mx-auto flex max-w-screen-2xl items-center justify-between gap-4 px-4 py-3">
          <div className="flex items-center gap-4">
            <h1 className="text-lg font-semibold tracking-tight">Quarant</h1>
            <div className="hidden items-center gap-2 text-xs text-muted-foreground sm:flex">
              <Server className="size-3.5" />
              <span className="font-mono">{API_BASE_URL}</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Clock className="size-3.5" />
              <span>
                {lastUpdated ? formatTime(lastUpdated.toISOString()) : "-"}
              </span>
            </div>

            <div className="flex items-center gap-1.5">
              <Button
                variant={autoRefresh ? "default" : "outline"}
                size="sm"
                onClick={() => setAutoRefresh((v) => !v)}
                className="h-7 gap-1.5 text-xs"
              >
                <Activity className="size-3.5" />
                Auto {autoRefresh ? "ON" : "OFF"}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void loadReport()}
                disabled={isRefreshing}
                className="h-7 gap-1.5 text-xs"
              >
                <RefreshCw
                  className={cn("size-3.5", isRefreshing && "animate-spin")}
                />
                Refresh
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-screen-2xl px-4 py-4">
        {error && (
          <div className="mb-4 rounded-md border border-[var(--severity-critical)]/30 bg-[var(--severity-critical-bg)] px-4 py-2 text-sm">
            <span className="font-medium text-[var(--severity-critical)]">
              Connection Error:
            </span>{" "}
            {error}
          </div>
        )}

        <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
          <SummaryCard
            label="Total Events"
            value={stats.total}
            icon={Activity}
          />
          <SummaryCard
            label="Critical"
            value={stats.critical}
            icon={AlertCircle}
            variant="critical"
          />
          <SummaryCard
            label="High"
            value={stats.high}
            icon={AlertTriangle}
            variant="high"
          />
          <SummaryCard
            label="Warning"
            value={stats.warning}
            icon={AlertTriangle}
            variant="warning"
          />
          <SummaryCard
            label="Source IPs"
            value={stats.sources}
            icon={Info}
            variant="info"
          />
          <SummaryCard
            label="User Notices"
            value={report?.user_notifications || userFacingEvents.length}
            icon={Info}
            variant="info"
          />
          <SummaryCard
            label="Quarantine"
            value={report?.quarantine_candidates || 0}
            icon={AlertTriangle}
            variant="high"
          />
          <SummaryCard
            label="Unknown Devices"
            value={report?.unknown_devices || 0}
            icon={Server}
            variant="warning"
          />
        </div>

        <section className="mb-4 rounded-2xl border border-border bg-card p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold tracking-tight">
                ユーザー向け通知
              </h2>
              <p className="text-sm text-muted-foreground">
                専門用語を抑えて、まず確認したいことを上に表示しています。
              </p>
            </div>
            <Badge variant="outline">{userFacingEvents.length} items</Badge>
          </div>

          <div className="mt-4 space-y-3">
            {userFacingEvents.length > 0 ? (
              userFacingEvents.map((event, index) => (
                <UserNotificationCard
                  key={`${event.ts}-${event.rule_id || event.type || "notification"}-${index}`}
                  event={event}
                />
              ))
            ) : (
              <div className="rounded-xl border border-dashed border-border px-4 py-8 text-center text-sm text-muted-foreground">
                現在のフィルタ条件では、ユーザー向け通知はありません。
              </div>
            )}
          </div>
        </section>

        <div className="flex flex-col gap-4 lg:flex-row">
          <div className="min-w-0 flex-1">
            <div className="rounded-md border border-border bg-card">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-3 py-2">
                <FilterBar
                  severity={severity}
                  setSeverity={setSeverity}
                  rule={rule}
                  setRule={setRule}
                  query={query}
                  setQuery={setQuery}
                  severityOptions={report?.severity || []}
                  ruleOptions={report?.rules || []}
                />
                <span className="text-xs text-muted-foreground">
                  {filteredEvents.length} events
                  {report?.total_events && filteredEvents.length !== report.total_events
                    ? ` / ${report.total_events} total`
                    : ""}
                </span>
              </div>

              <div className="grid grid-cols-[100px_80px_1fr_180px_2fr] items-center gap-3 border-b border-border bg-muted/30 px-3 py-2 text-xs font-medium text-muted-foreground">
                <span>Time</span>
                <span>Severity</span>
                <span>Rule</span>
                <span>Source → Dest</span>
                <span>Message</span>
              </div>

              <div className="max-h-[calc(100vh-320px)] overflow-y-auto">
                {filteredEvents.length > 0 ? (
                  filteredEvents.map((event, index) => (
                    <EventRow
                      key={`${event.ts}-${event.rule_id || event.type || "event"}-${index}`}
                      event={event}
                      index={index}
                    />
                  ))
                ) : (
                  <div className="px-4 py-12 text-center">
                    <p className="text-sm text-muted-foreground">
                      {report
                        ? "No events match the current filters"
                        : "Loading events..."}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          <aside className="w-full shrink-0 lg:w-64">
            <div className="rounded-md border border-border bg-card">
              <TopListCollapsible
                title="Top Rules"
                items={report?.rules || []}
                defaultOpen={true}
              />
              <div className="border-t border-border" />
              <TopListCollapsible
                title="Top Categories"
                items={report?.categories || []}
              />
              <div className="border-t border-border" />
              <TopListCollapsible
                title="Top Source IPs"
                items={report?.sources || []}
              />
            </div>
          </aside>
        </div>
      </main>
    </div>
  );
}
