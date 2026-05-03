"use client";

import { Fragment, Suspense, useDeferredValue, useEffect, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { RefreshCw, Search, ChevronRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

type EventSeverity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "WARNING"
  | "LOW"
  | "INFO"
  | string;

type Event = {
  ts: string;
  type?: string;
  severity?: EventSeverity;
  debug?: boolean;
  rule_id?: string;
  category?: string;
  flow_key?: string;
  owasp_tags?: string[];
  confidence?: string;
  evidence?: string;
  observed_fact?: string;
  inference?: string;
  limitation?: string;
  recommendation?: string;
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

type InventoryRiskSummary = {
  risk_event_count?: number;
  highest_severity?: string;
  top_owasp_tags?: string[];
  top_severities?: string[];
  last_risk_event_type?: string;
  last_risk_event_ts?: string;
  recommended_next_action?: string;
};

type InventoryDevice = {
  ip: string;
  first_seen?: string;
  last_seen?: string;
  observed_protocols?: string[];
  observed_ports?: number[];
  observed_hosts?: string[];
  observed_sni?: string[];
  category_candidate?: string;
  category_confidence?: string;
  vendor_candidate?: string;
  vendor_confidence?: string;
  family_candidate?: string;
  family_confidence?: string;
  risk_event_count?: number;
  severity_counts?: Record<string, number>;
  owasp_tag_counts?: Record<string, number>;
  last_risk_event_type?: string;
  last_risk_event_ts?: string;
  risk_summary?: InventoryRiskSummary;
};

type InventoryReport = {
  generated_at?: string;
  devices?: InventoryDevice[];
};

type FlowRecord = {
  ts: string;
  flow_key?: string;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  protocol?: string;
  app_protocol?: string;
  host?: string;
  sni?: string;
  http_method?: string;
  http_path?: string;
  bytes_out?: number;
  bytes_in?: number;
  packet_count?: number;
  direction?: string;
  device_label?: string;
  device_category?: string;
  observed_destination?: string;
};

type HostRow = {
  ip: string;
  labelCandidate: string;
  categoryCandidate: string;
  vendorCandidate: string;
  familyCandidate: string;
  confidence: string;
  risk: string;
  signals: number;
  owasp: string[];
  protocols: string[];
  ports: number[];
  topDestination: string;
  externalDestinationCount: number;
  firstSeen?: string;
  lastSeen?: string;
  hosts: string[];
  sni: string[];
  macAddress: string;
  events: Event[];
  flows: FlowRecord[];
  inventory?: InventoryDevice;
};

type ViewName = "overview" | "devices" | "events";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || "";

const DEBUG_EVENT_TYPES = new Set(["I6_DEBUG", "DEVICE_DEBUG", "PAYLOAD_DEBUG"]);

function formatTime(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ja-JP", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatWindow(start?: string, end?: string): string {
  if (!start || !end) return "-";
  const startDate = new Date(start);
  const endDate = new Date(end);
  if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) {
    return "-";
  }
  const hours = Math.max(
    1,
    Math.round((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60))
  );
  return `${hours}h`;
}

function endpoint(ip?: string, port?: number): string {
  if (!ip) return "-";
  return port ? `${ip}:${port}` : ip;
}

function severityRank(severity?: string): number {
  switch ((severity || "").toUpperCase()) {
    case "CRITICAL":
      return 6;
    case "HIGH":
      return 5;
    case "MEDIUM":
      return 4;
    case "WARNING":
      return 3;
    case "LOW":
      return 2;
    case "INFO":
      return 1;
    default:
      return 0;
  }
}

function topSeverity(events: Event[], inventory?: InventoryDevice): string {
  const candidates = new Set<string>();
  events.forEach((event) => {
    if (event.severity) candidates.add(event.severity);
  });
  Object.entries(inventory?.severity_counts || {}).forEach(([key, count]) => {
    if (count > 0) candidates.add(key);
  });
  const sorted = Array.from(candidates).sort(
    (a, b) => severityRank(b) - severityRank(a)
  );
  return sorted[0] || "INFO";
}

function uniqueStrings(values: Array<string | undefined | null>): string[] {
  return Array.from(
    new Set(values.map((value) => (value || "").trim()).filter(Boolean))
  ).sort((a, b) => a.localeCompare(b));
}

function uniqueNumbers(values: Array<number | undefined | null>): number[] {
  return Array.from(
    new Set(values.filter((value): value is number => typeof value === "number"))
  ).sort((a, b) => a - b);
}

function joinLimited(values: string[], limit = 3): string {
  if (values.length === 0) return "-";
  if (values.length <= limit) return values.join(", ");
  return `${values.slice(0, limit).join(", ")} +${values.length - limit}`;
}

function normalizeDestination(flow: FlowRecord): string {
  return (
    flow.observed_destination ||
    flow.sni ||
    flow.host ||
    flow.dst_ip ||
    "-"
  );
}

function formatOWASP(tags?: string[]): string {
  if (!tags || tags.length === 0) return "-";
  return tags.join(", ");
}

function topKV(items?: KV[], limit = 5): KV[] {
  return (items || []).slice(0, limit);
}

function metricValue(items: KV[] | undefined, key: string): number {
  return (items || []).find((item) => item.key === key)?.count || 0;
}

function countByKey(values: Array<string | undefined | null>): KV[] {
  const counts = new Map<string, number>();
  values.forEach((value) => {
    const normalized = (value || "").trim();
    if (!normalized) return;
    counts.set(normalized, (counts.get(normalized) || 0) + 1);
  });
  return Array.from(counts.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

function isDebugEvent(event: Event): boolean {
  return (
    Boolean(event.debug) ||
    DEBUG_EVENT_TYPES.has((event.type || "").toUpperCase()) ||
    DEBUG_EVENT_TYPES.has((event.rule_id || "").toUpperCase())
  );
}

function isPrivateIPv4(ip?: string): boolean {
  const value = (ip || "").trim();
  if (!value) return false;
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return false;
  }
  if (octets[0] === 10) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  if (octets[0] === 192 && octets[1] === 168) return true;
  return false;
}

function isLocalHost(host: HostRow): boolean {
  return isPrivateIPv4(host.ip);
}

function nonDebugEvents(events: Event[]): Event[] {
  return events.filter((event) => !isDebugEvent(event));
}

function warningOrHigherEvents(events: Event[]): Event[] {
  return events.filter((event) => severityRank(event.severity) >= severityRank("WARNING"));
}

function defaultVisibleEvents(events: Event[]): Event[] {
  return warningOrHigherEvents(nonDebugEvents(events));
}

function visibleEvents(events: Event[]): Event[] {
  return defaultVisibleEvents(events);
}

function parseRuleCategory(rule?: string): string[] {
  const token = (rule || "").toUpperCase();
  const match = token.match(/^I\d+/);
  return match ? [match[0]] : [];
}

function eventOWASP(event: Event): string[] {
  const tags = uniqueStrings([...(event.owasp_tags || []), ...parseRuleCategory(event.rule_id || event.type)]);
  return tags;
}

function humanizeCategoryCandidate(value?: string): string {
  const token = (value || "").trim();
  if (!token) return "未分類IoT機器";
  if (/unknown/i.test(token)) return "未分類IoT機器";

  const map: Record<string, string> = {
    camera: "スマートカメラ候補",
    thermostat: "サーモスタット候補",
    smarttv: "スマートTV候補",
    tv: "スマートTV候補",
    controller: "IoTコントローラー候補",
    speaker: "スマートスピーカー候補",
    lock: "スマートロック候補",
    doorbell: "スマートドアベル候補",
  };
  const normalized = token.toLowerCase().replace(/[^a-z0-9]/g, "");
  for (const [key, label] of Object.entries(map)) {
    if (normalized.includes(key)) return label;
  }

  if (token.endsWith("候補")) return token;
  return `${token}候補`;
}

function humanizeLabelCandidate(value?: string, family?: string): string {
  const token = (value || family || "").trim();
  if (!token) return "未分類IoT機器";
  if (/unknown/i.test(token)) return "未分類IoT機器";
  return token.endsWith("候補") ? token : `${token}候補`;
}

function summarizeObservation(values: string[], prefix: string): string[] {
  return values.slice(0, 3).map((value) => `${prefix} ${value}`);
}

function deriveInferenceReasons(host: HostRow): string[] {
  const reasons = [
    ...summarizeObservation(host.sni, "TLS SNI observed:"),
    ...summarizeObservation(host.hosts, "HTTP Host observed:"),
    ...host.ports.slice(0, 4).map((port) => `Port ${port} traffic was observed.`),
    ...host.protocols.slice(0, 3).map((protocol) => `${protocol} communication was observed.`),
  ];
  return reasons.length > 0 ? reasons : ["Passive observations are limited; candidate classification remains provisional."];
}

function aggregateHosts(
  events: Event[],
  inventory: InventoryDevice[],
  flows: FlowRecord[]
): HostRow[] {
  const byIP = new Map<string, HostRow>();

  const ensureHost = (ip: string): HostRow => {
    const existing = byIP.get(ip);
    if (existing) return existing;
    const created: HostRow = {
      ip,
      labelCandidate: "",
      categoryCandidate: "",
      vendorCandidate: "",
      familyCandidate: "",
      confidence: "unknown",
      risk: "INFO",
      signals: 0,
      owasp: [],
      protocols: [],
      ports: [],
      topDestination: "-",
      externalDestinationCount: 0,
      hosts: [],
      sni: [],
      macAddress: "-",
      events: [],
      flows: [],
    };
    byIP.set(ip, created);
    return created;
  };

  inventory.forEach((device) => {
    if (!device.ip) return;
    const host = ensureHost(device.ip);
    host.inventory = device;
    host.categoryCandidate = device.category_candidate || host.categoryCandidate;
    host.vendorCandidate = device.vendor_candidate || host.vendorCandidate;
    host.familyCandidate = device.family_candidate || host.familyCandidate;
    host.labelCandidate =
      device.family_candidate ||
      device.vendor_candidate ||
      device.category_candidate ||
      host.labelCandidate;
    host.confidence =
      device.family_confidence ||
      device.vendor_confidence ||
      device.category_confidence ||
      host.confidence;
    host.protocols = uniqueStrings([
      ...host.protocols,
      ...(device.observed_protocols || []),
    ]);
    host.ports = uniqueNumbers([...host.ports, ...(device.observed_ports || [])]);
    host.hosts = uniqueStrings([...host.hosts, ...(device.observed_hosts || [])]);
    host.sni = uniqueStrings([...host.sni, ...(device.observed_sni || [])]);
    host.firstSeen = device.first_seen || host.firstSeen;
    host.lastSeen = device.last_seen || host.lastSeen;
  });

  events.forEach((event) => {
    const ip = event.src_ip || event.device_key;
    if (!ip) return;
    const host = ensureHost(ip);
    host.events.push(event);
  });

  flows.forEach((flow) => {
    if (!flow.src_ip) return;
    const host = ensureHost(flow.src_ip);
    host.flows.push(flow);
    host.protocols = uniqueStrings([
      ...host.protocols,
      flow.app_protocol,
      flow.protocol,
    ]);
    host.ports = uniqueNumbers([
      ...host.ports,
      flow.src_port,
      flow.dst_port,
    ]);
    host.hosts = uniqueStrings([...host.hosts, flow.host]);
    host.sni = uniqueStrings([...host.sni, flow.sni]);
    if (!host.labelCandidate) {
      host.labelCandidate = flow.device_label || flow.device_category || "";
    }
    if (!host.categoryCandidate) {
      host.categoryCandidate = flow.device_category || "";
    }
  });

  const hosts = Array.from(byIP.values()).map((host) => {
    const hostNonDebugEvents = nonDebugEvents(host.events);
    const eventOWASPSet = uniqueStrings(hostNonDebugEvents.flatMap((event) => eventOWASP(event)));
    const destinationCounts = new Map<string, number>();
    host.flows.forEach((flow) => {
      const destination = normalizeDestination(flow);
      destinationCounts.set(destination, (destinationCounts.get(destination) || 0) + 1);
    });
    const topDestination =
      Array.from(destinationCounts.entries()).sort((a, b) => {
        if (a[1] === b[1]) return a[0].localeCompare(b[0]);
        return b[1] - a[1];
      })[0]?.[0] || "-";

    const externalDestinationCount = uniqueStrings(
      host.flows
        .filter((flow) => flow.direction === "external")
        .map((flow) => normalizeDestination(flow))
    ).length;
    const inventoryOWASP = host.inventory?.risk_summary?.top_owasp_tags
      ? host.inventory.risk_summary.top_owasp_tags
      : host.inventory?.owasp_tag_counts
        ? Object.entries(host.inventory.owasp_tag_counts)
            .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
            .map(([key]) => key)
        : undefined;

    return {
      ...host,
      labelCandidate: humanizeLabelCandidate(
        host.labelCandidate,
        host.familyCandidate || host.categoryCandidate
      ),
      categoryCandidate: humanizeCategoryCandidate(host.categoryCandidate),
      vendorCandidate: host.vendorCandidate || "不明候補",
      familyCandidate: host.familyCandidate || "不明候補",
      confidence: host.confidence || "unknown",
      risk: topSeverity(hostNonDebugEvents, host.inventory),
      signals:
        host.inventory?.risk_summary?.risk_event_count ||
        host.inventory?.risk_event_count ||
        hostNonDebugEvents.length,
      owasp: inventoryOWASP || eventOWASPSet,
      topDestination,
      externalDestinationCount,
      firstSeen:
        host.firstSeen ||
        host.events.slice().sort((a, b) => a.ts.localeCompare(b.ts))[0]?.ts,
      lastSeen:
        host.lastSeen ||
        host.events
          .slice()
          .sort((a, b) => b.ts.localeCompare(a.ts))[0]?.ts,
      macAddress: "-",
      events: host.events.slice().sort((a, b) => b.ts.localeCompare(a.ts)),
      flows: host.flows.slice().sort((a, b) => b.ts.localeCompare(a.ts)),
    };
  });

  return hosts.sort((a, b) => {
    if (severityRank(a.risk) === severityRank(b.risk)) {
      return a.ip.localeCompare(b.ip);
    }
    return severityRank(b.risk) - severityRank(a.risk);
  });
}

function linkClassName(active = false): string {
  return cn(
    "inline-flex items-center border-b-2 px-4 py-3 text-sm",
    active
      ? "border-[#2563eb] text-foreground"
      : "border-transparent text-muted-foreground hover:text-foreground"
  );
}

function SeverityBadge({ severity }: { severity?: string }) {
  const value = (severity || "UNKNOWN").toUpperCase();
  const styles: Record<string, string> = {
    CRITICAL:
      "border-[#d92d20] bg-[#fff1f1] text-[#b42318]",
    HIGH: "border-[#f79009] bg-[#fff7ed] text-[#b54708]",
    MEDIUM: "border-[#f6c343] bg-[#fffbea] text-[#8a6116]",
    WARNING: "border-[#f6c343] bg-[#fffbea] text-[#8a6116]",
    LOW: "border-[#60a5fa] bg-[#eff6ff] text-[#1d4ed8]",
    INFO: "border-[#cbd5e1] bg-[#f8fafc] text-[#475569]",
  };

  return (
    <span
      className={cn(
        "inline-flex min-w-[74px] justify-center rounded border px-2 py-0.5 text-[11px] font-semibold tracking-[0.02em]",
        styles[value] || "border-border bg-muted text-foreground"
      )}
    >
      {value}
    </span>
  );
}

function OWASPLabel({ tag }: { tag: string }) {
  return (
    <span className="inline-flex rounded border border-border bg-[#f8fafc] px-1.5 py-0.5 text-[11px] text-[#334155]">
      {tag}
    </span>
  );
}

function Section({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="border border-border bg-card">
      <div className="border-b border-border px-5 py-4">
        <h2 className="text-lg font-semibold">{title}</h2>
        {description ? (
          <p className="mt-1 text-sm text-muted-foreground">{description}</p>
        ) : null}
      </div>
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}

function SummaryLine({ children }: { children: React.ReactNode }) {
  return (
    <div className="border border-border bg-[#fcfcfd] px-4 py-3 text-sm text-[#334155]">
      {children}
    </div>
  );
}

function MetricCard({
  label,
  value,
  helper,
}: {
  label: string;
  value: string | number;
  helper?: string;
}) {
  return (
    <div className="border border-border bg-card px-4 py-4">
      <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[#667085]">
        {label}
      </div>
      <div className="mt-2 font-mono text-3xl font-semibold text-[#101828]">
        {value}
      </div>
      {helper ? (
        <div className="mt-1 text-xs text-[#667085]">{helper}</div>
      ) : null}
    </div>
  );
}

function JsonDisclosure({
  label,
  value,
}: {
  label: string;
  value: unknown;
}) {
  return (
    <details className="border border-border bg-[#fcfcfd]">
      <summary className="cursor-pointer px-3 py-2 text-sm text-[#2563eb]">
        {label}
      </summary>
      <pre className="overflow-x-auto border-t border-border px-3 py-3 text-xs leading-5 text-[#334155]">
        {JSON.stringify(value, null, 2)}
      </pre>
    </details>
  );
}

function OverviewView({
  report,
  hosts,
  onOpenHost,
}: {
  report: Report | null;
  hosts: HostRow[];
  onOpenHost: (ip: string) => void;
}) {
  const events = report?.events || [];
  const nonDebugEvents = visibleEvents(events);
  const debugEvents = events.filter((event) => isDebugEvent(event));
  const riskSignals = warningOrHigherEvents(nonDebugEvents)
    .slice()
    .sort((a, b) => {
      if (severityRank(a.severity) !== severityRank(b.severity)) {
        return severityRank(b.severity) - severityRank(a.severity);
      }
      return b.ts.localeCompare(a.ts);
    });
  const warnings = nonDebugEvents.filter(
    (event) => (event.severity || "").toUpperCase() === "WARNING"
  ).length;
  const highCritical = nonDebugEvents.filter(
    (event) => severityRank(event.severity) >= severityRank("HIGH")
  ).length;
  const localHosts = hosts.filter((host) => isLocalHost(host));
  const externalHosts = hosts.filter((host) => !isLocalHost(host));
  const visibleRules = countByKey(nonDebugEvents.map((event) => event.rule_id || event.type));
  const visibleCategories = countByKey(nonDebugEvents.map((event) => event.category));
  const visibleSources = countByKey(nonDebugEvents.map((event) => event.src_ip || event.device_key));
  const sourceLabel = report?.source || "-";
  const highCount = nonDebugEvents.length > 0 ? nonDebugEvents.filter((event) => (event.severity || "").toUpperCase() === "HIGH").length : metricValue(report?.severity, "HIGH");
  const criticalCount = nonDebugEvents.length > 0 ? nonDebugEvents.filter((event) => (event.severity || "").toUpperCase() === "CRITICAL").length : metricValue(report?.severity, "CRITICAL");
  const warningCount = nonDebugEvents.length > 0 ? warnings : metricValue(report?.severity, "WARNING");
  const totalVisibleEvents = nonDebugEvents.length > 0 ? nonDebugEvents.length : report?.total_events || 0;

  return (
    <div className="space-y-6">
      <Section
        title="Overview"
        description="観測入力の由来、件数、主要カテゴリを最初に把握するためのサマリです。"
      >
        <div className="space-y-4">
          <SummaryLine>
            {totalVisibleEvents} visible events ・ {riskSignals.length} risk signals ・{" "}
            {warningCount} warnings ・ {localHosts.length} local devices ・ {externalHosts.length} external destinations ・ 観測期間{" "}
            {formatWindow(report?.window?.start, report?.window?.end)}
            {debugEvents.length > 0 ? ` ・ ${debugEvents.length} debug events hidden by default` : ""}
          </SummaryLine>

          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
            <MetricCard
              label="Total Visible Events"
              value={totalVisibleEvents}
              helper={`source: ${sourceLabel}`}
            />
            <MetricCard
              label="Risk Signals"
              value={riskSignals.length}
              helper={debugEvents.length > 0 ? `${debugEvents.length} debug events hidden` : "debug events excluded"}
            />
            <MetricCard
              label="Warnings"
              value={warningCount}
              helper="warning-level signals highlighted"
            />
            <MetricCard
              label="High / Critical"
              value={highCount + criticalCount}
              helper={`critical ${criticalCount} / high ${highCount}`}
            />
            <MetricCard
              label="Local Devices"
              value={localHosts.length}
              helper={`${report?.unknown_devices || 0} unknown devices`}
            />
            <MetricCard
              label="External Destinations"
              value={externalHosts.length}
              helper={`${report?.user_notifications || 0} user notifications`}
            />
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <div className="border border-border">
              <div className="border-b border-border bg-[#fafafa] px-4 py-2 text-sm font-medium">
                Top Rules
              </div>
              <div className="divide-y divide-border">
                {topKV(nonDebugEvents.length > 0 ? visibleRules : report?.rules).length > 0 ? (
                  topKV(nonDebugEvents.length > 0 ? visibleRules : report?.rules).map((item) => (
                    <div
                      key={item.key}
                      className="flex items-center justify-between px-4 py-2 text-sm"
                    >
                      <span className="font-mono text-xs text-[#334155]">{item.key}</span>
                      <span className="font-mono text-xs text-[#667085]">{item.count}</span>
                    </div>
                  ))
                ) : (
                  <div className="px-4 py-3 text-sm text-muted-foreground">
                    No rule summary available.
                  </div>
                )}
              </div>
            </div>

            <div className="border border-border">
              <div className="border-b border-border bg-[#fafafa] px-4 py-2 text-sm font-medium">
                Top OWASP Categories
              </div>
              <div className="divide-y divide-border">
                {topKV(nonDebugEvents.length > 0 ? visibleCategories : report?.categories).length > 0 ? (
                  topKV(nonDebugEvents.length > 0 ? visibleCategories : report?.categories).map((item) => (
                    <div
                      key={item.key}
                      className="flex items-center justify-between px-4 py-2 text-sm"
                    >
                      <span>{item.key}</span>
                      <span className="font-mono text-xs text-[#667085]">{item.count}</span>
                    </div>
                  ))
                ) : (
                  <div className="px-4 py-3 text-sm text-muted-foreground">
                    No category summary available.
                  </div>
                )}
              </div>
            </div>

            <div className="border border-border">
              <div className="border-b border-border bg-[#fafafa] px-4 py-2 text-sm font-medium">
                Top Source IP
              </div>
              <div className="divide-y divide-border">
                {topKV(nonDebugEvents.length > 0 ? visibleSources : report?.sources).length > 0 ? (
                  topKV(nonDebugEvents.length > 0 ? visibleSources : report?.sources).map((item) => (
                    <div
                      key={item.key}
                      className="flex items-center justify-between px-4 py-2 text-sm"
                    >
                      <span className="font-mono text-xs text-[#334155]">{item.key}</span>
                      <span className="font-mono text-xs text-[#667085]">{item.count}</span>
                    </div>
                  ))
                ) : (
                  <div className="px-4 py-3 text-sm text-muted-foreground">
                    No source summary available.
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <div className="text-sm font-medium">Risk Signals</div>
            <Table className="text-[13px]">
              <TableHeader>
                <TableRow className="bg-[#fafafa] hover:bg-[#fafafa]">
                  <TableHead>Severity</TableHead>
                  <TableHead>Rule ID</TableHead>
                  <TableHead>OWASP Tags</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Observed Fact</TableHead>
                  <TableHead>Evidence</TableHead>
                  <TableHead>Device IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {riskSignals.length > 0 ? (
                  riskSignals.map((event, index) => (
                    <TableRow key={`${event.ts}-${event.rule_id}-${index}`}>
                      <TableCell><SeverityBadge severity={event.severity} /></TableCell>
                      <TableCell className="font-mono text-xs">
                        {event.rule_id || event.type || "-"}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {eventOWASP(event).map((tag) => (
                            <OWASPLabel key={tag} tag={tag} />
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>{event.confidence || "-"}</TableCell>
                      <TableCell className="max-w-[280px] whitespace-normal">
                        {event.observed_fact || "-"}
                      </TableCell>
                      <TableCell className="max-w-[260px] whitespace-normal font-mono text-xs text-muted-foreground">
                        {event.evidence || "-"}
                      </TableCell>
                      <TableCell>
                        <button
                          onClick={() => event.src_ip && onOpenHost(event.src_ip)}
                          className="text-[#2563eb] hover:underline"
                        >
                          {event.src_ip || "-"}
                        </button>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground">
                      観測対象のリスクシグナルはありません。
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>

          <div className="space-y-2">
            <div className="text-sm font-medium">All Events</div>
            {nonDebugEvents.length === 0 ? (
              <SummaryLine>
                この `report` にはイベント配列が含まれていません。summary-only の
                `report.json` を読み込んでいる場合、Overview の集計だけが表示されます。
              </SummaryLine>
            ) : null}
            <Table className="text-[13px]">
              <TableHeader>
                <TableRow className="bg-[#fafafa] hover:bg-[#fafafa]">
                  <TableHead>Time</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Rule ID</TableHead>
                  <TableHead>OWASP</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Source → Destination</TableHead>
                  <TableHead>Evidence</TableHead>
                  <TableHead>Message</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {nonDebugEvents.map((event, index) => (
                  <TableRow key={`${event.ts}-${event.rule_id || event.type}-${index}`}>
                    <TableCell className="font-mono text-xs">{formatTime(event.ts)}</TableCell>
                    <TableCell><SeverityBadge severity={event.severity} /></TableCell>
                    <TableCell className="font-mono text-xs">
                      {event.rule_id || event.type || "-"}
                    </TableCell>
                    <TableCell>{formatOWASP(eventOWASP(event))}</TableCell>
                    <TableCell>{event.confidence || "-"}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {endpoint(event.src_ip, event.src_port)} {"->"}{" "}
                      {endpoint(event.dst_ip, event.dst_port)}
                    </TableCell>
                    <TableCell className="max-w-[240px] whitespace-normal font-mono text-xs text-muted-foreground">
                      {event.evidence || "-"}
                    </TableCell>
                    <TableCell className="max-w-[280px] whitespace-normal">
                      {event.message || "-"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      </Section>
    </div>
  );
}

function DevicesView({
  hosts,
  onOpenHost,
}: {
  hosts: HostRow[];
  onOpenHost: (ip: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");
  const [owaspFilter, setOwaspFilter] = useState("all");
  const deferredQuery = useDeferredValue(query);

  const owaspOptions = uniqueStrings(hosts.flatMap((host) => host.owasp));
  const filteredHosts = hosts.filter((host) => {
    const haystack = [
      host.ip,
      host.labelCandidate,
      host.categoryCandidate,
      host.vendorCandidate,
      host.familyCandidate,
      host.topDestination,
      ...host.protocols,
      ...host.hosts,
      ...host.sni,
      ...host.owasp,
    ]
      .join(" ")
      .toLowerCase();

    if (riskFilter !== "all" && host.risk !== riskFilter) {
      return false;
    }
    if (owaspFilter !== "all" && !host.owasp.includes(owaspFilter)) {
      return false;
    }
    if (
      deferredQuery.trim() &&
      !haystack.includes(deferredQuery.trim().toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  const withSignals = hosts.filter((host) => host.signals > 0).length;
  const unclassified = hosts.filter((host) =>
    host.categoryCandidate.includes("未分類")
  ).length;
  const localHosts = filteredHosts.filter((host) => isLocalHost(host));
  const externalHosts = filteredHosts.filter((host) => !isLocalHost(host));

  return (
    <div className="space-y-6">
      <Section
        title="Devices"
        description="LAN内端末と外部通信先を分けて一覧表示します。"
      >
        <div className="space-y-4">
          <SummaryLine>
            {hosts.length} hosts observed ・ {withSignals} with risk signals ・{" "}
            {unclassified} unclassified ・ {localHosts.length} local devices shown ・ {externalHosts.length} external destinations shown
          </SummaryLine>

          <div className="grid gap-3 lg:grid-cols-[minmax(0,2fr)_repeat(2,minmax(0,1fr))]">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search IP, candidate label, vendor, protocol, destination, or SNI"
                className="pl-9"
              />
            </div>
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Risk" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Risk</SelectItem>
                {uniqueStrings(hosts.map((host) => host.risk)).map((value) => (
                  <SelectItem key={value} value={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={owaspFilter} onValueChange={setOwaspFilter}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="OWASP" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All OWASP</SelectItem>
                {owaspOptions.map((value) => (
                  <SelectItem key={value} value={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <SummaryLine>{filteredHosts.length} hosts shown</SummaryLine>

          <div className="space-y-6">
            <div className="space-y-2">
              <div className="text-sm font-medium">Local Devices</div>
              <HostTable hosts={localHosts} onOpenHost={onOpenHost} emptyLabel="条件に一致する local device はありません。" />
            </div>

            <div className="space-y-2">
              <div className="text-sm font-medium">External Destinations</div>
              <HostTable hosts={externalHosts} onOpenHost={onOpenHost} emptyLabel="条件に一致する external destination はありません。" />
            </div>
          </div>
        </div>
      </Section>
    </div>
  );
}

function HostTable({
  hosts,
  onOpenHost,
  emptyLabel,
}: {
  hosts: HostRow[];
  onOpenHost: (ip: string) => void;
  emptyLabel: string;
}) {
  return (
    <Table className="text-[13px]">
      <TableHeader>
        <TableRow className="bg-[#fafafa] hover:bg-[#fafafa]">
          <TableHead>IP Address</TableHead>
          <TableHead>Label / Candidate</TableHead>
          <TableHead>Category Candidate</TableHead>
          <TableHead>Vendor Candidate</TableHead>
          <TableHead>Risk</TableHead>
          <TableHead>Signals</TableHead>
          <TableHead>OWASP</TableHead>
          <TableHead>Protocols</TableHead>
          <TableHead>Top Destination</TableHead>
          <TableHead>Last Seen</TableHead>
          <TableHead>Detail</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {hosts.length > 0 ? hosts.map((host) => (
          <TableRow key={host.ip}>
            <TableCell className="font-mono text-xs">{host.ip}</TableCell>
            <TableCell>{host.labelCandidate}</TableCell>
            <TableCell>{host.categoryCandidate}</TableCell>
            <TableCell>{host.vendorCandidate}</TableCell>
            <TableCell><SeverityBadge severity={host.risk} /></TableCell>
            <TableCell>{host.signals}</TableCell>
            <TableCell>{joinLimited(host.owasp, 3)}</TableCell>
            <TableCell>{joinLimited(host.protocols, 3)}</TableCell>
            <TableCell className="max-w-[180px] truncate" title={host.topDestination}>
              {host.topDestination}
            </TableCell>
            <TableCell className="font-mono text-xs">
              {formatTime(host.lastSeen)}
            </TableCell>
            <TableCell>
              <button
                onClick={() => onOpenHost(host.ip)}
                className="text-[#2563eb] hover:underline"
              >
                Host Report
              </button>
            </TableCell>
          </TableRow>
        )) : (
          <TableRow>
            <TableCell colSpan={11} className="text-center text-muted-foreground">
              {emptyLabel}
            </TableCell>
          </TableRow>
        )}
      </TableBody>
    </Table>
  );
}

function HostReportView({
  host,
  onBack,
}: {
  host: HostRow;
  onBack: () => void;
}) {
  const nonDebugEvents = visibleEvents(host.events);
  const hiddenDebugCount = host.events.length - nonDebugEvents.length;
  const highCritical = nonDebugEvents.filter(
    (event) => severityRank(event.severity) >= severityRank("HIGH")
  ).length;
  const relatedEvents = nonDebugEvents.slice().sort((a, b) => b.ts.localeCompare(a.ts));
  const topDestinations = uniqueStrings(
    host.flows
      .filter((flow) => flow.direction === "external")
      .map((flow) => normalizeDestination(flow))
  );
  const inferenceReasons = deriveInferenceReasons(host);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <button onClick={onBack} className="text-sm text-[#2563eb] hover:underline">
          Devices
        </button>
        <ChevronRight className="size-4 text-muted-foreground" />
        <div className="text-sm text-muted-foreground">Host Report</div>
      </div>

      <Section
        title={`Host Report: ${host.ip}`}
        description="1台のホストについて、観測情報と候補情報を分けて表示します。"
      >
        <div className="space-y-4">
          <SummaryLine>
            {host.signals} risk signals ・ {highCritical} high/critical ・{" "}
            {host.protocols.length} protocols ・ {host.externalDestinationCount} external destinations ・{" "}
            {uniqueStrings(host.owasp).length} OWASP categories
            {hiddenDebugCount > 0 ? ` ・ ${hiddenDebugCount} debug events hidden` : ""}
          </SummaryLine>

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="border border-border">
              <div className="border-b border-border bg-[#fafafa] px-4 py-2 text-sm font-medium">
                Device Profile
              </div>
              <div className="space-y-4 px-4 py-4 text-sm">
                <div>
                  <div className="mb-2 font-medium">Observed</div>
                  <dl className="grid grid-cols-[150px_1fr] gap-y-2">
                    <dt className="text-muted-foreground">IP Address</dt>
                    <dd className="font-mono text-xs">{host.ip}</dd>
                    <dt className="text-muted-foreground">MAC Address</dt>
                    <dd>{host.macAddress}</dd>
                    <dt className="text-muted-foreground">First Seen</dt>
                    <dd className="font-mono text-xs">{formatTime(host.firstSeen)}</dd>
                    <dt className="text-muted-foreground">Last Seen</dt>
                    <dd className="font-mono text-xs">{formatTime(host.lastSeen)}</dd>
                    <dt className="text-muted-foreground">Protocols</dt>
                    <dd>{joinLimited(host.protocols, 5)}</dd>
                    <dt className="text-muted-foreground">Ports</dt>
                    <dd className="font-mono text-xs">
                      {host.ports.length > 0 ? host.ports.join(", ") : "-"}
                    </dd>
                  </dl>
                </div>

                <div>
                  <div className="mb-2 font-medium">Inferred / Candidate</div>
                  <dl className="grid grid-cols-[150px_1fr] gap-y-2">
                    <dt className="text-muted-foreground">Label Candidate</dt>
                    <dd>{host.labelCandidate}</dd>
                    <dt className="text-muted-foreground">Category Candidate</dt>
                    <dd>{host.categoryCandidate}</dd>
                    <dt className="text-muted-foreground">Vendor Candidate</dt>
                    <dd>{host.vendorCandidate}</dd>
                    <dt className="text-muted-foreground">Family Candidate</dt>
                    <dd>{host.familyCandidate}</dd>
                    <dt className="text-muted-foreground">Confidence</dt>
                    <dd>{host.confidence}</dd>
                  </dl>
                </div>

                <div>
                  <div className="mb-2 font-medium">Inference Reasons</div>
                  <ul className="space-y-1 text-sm text-[#334155]">
                    {inferenceReasons.map((reason) => (
                      <li key={reason}>- {reason}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div className="border border-border">
                <div className="border-b border-border bg-[#fafafa] px-4 py-2 text-sm font-medium">
                  Observed Communication
                </div>
                <div className="px-4 py-4 text-sm">
                  <dl className="grid grid-cols-[150px_1fr] gap-y-2">
                    <dt className="text-muted-foreground">Protocols Observed</dt>
                    <dd>{joinLimited(host.protocols, 6)}</dd>
                    <dt className="text-muted-foreground">Common Ports</dt>
                    <dd className="font-mono text-xs">
                      {host.ports.length > 0 ? host.ports.join(", ") : "-"}
                    </dd>
                    <dt className="text-muted-foreground">Top Destinations</dt>
                    <dd>{joinLimited(topDestinations, 4)}</dd>
                    <dt className="text-muted-foreground">TLS SNI</dt>
                    <dd>{joinLimited(host.sni, 4)}</dd>
                    <dt className="text-muted-foreground">HTTP Hosts</dt>
                    <dd>{joinLimited(host.hosts, 4)}</dd>
                  </dl>
                </div>
              </div>

              <div className="border border-border">
                <div className="border-b border-border bg-[#fafafa] px-4 py-2 text-sm font-medium">
                  Risk Signals
                </div>
                <div className="p-0">
                  <Table className="text-[13px]">
                    <TableHeader>
                      <TableRow className="bg-[#fafafa] hover:bg-[#fafafa]">
                        <TableHead>Severity</TableHead>
                        <TableHead>Rule ID</TableHead>
                        <TableHead>OWASP Tags</TableHead>
                        <TableHead>Confidence</TableHead>
                        <TableHead>Observed Fact</TableHead>
                        <TableHead>Evidence</TableHead>
                        <TableHead>Inference</TableHead>
                        <TableHead>Limitation</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {relatedEvents.map((event, index) => (
                        <TableRow key={`${event.ts}-${event.rule_id || event.type}-${index}`}>
                          <TableCell><SeverityBadge severity={event.severity} /></TableCell>
                          <TableCell className="font-mono text-xs">
                            {event.rule_id || event.type || "-"}
                          </TableCell>
                          <TableCell>{formatOWASP(eventOWASP(event))}</TableCell>
                          <TableCell>{event.confidence || "-"}</TableCell>
                          <TableCell className="max-w-[220px] whitespace-normal">
                            {event.observed_fact || "-"}
                          </TableCell>
                          <TableCell className="max-w-[220px] whitespace-normal font-mono text-xs text-muted-foreground">
                            {event.evidence || "-"}
                          </TableCell>
                          <TableCell className="max-w-[220px] whitespace-normal">
                            {event.inference || "-"}
                          </TableCell>
                          <TableCell className="max-w-[220px] whitespace-normal">
                            {event.limitation || "-"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <div className="text-sm font-medium">Related Events</div>
            <Table className="text-[13px]">
              <TableHeader>
                <TableRow className="bg-[#fafafa] hover:bg-[#fafafa]">
                  <TableHead>Time</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Rule ID</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Evidence</TableHead>
                  <TableHead>Message</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {relatedEvents.map((event, index) => (
                  <TableRow key={`${event.ts}-related-${index}`}>
                    <TableCell className="font-mono text-xs">{formatTime(event.ts)}</TableCell>
                    <TableCell><SeverityBadge severity={event.severity} /></TableCell>
                    <TableCell className="font-mono text-xs">
                      {event.rule_id || event.type || "-"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {endpoint(event.dst_ip, event.dst_port)}
                    </TableCell>
                    <TableCell className="max-w-[240px] whitespace-normal font-mono text-xs text-muted-foreground">
                      {event.evidence || "-"}
                    </TableCell>
                    <TableCell className="max-w-[280px] whitespace-normal">
                      {event.message || "-"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <JsonDisclosure label="Raw JSON" value={host} />
        </div>
      </Section>
    </div>
  );
}

function EventDetails({ event }: { event: Event }) {
  return (
    <div className="grid gap-3 border-t border-border bg-[#fcfcfd] px-4 py-4 text-sm">
      <div className="grid gap-3 md:grid-cols-4">
        <div>
          <div className="text-xs text-muted-foreground">Severity</div>
          <div className="mt-1"><SeverityBadge severity={event.severity} /></div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Rule ID</div>
          <div className="font-mono text-xs">{event.rule_id || event.type || "-"}</div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">OWASP</div>
          <div>{formatOWASP(eventOWASP(event))}</div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Device / Source</div>
          <div className="font-mono text-xs">{event.device_key || event.src_ip || "-"}</div>
        </div>
      </div>
      <div>
        <div className="text-xs text-muted-foreground">Observed Fact</div>
        <div>{event.observed_fact || "-"}</div>
      </div>
      <div>
        <div className="text-xs text-muted-foreground">Evidence</div>
        <div className="font-mono text-xs text-[#475569]">{event.evidence || "-"}</div>
      </div>
      <div>
        <div className="text-xs text-muted-foreground">Inference</div>
        <div>{event.inference || "-"}</div>
      </div>
      <div>
        <div className="text-xs text-muted-foreground">Limitation</div>
        <div>{event.limitation || "-"}</div>
      </div>
      <div>
        <div className="text-xs text-muted-foreground">Recommendation</div>
        <div>{event.recommendation || "-"}</div>
      </div>
      <JsonDisclosure label="Raw JSON" value={event} />
    </div>
  );
}

function EventsView({
  report,
  hosts,
}: {
  report: Report | null;
  hosts: HostRow[];
}) {
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [owaspFilter, setOwaspFilter] = useState("all");
  const [ruleFilter, setRuleFilter] = useState("all");
  const [deviceFilter, setDeviceFilter] = useState("all");
  const [showDebugEvents, setShowDebugEvents] = useState(false);
  const [openRows, setOpenRows] = useState<Record<string, boolean>>({});
  const deferredQuery = useDeferredValue(query);

  const events = report?.events || [];
  const candidateEvents = showDebugEvents ? events : visibleEvents(events);
  const hiddenDebugCount = events.filter((event) => isDebugEvent(event)).length;
  const owaspOptions = uniqueStrings(candidateEvents.flatMap((event) => eventOWASP(event)));
  const ruleOptions = uniqueStrings(candidateEvents.map((event) => event.rule_id || event.type));
  const deviceOptions = uniqueStrings(
    candidateEvents.flatMap((event) => [event.device_key, event.device_label, event.src_ip])
  );

  const filtered = candidateEvents.filter((event) => {
    const tags = eventOWASP(event);
    const haystack = [
      event.rule_id,
      event.type,
      event.category,
      event.message,
      event.evidence,
      event.observed_fact,
      event.inference,
      event.device_key,
      event.device_label,
      event.src_ip,
      event.dst_ip,
      ...tags,
    ]
      .join(" ")
      .toLowerCase();

    if (severityFilter !== "all" && (event.severity || "") !== severityFilter) {
      return false;
    }
    if (owaspFilter !== "all" && !tags.includes(owaspFilter)) {
      return false;
    }
    if (ruleFilter !== "all" && (event.rule_id || event.type || "") !== ruleFilter) {
      return false;
    }
    if (
      deviceFilter !== "all" &&
      ![event.device_key, event.device_label, event.src_ip].includes(deviceFilter)
    ) {
      return false;
    }
    if (
      deferredQuery.trim() &&
      !haystack.includes(deferredQuery.trim().toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      <Section
        title="Events"
        description="全イベントを検索・フィルタし、根拠と制約を確認します。"
      >
        <div className="space-y-4">
          <div className="grid gap-3 lg:grid-cols-[minmax(0,2fr)_repeat(4,minmax(0,1fr))]">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search device, IP, rule, OWASP, observed fact, evidence, or inference"
                className="pl-9"
              />
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severity</SelectItem>
                {uniqueStrings(events.map((event) => event.severity)).map((value) => (
                  <SelectItem key={value} value={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={owaspFilter} onValueChange={setOwaspFilter}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="OWASP" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All OWASP</SelectItem>
                {owaspOptions.map((value) => (
                  <SelectItem key={value} value={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={ruleFilter} onValueChange={setRuleFilter}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Rule ID" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Rules</SelectItem>
                {ruleOptions.map((value) => (
                  <SelectItem key={value} value={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={deviceFilter} onValueChange={setDeviceFilter}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Device / IP" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Devices</SelectItem>
                {deviceOptions.map((value) => (
                  <SelectItem key={value} value={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <SummaryLine>
              {filtered.length} events shown
              {!showDebugEvents && hiddenDebugCount > 0 ? ` ・ ${hiddenDebugCount} debug events hidden` : ""}
            </SummaryLine>
            <Button
              variant={showDebugEvents ? "default" : "outline"}
              onClick={() => setShowDebugEvents((current) => !current)}
              className="h-9 rounded-none"
            >
              {showDebugEvents ? "Hide Debug Events" : "Show Debug Events"}
            </Button>
          </div>

          <div className="border border-border">
            <Table className="text-[13px]">
              <TableHeader>
                <TableRow className="bg-[#fafafa] hover:bg-[#fafafa]">
                  <TableHead>Time</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Rule ID</TableHead>
                  <TableHead>OWASP</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Evidence</TableHead>
                  <TableHead>Observed Fact</TableHead>
                  <TableHead>Message</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.length > 0 ? filtered.map((event, index) => {
                  const rowKey = `${event.ts}-${event.rule_id || event.type}-${index}`;
                  const isOpen = Boolean(openRows[rowKey]);

                  return (
                    <Fragment key={rowKey}>
                      <TableRow
                        className="cursor-pointer"
                        onClick={() =>
                          setOpenRows((current) => ({
                            ...current,
                            [rowKey]: !current[rowKey],
                          }))
                        }
                      >
                        <TableCell className="font-mono text-xs">{formatTime(event.ts)}</TableCell>
                        <TableCell><SeverityBadge severity={event.severity} /></TableCell>
                        <TableCell className="font-mono text-xs">
                          {event.rule_id || event.type || "-"}
                        </TableCell>
                        <TableCell>{formatOWASP(eventOWASP(event))}</TableCell>
                        <TableCell>{event.confidence || "-"}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {endpoint(event.src_ip, event.src_port)}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {endpoint(event.dst_ip, event.dst_port)}
                        </TableCell>
                        <TableCell className="max-w-[200px] whitespace-normal font-mono text-xs text-muted-foreground">
                          {event.evidence || "-"}
                        </TableCell>
                        <TableCell className="max-w-[220px] whitespace-normal">
                          {event.observed_fact || "-"}
                        </TableCell>
                        <TableCell className="max-w-[220px] whitespace-normal">
                          {event.message || "-"}
                        </TableCell>
                      </TableRow>
                      {isOpen ? (
                        <TableRow className="hover:bg-transparent">
                          <TableCell colSpan={10} className="p-0">
                            <EventDetails event={event} />
                          </TableCell>
                        </TableRow>
                      ) : null}
                    </Fragment>
                  );
                }) : (
                  <TableRow>
                    <TableCell colSpan={10} className="text-center text-muted-foreground">
                      条件に一致する event はありません。
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </div>
      </Section>
    </div>
  );
}

function QuarantReportViewerContent() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const [report, setReport] = useState<Report | null>(null);
  const [inventory, setInventory] = useState<InventoryReport | null>(null);
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [status, setStatus] = useState("Loading...");
  const [error, setError] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const viewParam = searchParams.get("view");
  const activeView: ViewName =
    viewParam === "devices" || viewParam === "events" ? viewParam : "overview";
  const activeHost = searchParams.get("host");

  async function loadData(): Promise<void> {
    try {
      setIsRefreshing(true);
      setError("");

      const [reportResponse, inventoryResponse, flowsResponse] =
        await Promise.all([
          fetch(`${API_BASE_URL}/api/report`, { cache: "no-store" }),
          fetch(`${API_BASE_URL}/api/inventory`, { cache: "no-store" }),
          fetch(`${API_BASE_URL}/api/flows`, { cache: "no-store" }),
        ]);

      if (!reportResponse.ok) {
        throw new Error(`report HTTP ${reportResponse.status}`);
      }

      const [nextReport, nextInventory, nextFlows] = await Promise.all([
        reportResponse.json() as Promise<Report>,
        inventoryResponse.ok
          ? (inventoryResponse.json() as Promise<InventoryReport>)
          : Promise.resolve({ devices: [] }),
        flowsResponse.ok
          ? (flowsResponse.json() as Promise<FlowRecord[]>)
          : Promise.resolve([]),
      ]);

      setReport(nextReport);
      setInventory(nextInventory);
      setFlows(nextFlows);
      setStatus("Connected");
      setLastUpdated(new Date());
    } catch (fetchError) {
      const message =
        fetchError instanceof Error ? fetchError.message : "Unknown error";
      setError(message);
      setStatus("Error");
    } finally {
      setIsRefreshing(false);
    }
  }

  useEffect(() => {
    void loadData();
  }, []);

  function setView(view: ViewName, host?: string): void {
    const params = new URLSearchParams(searchParams.toString());
    params.set("view", view);
    if (host) {
      params.set("host", host);
    } else {
      params.delete("host");
    }
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname);
  }

  const hosts = aggregateHosts(report?.events || [], inventory?.devices || [], flows);
  const selectedHost = hosts.find((host) => host.ip === activeHost);

  return (
    <div className="min-h-screen bg-white text-[#0f172a]">
      <header className="border-b border-border bg-white">
        <div className="mx-auto max-w-[1440px] px-7 py-5">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <h1 className="text-[42px] font-semibold tracking-[-0.03em]">
                Quarant
              </h1>
              <p className="mt-1 text-lg text-[#475569]">
                IoT Passive Observation Report Viewer
              </p>
            </div>

            <div className="text-right text-sm text-[#475569]">
              <div>API: {API_BASE_URL}</div>
              <div>Status: {status}</div>
              <div>Report: {report?.source || "-"}</div>
              <div>Updated: {lastUpdated ? formatTime(lastUpdated.toISOString()) : "-"}</div>
            </div>
          </div>

          <nav className="mt-5 flex items-center gap-2">
            <button
              onClick={() => setView("overview")}
              className={linkClassName(activeView === "overview" && !selectedHost)}
            >
              Overview
            </button>
            <button
              onClick={() => setView("devices")}
              className={linkClassName(activeView === "devices" || Boolean(selectedHost))}
            >
              Devices
            </button>
            <button
              onClick={() => setView("events")}
              className={linkClassName(activeView === "events")}
            >
              Events
            </button>

            <div className="ml-auto">
              <Button
                variant="outline"
                onClick={() => void loadData()}
                disabled={isRefreshing}
                className="h-9 rounded-none border-[#d0d5dd]"
              >
                <RefreshCw className={cn("mr-2 size-4", isRefreshing && "animate-spin")} />
                Refresh
              </Button>
            </div>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-[1440px] px-7 py-8">
        {error ? (
          <div className="mb-6 border border-[#fda29b] bg-[#fff5f4] px-4 py-3 text-sm text-[#b42318]">
            API 接続に失敗しました: {error}
          </div>
        ) : null}

        {selectedHost ? (
          <HostReportView host={selectedHost} onBack={() => setView("devices")} />
        ) : activeView === "devices" ? (
          <DevicesView hosts={hosts} onOpenHost={(ip) => setView("devices", ip)} />
        ) : activeView === "events" ? (
          <EventsView report={report} hosts={hosts} />
        ) : (
          <OverviewView
            report={report}
            hosts={hosts}
            onOpenHost={(ip) => setView("devices", ip)}
          />
        )}
      </main>
    </div>
  );
}

export default function QuarantReportViewer() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-white" />}>
      <QuarantReportViewerContent />
    </Suspense>
  );
}
