"use client";

import {
  Fragment,
  Suspense,
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useState,
} from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { RefreshCw, Search } from "lucide-react";

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

type ExternalDestinationRow = {
  key: string;
  destination: string;
  port: string;
  protocol: string;
  sourceIp: string;
  sourceCount: number;
  observedCount: number;
  firstSeen?: string;
  lastSeen?: string;
  relatedSeverity?: string;
  relatedSignal: string;
  relatedOwasp: string;
};

type ViewName = "overview" | "devices" | "events";
type ViewerMeta = {
  demo_mode?: boolean;
  events_path?: string;
  report_path?: string;
  flows_path?: string;
  inventory_path?: string;
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "";
const AUTO_REFRESH_INTERVAL_MS = 3000;

const DEBUG_EVENT_TYPES = new Set([
  "I6_DEBUG",
  "DEVICE_DEBUG",
  "PAYLOAD_DEBUG",
]);

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

function formatReportDateTime(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

function formatCompactDateTime(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  const month = date.getMonth() + 1;
  const day = date.getDate();
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");

  return `${month}/${day} ${hours}:${minutes}`;
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

function formatWindowLabel(start?: string, end?: string): string {
  if (!start || !end) return "-";
  return `${formatTime(start)} 〜 ${formatTime(end)}`;
}

function formatReportWindowLabel(start?: string, end?: string): string {
  if (!start || !end) return "-";
  return `${formatReportDateTime(start)} 〜 ${formatReportDateTime(end)}`;
}

function endpoint(ip?: string, port?: number): string {
  if (!ip) return "-";
  return port ? `${ip}:${port}` : ip;
}

function baseName(path?: string): string {
  const value = (path || "").trim();
  if (!value) return "";
  const parts = value.split(/[\\/]/);
  return parts[parts.length - 1] || value;
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
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
    new Set(
      values.filter((value): value is number => typeof value === "number")
    )
  ).sort((a, b) => a - b);
}

function joinLimited(values: string[], limit = 3): string {
  if (values.length === 0) return "-";
  if (values.length <= limit) return values.join(", ");
  return `${values.slice(0, limit).join(", ")} +${values.length - limit}`;
}

function normalizeDestination(flow: FlowRecord): string {
  return (
    flow.observed_destination || flow.sni || flow.host || flow.dst_ip || "-"
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
  if (
    octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) {
    return false;
  }
  if (octets[0] === 10) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  if (octets[0] === 192 && octets[1] === 168) return true;
  return false;
}

function isDeviceCandidateIP(ip?: string): boolean {
  const value = (ip || "").trim();
  if (!value) return false;
  return isPrivateIPv4(value);
}

function isLocalHost(host: HostRow): boolean {
  return isPrivateIPv4(host.ip);
}

function nonDebugEvents(events: Event[]): Event[] {
  return events.filter((event) => !isDebugEvent(event));
}

function warningOrHigherEvents(events: Event[]): Event[] {
  return events.filter(
    (event) => severityRank(event.severity) >= severityRank("WARNING")
  );
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
  const tags = uniqueStrings([
    ...(event.owasp_tags || []),
    ...parseRuleCategory(event.rule_id || event.type),
  ]);
  return tags;
}

function eventIdentityKey(event: Event): string {
  return [
    event.ts || "",
    event.rule_id || event.type || "",
    event.flow_key || "",
    event.device_key || "",
    event.src_ip || "",
    `${event.src_port || ""}`,
    event.dst_ip || "",
    `${event.dst_port || ""}`,
  ].join("|");
}

function flowIdentityKey(flow: FlowRecord): string {
  return [
    flow.ts || "",
    flow.flow_key || "",
    flow.src_ip || "",
    `${flow.src_port || ""}`,
    flow.dst_ip || "",
    `${flow.dst_port || ""}`,
    flow.protocol || "",
    flow.app_protocol || "",
  ].join("|");
}

function deviceMatchesEvent(ip: string, event: Event): boolean {
  return (
    event.device_key === ip || event.src_ip === ip || event.dst_ip === ip
  );
}

function deviceMatchesFlow(ip: string, flow: FlowRecord): boolean {
  return (
    flow.src_ip === ip ||
    flow.dst_ip === ip ||
    (flow.flow_key || "").includes(ip)
  );
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
    ...host.ports
      .slice(0, 4)
      .map((port) => `Port ${port} traffic was observed.`),
    ...host.protocols
      .slice(0, 3)
      .map((protocol) => `${protocol} communication was observed.`),
  ];
  return reasons.length > 0
    ? reasons
    : [
        "Passive observations are limited; candidate classification remains provisional.",
      ];
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
    host.categoryCandidate =
      device.category_candidate || host.categoryCandidate;
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
    host.ports = uniqueNumbers([
      ...host.ports,
      ...(device.observed_ports || []),
    ]);
    host.hosts = uniqueStrings([
      ...host.hosts,
      ...(device.observed_hosts || []),
    ]);
    host.sni = uniqueStrings([...host.sni, ...(device.observed_sni || [])]);
    host.firstSeen = device.first_seen || host.firstSeen;
    host.lastSeen = device.last_seen || host.lastSeen;
  });

  events.forEach((event) => {
    uniqueStrings([
      event.device_key,
      event.src_ip,
      isDeviceCandidateIP(event.dst_ip) ? event.dst_ip : undefined,
    ]).forEach((ip) => {
      const host = ensureHost(ip);
      if (!host.labelCandidate) {
        host.labelCandidate = event.device_label || "";
      }
    });
  });

  flows.forEach((flow) => {
    uniqueStrings([
      flow.src_ip,
      isDeviceCandidateIP(flow.dst_ip) ? flow.dst_ip : undefined,
    ]).forEach((ip) => {
      const host = ensureHost(ip);
      if (!host.labelCandidate) {
        host.labelCandidate = flow.device_label || flow.device_category || "";
      }
      if (!host.categoryCandidate) {
        host.categoryCandidate = flow.device_category || "";
      }
    });
  });

  const hosts = Array.from(byIP.values()).map((host) => {
    const eventSeen = new Set<string>();
    const matchedEvents = events.filter((event) => {
      if (!deviceMatchesEvent(host.ip, event)) return false;
      const key = eventIdentityKey(event);
      if (eventSeen.has(key)) return false;
      eventSeen.add(key);
      return true;
    });

    const flowSeen = new Set<string>();
    const matchedFlows = flows.filter((flow) => {
      if (!deviceMatchesFlow(host.ip, flow)) return false;
      const key = flowIdentityKey(flow);
      if (flowSeen.has(key)) return false;
      flowSeen.add(key);
      return true;
    });

    const hostNonDebugEvents = nonDebugEvents(matchedEvents);
    const hostVisibleEvents = visibleEvents(matchedEvents);
    const eventOWASPSet = uniqueStrings(
      hostNonDebugEvents.flatMap((event) => eventOWASP(event))
    );
    const destinationCounts = new Map<string, number>();
    matchedFlows.forEach((flow) => {
      const destination = normalizeDestination(flow);
      destinationCounts.set(
        destination,
        (destinationCounts.get(destination) || 0) + 1
      );
    });
    const topDestination =
      Array.from(destinationCounts.entries()).sort((a, b) => {
        if (a[1] === b[1]) return a[0].localeCompare(b[0]);
        return b[1] - a[1];
      })[0]?.[0] || "-";

    const externalDestinationCount = uniqueStrings(
      matchedFlows
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
      risk: topSeverity(hostVisibleEvents, host.inventory),
      signals: hostVisibleEvents.length,
      owasp: inventoryOWASP || eventOWASPSet,
      topDestination,
      externalDestinationCount,
      firstSeen:
        host.firstSeen ||
        matchedEvents.slice().sort((a, b) => a.ts.localeCompare(b.ts))[0]?.ts,
      lastSeen:
        host.lastSeen ||
        matchedEvents.slice().sort((a, b) => b.ts.localeCompare(a.ts))[0]?.ts,
      macAddress: "-",
      events: matchedEvents.slice().sort((a, b) => b.ts.localeCompare(a.ts)),
      flows: matchedFlows.slice().sort((a, b) => b.ts.localeCompare(a.ts)),
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
    CRITICAL: "border-[#d92d20] bg-[#fff1f1] text-[#b42318]",
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
    <section className="rounded-[4px] border border-[#d9e0ea] bg-white shadow-[0_1px_2px_rgba(15,23,42,0.04)]">
      <div className="px-6 pt-5">
        <h2 className="text-[19px] font-semibold tracking-[-0.02em] text-[#10203b]">
          {title}
        </h2>
        {description ? (
          <p className="mt-1 text-[13px] leading-6 text-[#64748b]">
            {description}
          </p>
        ) : null}
      </div>
      <div className="px-6 pb-5 pt-4">{children}</div>
    </section>
  );
}

function SummaryLine({ children }: { children: React.ReactNode }) {
  return (
    <div className="border border-[#d7dee8] bg-[#fbfcfe] px-4 py-3 text-sm leading-6 text-[#334155]">
      {children}
    </div>
  );
}

function MetricCard({
  label,
  value,
  helper,
  accent = false,
}: {
  label: string;
  value: string | number;
  helper?: string;
  accent?: boolean;
}) {
  return (
    <div className="flex min-w-0 flex-col items-center justify-center px-6 py-6 text-center">
      <div
        className={cn(
          "text-[14px] font-semibold text-[#334155]",
          accent && "text-[#f97316]"
        )}
      >
        {label}
      </div>
      <div
        className={cn(
          "mt-5 font-mono text-[54px] font-semibold leading-none tracking-[-0.04em]",
          accent ? "text-[#f97316]" : "text-[#10203b]"
        )}
      >
        {value}
      </div>
      {helper ? (
        <div className="mt-3 text-[14px] text-[#334155]">{helper}</div>
      ) : null}
    </div>
  );
}

const RULE_LABELS: Record<string, string> = {
  I7_HTTP_PLAINTEXT: "平文HTTP通信",
  I8_UNREGISTERED_DEVICE_ACTIVE: "未登録端末",
  I8_NEW_DEVICE_OBSERVED: "新規端末",
  I4_WEAK_UPDATE_VISIBILITY: "更新確認通信",
  INSECURE_HTTP: "平文HTTP通信",
  INSECURE_HTTP_TOKEN: "URL内トークン",
};

const CATEGORY_LABELS: Record<string, string> = {
  I4: "更新機構",
  I7: "通信の保護",
  I8: "端末管理",
};

function displayRuleLabel(rule?: string): string {
  const token = (rule || "").trim();
  if (!token) return "未分類";
  return RULE_LABELS[token] || token;
}

function displayCategoryLabel(category?: string): string {
  const token = (category || "").trim();
  if (!token) return "-";
  return CATEGORY_LABELS[token] || token;
}

function categoryForRule(rule?: string): string {
  return parseRuleCategory(rule)[0] || "-";
}

function percent(count: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((count / total) * 100);
}

function InlineBar({ value }: { value: number }) {
  return (
    <div className="h-2 w-16 rounded-full bg-[#e7ecf3]">
      <div
        className="h-2 rounded-full bg-[#102b52]"
        style={{ width: `${Math.max(8, Math.min(100, value))}%` }}
      />
    </div>
  );
}

function severityTextClass(severity?: string): string {
  const value = (severity || "").toUpperCase();
  if (value === "CRITICAL" || value === "HIGH") return "text-[#ff2f1a]";
  if (value === "WARNING") return "text-[#f79009]";
  if (value === "LOW") return "text-[#2563eb]";
  return "text-[#667085]";
}

function severityDotClass(severity?: string): string {
  const value = (severity || "").toUpperCase();
  if (value === "CRITICAL" || value === "HIGH") return "bg-[#ff2f1a]";
  if (value === "WARNING") return "bg-[#f79009]";
  if (value === "LOW") return "bg-[#3b82f6]";
  return "bg-[#98a2b3]";
}

function summaryForRule(rule?: string): string {
  const token = (rule || "").toUpperCase();
  switch (token) {
    case "I7_HTTP_PLAINTEXT":
      return "HTTP（暗号化なし）の通信を観測";
    case "I8_UNREGISTERED_DEVICE_ACTIVE":
      return "端末一覧に存在しない端末の通信を観測";
    case "I4_WEAK_UPDATE_VISIBILITY":
      return "平文HTTPによる更新確認通信を観測";
    case "I2_INSECURE_SERVICE":
      return "Telnet / 23番ポート通信を観測";
    default:
      return displayRuleLabel(rule);
  }
}

function hostTopReason(host: HostRow): string {
  const topEvent = visibleEvents(host.events)
    .slice()
    .sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        b.ts.localeCompare(a.ts)
    )[0];
  return topEvent ? displayRuleLabel(topEvent.rule_id || topEvent.type) : "-";
}

function buildExternalDestinationRows(
  flows: FlowRecord[],
  events: Event[]
): ExternalDestinationRow[] {
  const grouped = new Map<string, ExternalDestinationRow>();
  const sourceSets = new Map<string, Set<string>>();

  flows.forEach((flow) => {
    const destination = normalizeDestination(flow);
    const isExternal =
      flow.direction === "external" || !isPrivateIPv4(destination);
    if (!destination || destination === "-" || !isExternal) return;

    const protocol = (flow.app_protocol || flow.protocol || "-").toUpperCase();
    const port = `${flow.dst_port || "-"}`;
    const key = `${destination}|${port}|${protocol}`;
    const existing = grouped.get(key);

    if (existing) {
      existing.observedCount += 1;
      if (!existing.firstSeen || flow.ts < existing.firstSeen)
        existing.firstSeen = flow.ts;
      if (!existing.lastSeen || flow.ts > existing.lastSeen)
        existing.lastSeen = flow.ts;
    } else {
      grouped.set(key, {
        key,
        destination,
        port,
        protocol,
        sourceIp: flow.src_ip || "-",
        sourceCount: 0,
        observedCount: 1,
        firstSeen: flow.ts,
        lastSeen: flow.ts,
        relatedSeverity: undefined,
        relatedSignal: "-",
        relatedOwasp: "-",
      });
    }

    const sources = sourceSets.get(key) || new Set<string>();
    if (flow.src_ip) sources.add(flow.src_ip);
    sourceSets.set(key, sources);
  });

  const visible = visibleEvents(events);
  grouped.forEach((row, key) => {
    row.sourceCount = sourceSets.get(key)?.size || 0;
    const matching = visible
      .filter(
        (event) =>
          (event.dst_ip || "-") === row.destination &&
          `${event.dst_port || "-"}` === row.port
      )
      .sort(
        (a, b) =>
          severityRank(b.severity) - severityRank(a.severity) ||
          b.ts.localeCompare(a.ts)
      );
    const topEvent = matching[0];
    row.relatedSeverity = topEvent?.severity;
    row.relatedSignal = topEvent
      ? displayRuleLabel(topEvent.rule_id || topEvent.type)
      : "-";
    row.relatedOwasp = topEvent ? formatOWASP(eventOWASP(topEvent)) : "-";
  });

  return Array.from(grouped.values()).sort((a, b) => {
    if (severityRank(a.relatedSeverity) !== severityRank(b.relatedSeverity)) {
      return severityRank(b.relatedSeverity) - severityRank(a.relatedSeverity);
    }
    if (a.observedCount !== b.observedCount) {
      return b.observedCount - a.observedCount;
    }
    return a.destination.localeCompare(b.destination);
  });
}

function compactSeverityLabel(severity?: string): string {
  const value = (severity || "").toUpperCase();
  if (value === "CRITICAL") return "Critical";
  if (value === "HIGH") return "High";
  if (value === "MEDIUM") return "Medium";
  if (value === "WARNING") return "Warning";
  if (value === "LOW") return "Low";
  if (value === "INFO") return "Info";
  return severity || "-";
}

function displayInferredValue(value?: string): string {
  const token = (value || "").trim();
  if (!token) return "-";
  if (token === "不明候補") return "不明";
  if (token.endsWith("候補")) return token.slice(0, -2);
  return token;
}

function reportSeverityClass(severity?: string): string {
  const value = (severity || "").toUpperCase();
  if (value === "CRITICAL" || value === "HIGH") {
    return "border-[#ff6b57] text-[#ff3b1f]";
  }
  if (value === "WARNING" || value === "MEDIUM") {
    return "border-[#f59e0b] text-[#d97706]";
  }
  if (value === "LOW") {
    return "border-[#a8b7cf] text-[#5e7598]";
  }
  return "border-[#cbd5e1] text-[#64748b]";
}

function JsonDisclosure({ label, value }: { label: string; value: unknown }) {
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
  flows,
  onOpenEvents,
  onOpenDevices,
  meta,
}: {
  report: Report | null;
  hosts: HostRow[];
  onOpenHost: (ip: string) => void;
  flows: FlowRecord[];
  onOpenEvents: () => void;
  onOpenDevices: () => void;
  meta: ViewerMeta | null;
}) {
  const events = report?.events || [];
  const visible = visibleEvents(events);
  const warningEvents = visible.filter(
    (event) => (event.severity || "").toUpperCase() === "WARNING"
  );
  const highEvents = visible.filter(
    (event) => (event.severity || "").toUpperCase() === "HIGH"
  );
  const criticalEvents = visible.filter(
    (event) => (event.severity || "").toUpperCase() === "CRITICAL"
  );
  const localHosts = hosts.filter((host) => isLocalHost(host));
  const externalHosts = hosts.filter((host) => !isLocalHost(host));
  const sourceHosts = uniqueStrings(flows.map((flow) => flow.src_ip));
  const protocols = uniqueStrings(
    flows.map((flow) => flow.app_protocol || flow.protocol).filter(Boolean)
  );
  const packetCount = flows.reduce(
    (sum, flow) => sum + (flow.packet_count || 0),
    0
  );
  const bytesTotal = flows.reduce(
    (sum, flow) => sum + (flow.bytes_in || 0) + (flow.bytes_out || 0),
    0
  );
  const sniCount = flows.filter(
    (flow) => (flow.sni || "").trim() !== ""
  ).length;
  const hostCount = flows.filter(
    (flow) => (flow.host || "").trim() !== ""
  ).length;
  const uniqueExternal = uniqueStrings(
    flows
      .filter((flow) => flow.direction === "external")
      .map(
        (flow) =>
          flow.observed_destination || flow.host || flow.sni || flow.dst_ip
      )
  );
  const totalFlowCount = uniqueStrings(
    flows.map((flow) => flow.flow_key)
  ).length;
  const topHosts = localHosts
    .slice()
    .sort(
      (a, b) =>
        b.signals - a.signals ||
        severityRank(b.risk) - severityRank(a.risk) ||
        a.ip.localeCompare(b.ip)
    )
    .slice(0, 3);
  const signalRows = topKV(
    countByKey(visible.map((event) => event.rule_id || event.type)),
    4
  ).map((item) => {
    const sample = visible.find(
      (event) => (event.rule_id || event.type) === item.key
    );
    return {
      ...item,
      label: displayRuleLabel(item.key),
      summary:
        sample?.observed_fact || sample?.message || summaryForRule(item.key),
    };
  });
  const recentEvents = visible
    .slice()
    .sort((a, b) => b.ts.localeCompare(a.ts))
    .slice(0, 5);
  const sourceList = [
    baseName(
      meta?.report_path || meta?.events_path || report?.source || "events.jsonl"
    ),
    baseName(meta?.flows_path || "flows.jsonl"),
    baseName(meta?.inventory_path || "device_inventory.json"),
  ].filter(Boolean);
  const summaryMetrics = [
    { label: "観測端末数", value: `${sourceHosts.length}`, suffix: "台" },
    { label: "外部通信先", value: `${uniqueExternal.length}`, suffix: "件" },
    {
      label: "Warning",
      value: `${warningEvents.length}`,
      suffix: "件",
      accent: warningEvents.length > 0,
    },
    {
      label: "High / Critical",
      value: `${highEvents.length + criticalEvents.length}`,
      suffix: "件",
      accent: highEvents.length + criticalEvents.length > 0,
    },
    { label: "検出イベント総数", value: `${visible.length}`, suffix: "件" },
  ];
  const observedFacts = [
    ["プロトコル", protocols.join(", ") || "-"],
    ["パケット数", packetCount.toLocaleString("ja-JP")],
    ["通信量", formatBytes(bytesTotal)],
    ["SNI数", `${sniCount} 件`],
    ["HTTP Host数", `${hostCount} 件`],
    ["外部通信先", `${uniqueExternal.length} 件`],
    ["フロー数", `${totalFlowCount.toLocaleString("ja-JP")} 件`],
  ];

  return (
    <div className="space-y-7 text-[#24324b]">
      <section className="border-b border-[#dbe3ef] pb-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-[24px] font-medium tracking-[-0.02em] text-[#1f2a44]">
              概要
            </h1>
          </div>

          <Button
            variant="outline"
            className="h-9 rounded-none border-[#b8c6db] bg-white px-4 text-[13px] font-semibold text-[#1f2a44] shadow-none hover:bg-[#f8fbff]"
            onClick={() => {
              const payload = {
                report,
                flows,
                inventory: hosts.map((host) => host.inventory).filter(Boolean),
                exported_at: new Date().toISOString(),
              };
              const blob = new Blob([JSON.stringify(payload, null, 2)], {
                type: "application/json",
              });
              const url = URL.createObjectURL(blob);
              const link = document.createElement("a");
              link.href = url;
              link.download = "quarant-report-export.json";
              link.click();
              URL.revokeObjectURL(url);
            }}
          >
            レポートをエクスポート（JSON）
          </Button>
        </div>
      </section>

      <section className="border-b border-[#e4eaf3] pb-5">
        <dl className="mt-3 grid gap-y-2 text-[14px] leading-7 text-[#2e3b55] md:grid-cols-[140px_1fr]">
          <dt className="text-[#6d7f9c]">観測期間</dt>
          <dd className="font-mono text-[14px] text-[#22324d]">
            {formatReportWindowLabel(
              report?.window?.start,
              report?.window?.end
            )}
          </dd>
          <dt className="text-[#6d7f9c]">データソース</dt>
          <dd className="font-mono text-[14px] text-[#22324d]">
            {sourceList.join(" / ") || "-"}
          </dd>
        </dl>
      </section>

      <section className="border-b border-[#e4eaf3] pb-5">
        <div className="grid gap-y-4 md:grid-cols-5 md:divide-x md:divide-[#e4eaf3]">
          {summaryMetrics.map((metric) => (
            <div key={metric.label} className="pr-4">
              <div className="text-[13px] text-[#6d7f9c]">{metric.label}</div>
              <div className="mt-1 flex items-end gap-0.5">
                <span
                  className={cn(
                    "text-[18px] font-medium text-[#1f2a44]",
                    metric.accent && "text-[#e56b1f]"
                  )}
                >
                  {metric.value}
                </span>
                <span className="pb-0.5 text-[13px] text-[#6d7f9c]">
                  {metric.suffix}
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="border-b border-[#e4eaf3] pb-6">
        <div className="border-b border-[#cfd9e6] pb-2 text-[18px] font-semibold text-[#1f2a44]">
          観測された通信
        </div>
        <div className="mt-4 divide-y divide-[#edf2f8]">
          {observedFacts.map(([label, value]) => (
            <div
              key={label}
              className="grid grid-cols-[180px_1fr] gap-6 py-2.5 text-[14px]"
            >
              <div className="text-[#6d7f9c]">{label}</div>
              <div className="font-mono text-[#22324d]">{value}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="grid gap-8 border-b border-[#e4eaf3] pb-7 xl:grid-cols-2">
        <div>
          <div className="border-b border-[#cfd9e6] pb-2 text-[18px] font-semibold text-[#1f2a44]">
            要確認端末
          </div>
          <div className="mt-4 overflow-x-auto">
            <div className="grid min-w-[580px] grid-cols-[128px_1.1fr_72px_120px_1.2fr] gap-4 border-b border-[#cfd9e6] pb-2 text-[13px] text-[#6d7f9c]">
              <div>IPアドレス</div>
              <div>推定カテゴリ</div>
              <div className="text-right">件数</div>
              <div>最高Severity</div>
              <div>主な理由</div>
            </div>
            <div className="divide-y divide-[#edf2f8]">
              {topHosts.map((host) => (
                <button
                  key={host.ip}
                  onClick={() => onOpenHost(host.ip)}
                  className="grid min-w-[580px] grid-cols-[128px_1.1fr_72px_120px_1.2fr] gap-4 py-3 text-left text-[14px] hover:bg-[#fafcff]"
                >
                  <div className="font-mono text-[#31415c] underline underline-offset-2">
                    {host.ip}
                  </div>
                  <div>{humanizeCategoryCandidate(host.categoryCandidate)}</div>
                  <div className="text-right font-mono">{host.signals}</div>
                  <div>
                    <span
                      className={cn(
                        "inline-flex min-w-[64px] justify-center border px-2 py-0.5 text-[12px] font-medium",
                        reportSeverityClass(host.risk)
                      )}
                    >
                      {compactSeverityLabel(host.risk)}
                    </span>
                  </div>
                  <div className="truncate text-[#4d5f7c]">
                    {hostTopReason(host)}
                  </div>
                </button>
              ))}
            </div>
          </div>
          <button
            onClick={onOpenDevices}
            className="mt-4 text-[14px] text-[#4d5f7c] underline underline-offset-2"
          >
            → すべての端末を見る
          </button>
        </div>

        <div>
          <div className="border-b border-[#cfd9e6] pb-2 text-[18px] font-semibold text-[#1f2a44]">
            主なリスクシグナル
          </div>
          <div className="mt-4 overflow-x-auto">
            <div className="grid min-w-[560px] grid-cols-[1.1fr_1.5fr_52px] gap-4 border-b border-[#cfd9e6] pb-2 text-[13px] text-[#6d7f9c]">
              <div>シグナル</div>
              <div>概要</div>
              <div className="text-right">件数</div>
            </div>
            <div className="divide-y divide-[#edf2f8]">
              {signalRows.map((item) => (
                <div
                  key={item.key}
                  className="grid min-w-[560px] grid-cols-[1.1fr_1.5fr_52px] gap-4 py-3 text-[14px]"
                >
                  <div className="text-[#24324b]">{item.label}</div>
                  <div className="text-[#4d5f7c]">{item.summary}</div>
                  <div className="text-right font-mono text-[#24324b]">
                    {item.count}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <button
            onClick={onOpenEvents}
            className="mt-4 text-[14px] text-[#4d5f7c] underline underline-offset-2"
          >
            → すべてのリスクシグナルを見る
          </button>
        </div>
      </section>

      <section className="border-b border-[#e4eaf3] pb-7">
        <div className="flex items-center justify-between border-b border-[#cfd9e6] pb-2">
          <div className="text-[18px] font-semibold text-[#1f2a44]">
            最近のイベント
          </div>
          <div className="text-[13px] text-[#6d7f9c]">最新5件</div>
        </div>
        <div className="mt-4 overflow-x-auto">
          <div className="grid min-w-[780px] grid-cols-[170px_92px_150px_170px_minmax(0,1fr)] gap-4 border-b border-[#cfd9e6] pb-2 text-[13px] text-[#6d7f9c]">
            <div>時刻</div>
            <div>Severity</div>
            <div>プロトコル / ポート</div>
            <div>ルール</div>
            <div>内容</div>
          </div>
          <div className="divide-y divide-[#edf2f8]">
            {recentEvents.map((event, index) => {
              const flow = flows.find(
                (item) => item.flow_key === event.flow_key
              );
              const protocolLabel = flow
                ? `${(
                    flow.app_protocol ||
                    flow.protocol ||
                    "-"
                  ).toUpperCase()} / ${event.dst_port || flow.dst_port || "-"}`
                : `- / ${event.dst_port || "-"}`;
              return (
                <div
                  key={`${event.ts}-${index}`}
                  className="grid min-w-[780px] grid-cols-[170px_92px_150px_170px_minmax(0,1fr)] gap-4 py-3 text-[14px]"
                >
                  <div className="font-mono text-[#24324b]">
                    {formatCompactDateTime(event.ts)}
                  </div>
                  <div>
                    <span
                      className={cn(
                        "inline-flex min-w-[64px] justify-center border px-2 py-0.5 text-[12px] font-medium",
                        reportSeverityClass(event.severity)
                      )}
                    >
                      {compactSeverityLabel(event.severity)}
                    </span>
                  </div>
                  <div className="font-mono text-[#24324b]">
                    {protocolLabel}
                  </div>
                  <div className="min-w-0 break-words font-mono text-[#5e7598]">
                    {event.rule_id || event.type || "-"}
                  </div>
                  <div className="min-w-0 break-words whitespace-normal text-[#4d5f7c]">
                    {event.observed_fact || event.message || "-"}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
        <button
          onClick={onOpenEvents}
          className="mt-4 text-[14px] text-[#4d5f7c] underline underline-offset-2"
        >
          → すべてのイベントを見る
        </button>
      </section>
    </div>
  );
}

function DevicesView({
  report,
  hosts,
  flows,
  meta,
  onOpenHost,
}: {
  report: Report | null;
  hosts: HostRow[];
  flows: FlowRecord[];
  meta: ViewerMeta | null;
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
  const localHosts = filteredHosts.filter((host) => isLocalHost(host));
  const destinationRows = buildExternalDestinationRows(
    flows,
    report?.events || []
  );
  const filteredDestinations = destinationRows.filter((row) => {
    const haystack = [
      row.destination,
      row.port,
      row.protocol,
      row.sourceIp,
      row.relatedSignal,
      row.relatedOwasp,
    ]
      .join(" ")
      .toLowerCase();

    if (riskFilter !== "all" && (row.relatedSeverity || "") !== riskFilter) {
      return false;
    }
    if (
      owaspFilter !== "all" &&
      row.relatedOwasp !== "-" &&
      !row.relatedOwasp.includes(owaspFilter)
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
  const sourceName = baseName(meta?.inventory_path || "device_inventory.json");

  return (
    <div className="space-y-7 text-[#24324b]">
      <section className="border-b border-[#dbe3ef] pb-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-[24px] font-medium tracking-[-0.02em] text-[#1f2a44]">
              端末一覧
            </h1>
          </div>

          <Button
            variant="outline"
            className="h-9 rounded-none border-[#b8c6db] bg-white px-4 text-[13px] font-semibold text-[#1f2a44] shadow-none hover:bg-[#f8fbff]"
            onClick={() => {
              const payload = {
                report,
                hosts,
                flows,
                exported_at: new Date().toISOString(),
              };
              const blob = new Blob([JSON.stringify(payload, null, 2)], {
                type: "application/json",
              });
              const url = URL.createObjectURL(blob);
              const link = document.createElement("a");
              link.href = url;
              link.download = "quarant-device-report.json";
              link.click();
              URL.revokeObjectURL(url);
            }}
          >
            レポートをエクスポート（JSON）
          </Button>
        </div>
      </section>

      <section className="border-b border-[#e4eaf3] pb-4">
        <div className="grid gap-4 xl:grid-cols-[minmax(0,2.2fr)_220px_220px_auto]">
          <div className="grid grid-cols-[44px_minmax(0,1fr)] items-center gap-2">
            <div className="text-[18px] font-semibold text-[#5c7094]">検索</div>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[#93a3bb]" />
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search"
                className="h-10 rounded-none border-[#cfd9e6] bg-white pl-10 text-[14px] placeholder:text-[#94a3b8]"
              />
            </div>
          </div>

          <div className="grid grid-cols-[84px_minmax(0,1fr)] items-center gap-2">
            <div className="text-[18px] font-semibold text-[#5c7094]">
              重要度
            </div>
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="h-10 rounded-none border-[#cfd9e6] bg-white text-[14px]">
                <SelectValue placeholder="" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">すべて</SelectItem>
                {uniqueStrings(hosts.map((host) => host.risk)).map((value) => (
                  <SelectItem key={value} value={value}>
                    {compactSeverityLabel(value)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-[72px_minmax(0,1fr)] items-center gap-2">
            <div className="text-[18px] font-semibold text-[#5c7094]">
              OWASP
            </div>
            <Select value={owaspFilter} onValueChange={setOwaspFilter}>
              <SelectTrigger className="h-10 rounded-none border-[#cfd9e6] bg-white text-[14px]">
                <SelectValue placeholder="" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">すべて</SelectItem>
                {owaspOptions.map((value) => (
                  <SelectItem key={value} value={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center justify-end">
            <div className="inline-flex border border-[#cfd9e6]">
              <a
                href="#lan-devices"
                className="border-r border-[#cfd9e6] bg-[#f8fbff] px-4 py-2 text-[13px] font-semibold text-[#1f2a44]"
              >
                LAN内端末
              </a>
              <a
                href="#external-destinations"
                className="bg-white px-4 py-2 text-[13px] font-semibold text-[#1f2a44]"
              >
                外部通信先
              </a>
            </div>
          </div>
        </div>
      </section>

      <section id="lan-devices" className="border-b border-[#e4eaf3] pb-7">
        <div className="flex items-center justify-between border-b border-[#cfd9e6] pb-2">
          <div className="text-[18px] font-semibold text-[#1f2a44]">
            LAN内端末一覧
          </div>
          <div className="text-[13px] text-[#6d7f9c]">
            {localHosts.length} 件
          </div>
        </div>
        <div className="mt-4 overflow-x-auto">
          <div className="grid min-w-[900px] grid-cols-[120px_140px_120px_84px_220px_128px_84px] gap-4 border-b border-[#cfd9e6] pb-2 text-[13px] text-[#6d7f9c]">
            <div>IPアドレス</div>
            <div>推定カテゴリ</div>
            <div>最高リスク</div>
            <div className="text-right">シグナル数</div>
            <div>主な通信</div>
            <div>最終観測</div>
            <div>詳細</div>
          </div>
          <div className="divide-y divide-[#edf2f8]">
            {localHosts.map((host) => (
              <div
                key={host.ip}
                className="grid min-w-[900px] grid-cols-[120px_140px_120px_84px_220px_128px_84px] gap-4 py-3 text-[14px]"
              >
                <div className="font-mono text-[#24324b]">{host.ip}</div>
                <div className="break-words text-[#4d5f7c]">
                  {displayInferredValue(host.categoryCandidate)}
                </div>
                <div>
                  <span
                    className={cn(
                      "inline-flex min-w-[74px] justify-center border px-2 py-0.5 text-[12px] font-medium",
                      reportSeverityClass(host.risk)
                    )}
                  >
                    {compactSeverityLabel(host.risk)}
                  </span>
                </div>
                <div className="text-right font-mono text-[#24324b]">
                  {host.signals}
                </div>
                <div
                  className="truncate text-[#4d5f7c]"
                  title={`${joinLimited(host.protocols, 2)} / ${
                    host.topDestination
                  }`}
                >
                  {joinLimited(host.protocols, 2)} / {host.topDestination}
                </div>
                <div className="font-mono text-[#5e7598]">
                  {formatCompactDateTime(host.lastSeen)}
                </div>
                <button
                  onClick={() => onOpenHost(host.ip)}
                  className="text-left text-[#4d5f7c] underline underline-offset-2"
                >
                  詳細
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section
        id="external-destinations"
        className="border-b border-[#e4eaf3] pb-7"
      >
        <div className="flex items-center justify-between border-b border-[#cfd9e6] pb-2">
          <div className="text-[18px] font-semibold text-[#1f2a44]">
            外部通信先一覧
          </div>
          <div className="text-[13px] text-[#6d7f9c]">
            {filteredDestinations.length} 件
          </div>
        </div>
        <div className="mt-4 overflow-x-auto">
          <div className="grid min-w-[1220px] grid-cols-[170px_64px_90px_118px_80px_120px_120px_92px_1fr] gap-4 border-b border-[#cfd9e6] pb-2 text-[13px] text-[#6d7f9c]">
            <div>宛先</div>
            <div>ポート</div>
            <div>プロトコル</div>
            <div>通信元端末</div>
            <div className="text-right">観測回数</div>
            <div>初回観測</div>
            <div>最終観測</div>
            <div>関連シグナル</div>
            <div />
          </div>
          <div className="divide-y divide-[#edf2f8]">
            {filteredDestinations.slice(0, 5).map((row) => (
              <div
                key={row.key}
                className="grid min-w-[1220px] grid-cols-[170px_64px_90px_118px_80px_120px_120px_92px_1fr] gap-4 py-3 text-[14px]"
              >
                <div className="font-mono text-[#24324b]">
                  {row.destination}
                </div>
                <div className="font-mono text-[#24324b]">{row.port}</div>
                <div className="text-[#4d5f7c]">{row.protocol}</div>
                <div className="font-mono text-[#5e7598] underline underline-offset-2">
                  {row.sourceIp}
                </div>
                <div className="text-right font-mono text-[#24324b]">
                  {row.observedCount}
                </div>
                <div className="font-mono text-[#5e7598]">
                  {formatCompactDateTime(row.firstSeen)}
                </div>
                <div className="font-mono text-[#5e7598]">
                  {formatCompactDateTime(row.lastSeen)}
                </div>
                <div>
                  {row.relatedSeverity ? (
                    <span
                      className={cn(
                        "inline-flex min-w-[74px] justify-center border px-2 py-0.5 text-[12px] font-medium",
                        reportSeverityClass(row.relatedSeverity)
                      )}
                    >
                      {compactSeverityLabel(row.relatedSeverity)}
                    </span>
                  ) : (
                    <span className="text-[#94a3b8]">-</span>
                  )}
                </div>
                <div className="text-[#4d5f7c]">{row.relatedSignal}</div>
              </div>
            ))}
          </div>
        </div>
      </section>
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
        {hosts.length > 0 ? (
          hosts.map((host) => (
            <TableRow key={host.ip}>
              <TableCell className="font-mono text-xs">{host.ip}</TableCell>
              <TableCell>{host.labelCandidate}</TableCell>
              <TableCell>{host.categoryCandidate}</TableCell>
              <TableCell>{host.vendorCandidate}</TableCell>
              <TableCell>
                <SeverityBadge severity={host.risk} />
              </TableCell>
              <TableCell>{host.signals}</TableCell>
              <TableCell>{joinLimited(host.owasp, 3)}</TableCell>
              <TableCell>{joinLimited(host.protocols, 3)}</TableCell>
              <TableCell
                className="max-w-[180px] truncate"
                title={host.topDestination}
              >
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
          ))
        ) : (
          <TableRow>
            <TableCell
              colSpan={11}
              className="text-center text-muted-foreground"
            >
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
  onOpenEvents,
}: {
  host: HostRow;
  onBack: () => void;
  onOpenEvents: () => void;
}) {
  const nonDebugEvents = visibleEvents(host.events);
  const relatedEvents = nonDebugEvents
    .slice()
    .sort((a, b) => b.ts.localeCompare(a.ts));
  const topDestinations = uniqueStrings(
    host.flows
      .filter((flow) => flow.direction === "external")
      .map((flow) => normalizeDestination(flow))
  );
  const totalBytes = host.flows.reduce(
    (sum, flow) => sum + (flow.bytes_in || 0) + (flow.bytes_out || 0),
    0
  );
  const externalRows = buildExternalDestinationRows(
    host.flows,
    host.events
  ).slice(0, 3);
  const deviceTitle = displayInferredValue(
    host.labelCandidate || host.categoryCandidate || "端末"
  );
  const topOwasp = host.owasp[0] || "-";
  const topReason = hostTopReason(host);

  return (
    <div className="space-y-7 text-[#24324b]">
      <section className="border-b border-[#dbe3ef] pb-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <button
              onClick={onBack}
              className="text-[14px] text-[#5e7598] underline underline-offset-2"
            >
              ← 端末一覧へ戻る
            </button>
            <div className="mt-4 flex items-baseline gap-1">
              <h1 className="font-mono text-[24px] font-medium tracking-[-0.02em] text-[#1f2a44]">
                {host.ip}
              </h1>
              <span className="text-[18px] text-[#5e7598]">{deviceTitle}</span>
            </div>
            <p className="mt-1 text-[14px] text-[#6d7f9c]">
              Device Detail Report
            </p>
          </div>

          <div className="flex items-center gap-3">
            <span
              className={cn(
                "inline-flex min-w-[74px] justify-center border px-2 py-0.5 text-[12px] font-medium",
                reportSeverityClass(host.risk)
              )}
            >
              {compactSeverityLabel(host.risk)}
            </span>
            <Button
              variant="outline"
              className="h-9 rounded-none border-[#b8c6db] bg-white px-4 text-[13px] font-semibold text-[#1f2a44] shadow-none hover:bg-[#f8fbff]"
              onClick={() => {
                const payload = {
                  host,
                  events: relatedEvents,
                  external_destinations: externalRows,
                  exported_at: new Date().toISOString(),
                };
                const blob = new Blob([JSON.stringify(payload, null, 2)], {
                  type: "application/json",
                });
                const url = URL.createObjectURL(blob);
                const link = document.createElement("a");
                link.href = url;
                link.download = `${host.ip}-device-detail.json`;
                link.click();
                URL.revokeObjectURL(url);
              }}
            >
              レポートをエクスポート（JSON）
            </Button>
          </div>
        </div>
      </section>

      <section className="border-b border-[#e4eaf3] pb-6">
        <div className="border-b border-[#cfd9e6] pb-2 text-[18px] font-semibold text-[#1f2a44]">
          観測情報（Observed）
        </div>
        <div className="mt-4 divide-y divide-[#edf2f8] text-[14px]">
          {[
            ["IPアドレス", host.ip],
            [
              "MACアドレス",
              host.macAddress === "-" ? "−（観測範囲外）" : host.macAddress,
            ],
            ["初回観測", formatReportDateTime(host.firstSeen)],
            ["最終観測", formatReportDateTime(host.lastSeen)],
            ["観測プロトコル", joinLimited(host.protocols, 6)],
            ["フロー数", `${host.flows.length} 件`],
            ["観測バイト数", formatBytes(totalBytes)],
            ["主な通信先", topDestinations[0] || host.topDestination],
          ].map(([label, value]) => (
            <div
              key={label}
              className="grid grid-cols-[220px_minmax(0,1fr)] gap-4 py-2.5"
            >
              <div className="text-[#6d7f9c]">{label}</div>
              <div
                className={cn(
                  "min-w-0 break-words text-[#2e3b55]",
                  label.includes("IP") || label.includes("観測")
                    ? "font-mono"
                    : ""
                )}
              >
                {value}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="border-b border-[#e4eaf3] pb-6">
        <div className="border-b border-[#cfd9e6] pb-2 text-[18px] font-semibold text-[#1f2a44]">
          推定情報（Inferred）
        </div>
        <div className="mt-4 divide-y divide-[#edf2f8] text-[14px]">
          {[
            ["推定カテゴリ", displayInferredValue(host.categoryCandidate)],
            ["推定ベンダ", displayInferredValue(host.vendorCandidate)],
            ["推定ファミリ", displayInferredValue(host.familyCandidate)],
            ["Confidence", host.confidence],
            ["主なOWASPカテゴリ", topOwasp],
            ["主な理由", topReason],
          ].map(([label, value]) => (
            <div
              key={label}
              className="grid grid-cols-[220px_minmax(0,1fr)] gap-4 py-2.5"
            >
              <div className="text-[#6d7f9c]">{label}</div>
              <div className="min-w-0 break-words text-[#2e3b55]">{value}</div>
            </div>
          ))}
        </div>
        <div className="mt-3 text-[13px] leading-6 text-[#6d7f9c]">
          ※ 端末カテゴリやベンダは、通信上の観測情報に基づく推定です。
        </div>
      </section>

      <section className="border-b border-[#e4eaf3] pb-7">
        <div className="flex items-center justify-between border-b border-[#cfd9e6] pb-2">
          <div className="text-[18px] font-semibold text-[#1f2a44]">
            この端末の外部通信先
          </div>
          <div className="text-[13px] text-[#6d7f9c]">
            {externalRows.length} 件
          </div>
        </div>
        <div className="mt-4 overflow-x-auto">
          <div className="grid min-w-[980px] grid-cols-[170px_70px_100px_90px_120px_120px_100px_1fr] gap-4 border-b border-[#cfd9e6] pb-2 text-[13px] text-[#6d7f9c]">
            <div>宛先</div>
            <div>ポート</div>
            <div>プロトコル</div>
            <div className="text-right">観測回数</div>
            <div>最終観測</div>
            <div />
            <div>関連シグナル</div>
            <div />
          </div>
          <div className="divide-y divide-[#edf2f8]">
            {externalRows.map((row) => (
              <div
                key={row.key}
                className="grid min-w-[980px] grid-cols-[170px_70px_100px_90px_120px_120px_100px_1fr] gap-4 py-3 text-[14px]"
              >
                <div className="font-mono text-[#24324b]">
                  {row.destination}
                </div>
                <div className="font-mono text-[#24324b]">{row.port}</div>
                <div className="text-[#4d5f7c]">{row.protocol}</div>
                <div className="text-right font-mono text-[#24324b]">
                  {row.observedCount}
                </div>
                <div className="font-mono text-[#5e7598]">
                  {formatReportDateTime(row.lastSeen)}
                </div>
                <div />
                <div>
                  {row.relatedSeverity ? (
                    <span
                      className={cn(
                        "inline-flex min-w-[74px] justify-center border px-2 py-0.5 text-[12px] font-medium",
                        reportSeverityClass(row.relatedSeverity)
                      )}
                    >
                      {compactSeverityLabel(row.relatedSeverity)}
                    </span>
                  ) : (
                    <span className="text-[#94a3b8]">-</span>
                  )}
                </div>
                <div className="text-[#4d5f7c]">{row.relatedSignal}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="border-b border-[#e4eaf3] pb-7">
        <div className="flex items-center justify-between border-b border-[#cfd9e6] pb-2">
          <div className="text-[18px] font-semibold text-[#1f2a44]">
            この端末の検出イベント
          </div>
          <div className="text-[13px] text-[#6d7f9c]">
            {relatedEvents.length} 件
          </div>
        </div>
        <div className="mt-4 overflow-x-auto">
          <div className="grid min-w-[1060px] grid-cols-[148px_88px_144px_128px_188px_minmax(280px,1fr)] gap-3 border-b border-[#cfd9e6] pb-2 text-[13px] text-[#6d7f9c]">
            <div>時刻</div>
            <div>Severity</div>
            <div>宛先</div>
            <div>プロトコル / ポート</div>
            <div>ルールID</div>
            <div>観測された事実（要約）</div>
          </div>
          <div className="divide-y divide-[#edf2f8]">
            {relatedEvents.map((event, index) => {
              const flow = host.flows.find(
                (item) => item.flow_key === event.flow_key
              );
              const protocolLabel = `${(
                flow?.app_protocol ||
                flow?.protocol ||
                "-"
              ).toUpperCase()} / ${event.dst_port || flow?.dst_port || "-"}`;
              return (
                <div
                  key={`${event.ts}-${index}`}
                  className="grid min-w-[1060px] grid-cols-[148px_88px_144px_128px_188px_minmax(280px,1fr)] items-start gap-3 py-3 text-[14px]"
                >
                  <div className="font-mono whitespace-nowrap text-[#24324b]">
                    {formatReportDateTime(event.ts)}
                  </div>
                  <div className="pt-0.5">
                    <span
                      className={cn(
                        "inline-flex min-w-[74px] justify-center border px-2 py-0.5 text-[12px] font-medium",
                        reportSeverityClass(event.severity)
                      )}
                    >
                      {compactSeverityLabel(event.severity)}
                    </span>
                  </div>
                  <div className="min-w-0 whitespace-normal break-words font-mono [overflow-wrap:anywhere] text-[#24324b]">
                    {event.dst_ip || "-"}
                  </div>
                  <div className="min-w-0 whitespace-normal break-words font-mono [overflow-wrap:anywhere] text-[#24324b]">
                    {protocolLabel}
                  </div>
                  <div className="min-w-0 whitespace-normal break-words font-mono [overflow-wrap:anywhere] text-[#5e7598]">
                    {event.rule_id || event.type || "-"}
                  </div>
                  <div className="min-w-0 whitespace-normal break-words [overflow-wrap:anywhere] text-[#4d5f7c]">
                    {event.observed_fact || event.message || "-"}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
        <button
          onClick={onOpenEvents}
          className="mt-4 text-[14px] text-[#4d5f7c] underline underline-offset-2"
        >
          → すべての検出イベントを見る
        </button>
      </section>

      <section className="pb-4">
        <div className="text-[18px] font-semibold text-[#1f2a44]">注意</div>
        <div className="mt-3 text-[14px] leading-7 text-[#5e7598]">
          ・ 端末カテゴリやベンダは、通信上の観測情報に基づく推定です。
          <br />・
          本ページは端末内部の状態や実際の侵害を断定するものではありません。
        </div>
      </section>
    </div>
  );
}

function EventDetails({ event }: { event: Event }) {
  return (
    <div className="border-t border-[#edf2f8] bg-[#fbfdff] px-7 py-4">
      <div className="divide-y divide-[#edf2f8] text-[13px]">
        {[
          ["送信元", endpoint(event.src_ip, event.src_port)],
          ["宛先", endpoint(event.dst_ip, event.dst_port)],
          ["Observed Fact", event.observed_fact || "-"],
          ["Evidence", event.evidence || "-"],
          ["Inference", event.inference || "-"],
          ["Limitation", event.limitation || "-"],
        ].map(([label, value]) => (
          <div
            key={label}
            className="grid grid-cols-[180px_minmax(0,1fr)] gap-4 py-2.5"
          >
            <div className="text-[#6d7f9c]">{label}</div>
            <div
              className={cn(
                "min-w-0 whitespace-normal break-words [overflow-wrap:anywhere] text-[#2e3b55]",
                label === "Evidence" && "font-mono"
              )}
            >
              {value}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EventsView({
  report,
  flows,
  meta,
}: {
  report: Report | null;
  flows: FlowRecord[];
  meta: ViewerMeta | null;
}) {
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [protocolFilter, setProtocolFilter] = useState("all");
  const [openRows, setOpenRows] = useState<Record<string, boolean>>({});
  const deferredQuery = useDeferredValue(query);

  const events = report?.events || [];
  const candidateEvents = visibleEvents(events);
  const eventSourceName = baseName(
    meta?.events_path || report?.source || "events.jsonl"
  );
  const protocolOptions = uniqueStrings(
    candidateEvents
      .map((event) => {
        const flow = flows.find((item) => item.flow_key === event.flow_key);
        return (flow?.app_protocol || flow?.protocol || "").toUpperCase();
      })
      .filter(Boolean)
  );

  const filtered = candidateEvents.filter((event) => {
    const flow = flows.find((item) => item.flow_key === event.flow_key);
    const protocol = (flow?.app_protocol || flow?.protocol || "").toUpperCase();
    const haystack = [
      event.rule_id,
      event.type,
      event.message,
      event.evidence,
      event.observed_fact,
      event.src_ip,
      event.dst_ip,
      protocol,
    ]
      .join(" ")
      .toLowerCase();

    if (severityFilter !== "all" && (event.severity || "") !== severityFilter) {
      return false;
    }
    if (protocolFilter !== "all" && protocol !== protocolFilter) {
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
    <div className="space-y-7 text-[#24324b]">
      <section className="border-b border-[#dbe3ef] pb-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="text-[24px] font-medium tracking-[-0.02em] text-[#1f2a44]">
              検出一覧
            </h1>
            <p className="mt-1 text-[14px] text-[#6d7f9c]">
              Detection Events from {eventSourceName}
            </p>
          </div>

          <Button
            variant="outline"
            className="h-9 rounded-none border-[#b8c6db] bg-white px-4 text-[13px] font-semibold text-[#1f2a44] shadow-none hover:bg-[#f8fbff]"
            onClick={() => {
              const payload = {
                report,
                flows,
                exported_at: new Date().toISOString(),
              };
              const blob = new Blob([JSON.stringify(payload, null, 2)], {
                type: "application/json",
              });
              const url = URL.createObjectURL(blob);
              const link = document.createElement("a");
              link.href = url;
              link.download = "quarant-detection-report.json";
              link.click();
              URL.revokeObjectURL(url);
            }}
          >
            レポートをエクスポート（JSON）
          </Button>
        </div>
      </section>

      <section className="border-b border-[#e4eaf3] pb-4">
        <div className="grid gap-4 xl:grid-cols-[minmax(0,2.2fr)_220px_220px]">
          <div className="grid grid-cols-[44px_minmax(0,1fr)] items-center gap-2">
            <div className="text-[18px] font-semibold text-[#5c7094]">検索</div>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[#93a3bb]" />
              <Input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="ルールID / 送信元 / 宛先 / 事実"
                className="h-10 rounded-none border-[#cfd9e6] bg-white pl-10 text-[14px] placeholder:text-[#94a3b8]"
              />
            </div>
          </div>

          <div className="grid grid-cols-[84px_minmax(0,1fr)] items-center gap-2">
            <div className="text-[18px] font-semibold text-[#5c7094]">
              Severity
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="h-10 rounded-none border-[#cfd9e6] bg-white text-[14px]">
                <SelectValue placeholder="" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">すべて</SelectItem>
                {uniqueStrings(
                  candidateEvents.map((event) => event.severity)
                ).map((value) => (
                  <SelectItem key={value} value={value}>
                    {compactSeverityLabel(value)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-[102px_minmax(0,1fr)] items-center gap-2">
            <div className="text-[18px] font-semibold text-[#5c7094]">
              プロトコル
            </div>
            <Select value={protocolFilter} onValueChange={setProtocolFilter}>
              <SelectTrigger className="h-10 rounded-none border-[#cfd9e6] bg-white text-[14px]">
                <SelectValue placeholder="" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">すべて</SelectItem>
                {protocolOptions.map((value) => (
                  <SelectItem key={value} value={value}>
                    {value}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </section>

      <section className="border-b border-[#e4eaf3] pb-7">
        <div className="flex items-center justify-between border-b border-[#cfd9e6] pb-2">
          <div className="text-[18px] font-semibold text-[#1f2a44]">
            検出イベント
          </div>
          <div className="text-[13px] text-[#6d7f9c]">{filtered.length} 件</div>
        </div>

        <div className="mt-4 overflow-x-auto">
          <div className="grid w-full min-w-[720px] grid-cols-[20px_104px_100px_150px_170px_minmax(0,1fr)] gap-4 border-b border-[#cfd9e6] pb-2 text-[13px] text-[#6d7f9c]">
            <div />
            <div>時刻</div>
            <div>Severity</div>
            <div>プロトコル / ポート</div>
            <div>ルールID</div>
            <div />
          </div>

          <div className="divide-y divide-[#edf2f8]">
            {filtered.length > 0 ? (
              filtered.map((event, index) => {
                const rowKey = `${event.ts}-${
                  event.rule_id || event.type
                }-${index}`;
                const isOpen = Boolean(openRows[rowKey]);
                const flow = flows.find(
                  (item) => item.flow_key === event.flow_key
                );
                const protocolLabel = `${(
                  flow?.app_protocol ||
                  flow?.protocol ||
                  "-"
                ).toUpperCase()} / ${event.dst_port || flow?.dst_port || "-"}`;
                return (
                  <Fragment key={rowKey}>
                    <button
                      type="button"
                      className="grid w-full min-w-[720px] grid-cols-[20px_104px_100px_150px_170px_minmax(0,1fr)] gap-4 py-3 text-left text-[14px] hover:bg-[#fafcff]"
                      onClick={() =>
                        setOpenRows((current) => ({
                          ...current,
                          [rowKey]: !current[rowKey],
                        }))
                      }
                    >
                      <div className="pt-1 text-[10px] text-[#93a3bb]">
                        {isOpen ? "▼" : "▶"}
                      </div>
                      <div className="font-mono text-[#24324b]">
                        {formatCompactDateTime(event.ts)}
                      </div>
                      <div>
                        <span
                          className={cn(
                            "inline-flex min-w-[74px] justify-center border px-2 py-0.5 text-[12px] font-medium",
                            reportSeverityClass(event.severity)
                          )}
                        >
                          {compactSeverityLabel(event.severity)}
                        </span>
                      </div>
                      <div className="font-mono text-[#24324b]">
                        {protocolLabel}
                      </div>
                      <div className="font-mono text-[#5e7598]">
                        {event.rule_id || event.type || "-"}
                      </div>
                      <div />
                    </button>
                    {isOpen ? <EventDetails event={event} /> : null}
                  </Fragment>
                );
              })
            ) : (
              <div className="py-6 text-center text-[14px] text-[#6d7f9c]">
                条件に一致する event はありません。
              </div>
            )}
          </div>
        </div>
      </section>
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
  const [viewerMeta, setViewerMeta] = useState<ViewerMeta | null>(null);

  const viewParam = searchParams.get("view");
  const activeView: ViewName =
    viewParam === "devices" || viewParam === "events" ? viewParam : "overview";
  const activeHost = searchParams.get("host");

  const loadData = useEffectEvent(
    async ({
      background = false,
    }: { background?: boolean } = {}): Promise<void> => {
      try {
        setIsRefreshing(true);
        if (!background) {
          setError("");
        }

        const [reportResponse, inventoryResponse, flowsResponse, metaResponse] =
          await Promise.all([
            fetch(`${API_BASE_URL}/api/report`, { cache: "no-store" }),
            fetch(`${API_BASE_URL}/api/inventory`, { cache: "no-store" }),
            fetch(`${API_BASE_URL}/api/flows`, { cache: "no-store" }),
            fetch(`${API_BASE_URL}/api/meta`, { cache: "no-store" }),
          ]);

        if (!reportResponse.ok) {
          throw new Error(`report HTTP ${reportResponse.status}`);
        }

        const [nextReport, nextInventory, nextFlows, nextMeta] =
          await Promise.all([
            reportResponse.json() as Promise<Report>,
            inventoryResponse.ok
              ? (inventoryResponse.json() as Promise<InventoryReport>)
              : Promise.resolve({ devices: [] }),
            flowsResponse.ok
              ? (flowsResponse.json() as Promise<FlowRecord[]>)
              : Promise.resolve([]),
            metaResponse.ok
              ? (metaResponse.json() as Promise<ViewerMeta>)
              : Promise.resolve({}),
          ]);

        setReport(nextReport);
        setInventory(nextInventory);
        setFlows(nextFlows);
        setViewerMeta(nextMeta);
        setStatus("Connected");
        setError("");
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
  );

  useEffect(() => {
    void loadData();
    const intervalId = window.setInterval(() => {
      void loadData({ background: true });
    }, AUTO_REFRESH_INTERVAL_MS);
    return () => window.clearInterval(intervalId);
  }, [loadData]);

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

  const hosts = aggregateHosts(
    report?.events || [],
    inventory?.devices || [],
    flows
  );
  const selectedHost = hosts.find((host) => host.ip === activeHost);
  const navItems: Array<{ key: ViewName; label: string }> = [
    { key: "overview", label: "概要" },
    { key: "devices", label: "端末一覧" },
    { key: "events", label: "検出一覧" },
  ];
  const navActiveView: ViewName = selectedHost ? "devices" : activeView;
  const observationDay = report?.window?.start
    ? formatReportDateTime(report.window.start).slice(0, 10)
    : "-";

  return (
    <div className="min-h-screen bg-white text-[#0f172a]">
      <div className="flex min-h-screen">
        <aside className="sticky top-0 flex h-screen w-[296px] shrink-0 self-start flex-col overflow-y-auto border-r border-[#d7e0ec] bg-[#fbfcff]">
          <div className="border-b border-[#d7e0ec] px-7 pb-6 pt-9">
            <div className="text-[20px] font-semibold tracking-[-0.02em] text-[#1d2740]">
              Quarant
            </div>
            <div className="mt-2 text-[14px] text-[#70819d]">
              Observation Report
            </div>
          </div>

          <nav className="px-4 py-5">
            <div className="space-y-1">
              {navItems.map((item) => {
                const active = navActiveView === item.key;
                return (
                  <button
                    key={item.key}
                    onClick={() => setView(item.key)}
                    className={cn(
                      "flex w-full items-center px-4 py-4 text-left text-[15px] font-semibold text-[#61728f]",
                      active
                        ? "border-l-2 border-[#111827] bg-[#eef3f9] pl-[14px] text-[#111827]"
                        : "border-l-2 border-transparent hover:bg-[#f4f7fb]"
                    )}
                  >
                    {item.label}
                  </button>
                );
              })}
            </div>
          </nav>

          <div className="mt-auto border-t border-[#d7e0ec] px-7 py-7">
            <div className="text-[13px] text-[#70819d]">観測期間</div>
            <div className="mt-1 font-mono text-[14px] text-[#334155]">
              {observationDay}
            </div>
            <div className="mt-7 text-[13px] leading-6 text-[#8a99b2]">
              v0.1.0 / OSS
              <br />
              Passive observation
            </div>
            <div className="mt-5 flex flex-col items-start gap-3">
              {viewerMeta?.demo_mode ? (
                <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[#b54708]">
                  Demo data
                </div>
              ) : null}
            </div>
          </div>
        </aside>

        <main className="min-w-0 flex-1">
          <div className="mx-auto max-w-[1320px] px-12 py-12">
            <div className="mb-6 flex items-center justify-end gap-4 text-[12px] text-[#70819d]">
              <span>Auto refresh: 3s</span>
              {lastUpdated ? (
                <span className="font-mono text-[#5e7598]">
                  {formatReportDateTime(lastUpdated.toISOString())}
                </span>
              ) : null}
              <Button
                variant="outline"
                onClick={() => void loadData()}
                disabled={isRefreshing}
                className="h-8 rounded-none border-[#c8d3e3] bg-white px-3 text-[12px] text-[#334155]"
              >
                <RefreshCw
                  className={cn(
                    "mr-2 size-3.5",
                    isRefreshing && "animate-spin"
                  )}
                />
                Refresh
              </Button>
            </div>

            {error ? (
              <div className="mb-6 border border-[#fda29b] bg-[#fff5f4] px-4 py-3 text-sm text-[#b42318]">
                API 接続に失敗しました: {error}
              </div>
            ) : null}

            {selectedHost ? (
              <HostReportView
                host={selectedHost}
                onBack={() => setView("devices")}
                onOpenEvents={() => setView("events")}
              />
            ) : activeView === "devices" ? (
              <DevicesView
                report={report}
                hosts={hosts}
                flows={flows}
                meta={viewerMeta}
                onOpenHost={(ip) => setView("devices", ip)}
              />
            ) : activeView === "events" ? (
              <EventsView report={report} flows={flows} meta={viewerMeta} />
            ) : (
              <OverviewView
                report={report}
                hosts={hosts}
                flows={flows}
                meta={viewerMeta}
                onOpenHost={(ip) => setView("devices", ip)}
                onOpenDevices={() => setView("devices")}
                onOpenEvents={() => setView("events")}
              />
            )}
          </div>
        </main>
      </div>
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
