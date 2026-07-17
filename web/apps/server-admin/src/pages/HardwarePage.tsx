import { useQuery } from "@tanstack/react-query";
import {
  getHardwareHealth,
  type HardwareHealthCollectorStatus,
  type HardwareHealthCurrentResponse,
  type HardwareHealthFinding,
  type HardwareNetworkInterface,
  type HardwareStorageDevice
} from "@ironmesh/api";
import { ironmeshPrimaryColor, JsonBlock, StatCard } from "@ironmesh/ui";
import { Alert, Badge, Button, Card, Code, Grid, Group, Loader, Stack, Text } from "@mantine/core";
import { useCallback, type ReactNode } from "react";
import { formatBytes, formatUnixTs } from "../lib/format";
import { useAdminAccess } from "../lib/admin-access";

export function HardwarePage() {
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const hasExplicitAdminAccess =
    Boolean(normalizedAdminTokenOverride) || Boolean(sessionStatus?.authenticated);
  const loginRequired = sessionStatus?.login_required ?? true;
  const canInspectHardware =
    !sessionLoading && (!loginRequired || hasExplicitAdminAccess);

  const hardwareQuery = useQuery({
    queryKey: ["hardware-page", "current", normalizedAdminTokenOverride],
    queryFn: () => getHardwareHealth(normalizedAdminTokenOverride || undefined),
    enabled: canInspectHardware
  });

  const response: HardwareHealthCurrentResponse | null =
    canInspectHardware ? hardwareQuery.data ?? null : null;
  const report = response?.report ?? null;
  const findings = report?.findings ?? [];
  const criticalFindings = findings.filter((finding) => finding.severity === "critical");
  const warningFindings = findings.filter((finding) => finding.severity === "warn");

  const refresh = useCallback(async () => {
    await hardwareQuery.refetch();
  }, [hardwareQuery]);

  return (
    <Stack gap="lg">
      {!canInspectHardware ? (
        <Alert color="yellow" title="Admin access required">
          Sign in with the local admin password or provide an admin token override to inspect
          hardware health reports on this node.
        </Alert>
      ) : null}
      {hardwareQuery.error ? (
        <Alert color="red" title="Failed to load hardware health">
          {hardwareQuery.error instanceof Error ? hardwareQuery.error.message : String(hardwareQuery.error)}
        </Alert>
      ) : null}
      {criticalFindings.length > 0 ? (
        <Alert color="red" title="Critical hardware findings present">
          {criticalFindings.length} critical hardware or runtime finding
          {criticalFindings.length === 1 ? "" : "s"} are currently reported for this node.
        </Alert>
      ) : warningFindings.length > 0 ? (
        <Alert color="yellow" title="Hardware warnings present">
          {warningFindings.length} warning finding{warningFindings.length === 1 ? "" : "s"} are currently reported for this node.
        </Alert>
      ) : report ? (
        <Alert color={ironmeshPrimaryColor} title="No active hardware warnings">
          The latest structured hardware report contains no warning or critical findings.
        </Alert>
      ) : null}

      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={780}>
          This page exposes the node-local hardware health report used for future fleet-level
          robustness analysis. The payload keeps the node identity and exact hardware composition,
          but excludes object keys, paths, raw logs, URLs, and other user data.
        </Text>
        <Button variant="light" onClick={() => void refresh()} loading={hardwareQuery.isFetching}>
          Refresh
        </Button>
      </Group>

      <Grid>
        <Grid.Col span={{ base: 12, md: 4, xl: 3 }}>
          <StatCard
            label="Reporter Node"
            value={report?.reporting_node_id ?? (hardwareQuery.isLoading ? "loading..." : "unknown")}
            hint={`Generated ${formatUnixTs(report?.generated_at_unix ?? response?.last_success_unix)}`}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4, xl: 3 }}>
          <StatCard
            label="Hardware Profile"
            value={shortCode(report?.hardware_profile_id)}
            hint={report?.hardware_profile_id ?? "No hardware profile yet"}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4, xl: 3 }}>
          <StatCard
            label="Storage Devices"
            value={report ? String(report.inventory.storage_devices.length) : hardwareQuery.isLoading ? "loading..." : "0"}
            hint={report ? `${report.inventory.network_interfaces.length} NICs · ${report.inventory.cpu_packages.length} CPU packages` : "Waiting for report"}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4, xl: 3 }}>
          <StatCard
            label="Active Findings"
            value={report ? String(findings.length) : hardwareQuery.isLoading ? "loading..." : "0"}
            hint={report ? `${criticalFindings.length} critical · ${warningFindings.length} warn` : "No report loaded yet"}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
          <StatCard
            label="Current Uptime"
            value={formatDuration(report?.node_lifecycle.uptime_seconds)}
            hint={`Booted ${formatUnixTs(report?.node_lifecycle.booted_at_unix)}`}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
          <StatCard
            label="Observed Uptime"
            value={formatDuration(report?.node_lifecycle.cumulative_observed_uptime_seconds)}
            hint={`Node first seen ${formatUnixTs(report?.node_lifecycle.node_first_seen_at_unix)}`}
          />
        </Grid.Col>
      </Grid>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="sm">
              <Group justify="space-between" align="flex-start">
                <Text fw={700}>Health Notes</Text>
                <Badge variant="light">{report?.health_notes.length ?? 0}</Badge>
              </Group>
              {report ? (
                report.health_notes.length > 0 ? (
                  report.health_notes.map((note) => (
                    <Text key={note} size="sm">
                      • {note}
                    </Text>
                  ))
                ) : (
                  <Text c="dimmed">No generated notes yet.</Text>
                )
              ) : hardwareQuery.isLoading ? (
                <Loader size="sm" />
              ) : (
                <Text c="dimmed">No report loaded yet.</Text>
              )}
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="sm">
              <Text fw={700}>Collector Status</Text>
              {report ? (
                report.collectors.length > 0 ? (
                  report.collectors.map((collector) => (
                    <Card key={collector.collector_id} withBorder radius="md" padding="sm">
                      <Stack gap={4}>
                        <Group justify="space-between" align="center">
                          <Text fw={600}>{collector.label}</Text>
                          <Badge color={collectorStateColor(collector)} variant="light">
                            {collector.state}
                          </Badge>
                        </Group>
                        <Text size="sm" c="dimmed">{collector.detail}</Text>
                        <Text size="sm">
                          Last collected: <Code>{formatUnixTs(collector.last_collected_at_unix)}</Code>
                        </Text>
                        <Text size="sm">
                          Last error code: <Code>{collector.last_error_code ?? "none"}</Code>
                        </Text>
                      </Stack>
                    </Card>
                  ))
                ) : (
                  <Text c="dimmed">No collectors reported yet.</Text>
                )
              ) : hardwareQuery.isLoading ? (
                <Loader size="sm" />
              ) : (
                <Text c="dimmed">No report loaded yet.</Text>
              )}
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Text fw={700}>System Inventory</Text>
          {report ? (
            <>
              <Text size="sm">
                Host OS: <Code>{report.inventory.host_os}</Code> · Kernel:{" "}
                <Code>{report.inventory.kernel_version ?? "unknown"}</Code> · Architecture:{" "}
                <Code>{report.inventory.architecture}</Code>
              </Text>
              <Text size="sm">
                System: <Code>{report.inventory.system.vendor ?? "unknown"}</Code>{" "}
                <Code>{report.inventory.system.product_name ?? "unknown"}</Code>{" "}
                <Code>{report.inventory.system.product_version ?? ""}</Code>
              </Text>
              <Text size="sm">
                Board: <Code>{report.inventory.system.board_vendor ?? "unknown"}</Code>{" "}
                <Code>{report.inventory.system.board_name ?? "unknown"}</Code>{" "}
                <Code>{report.inventory.system.board_version ?? ""}</Code>
              </Text>
              <Text size="sm">
                BIOS: <Code>{report.inventory.system.bios_vendor ?? "unknown"}</Code>{" "}
                <Code>{report.inventory.system.bios_version ?? "unknown"}</Code>{" "}
                <Code>{report.inventory.system.bios_date ?? ""}</Code>
              </Text>
              <Text size="sm">
                Installed memory: <Code>{formatBytes(report.inventory.memory.installed_bytes)}</Code>
              </Text>
            </>
          ) : (
            <Text c="dimmed">No inventory loaded yet.</Text>
          )}
        </Stack>
      </Card>

      <InventorySection
        title="CPU Packages"
        emptyLabel="No CPU package inventory reported yet."
        itemCount={report?.inventory.cpu_packages.length ?? 0}
      >
        {report?.inventory.cpu_packages.map((cpu) => (
          <Card key={cpu.component_instance_id} withBorder radius="md" padding="sm">
            <Stack gap={4}>
              <Group justify="space-between" align="flex-start">
                <Text fw={600}>{cpu.component_ref}</Text>
                <Badge variant="light">{shortCode(cpu.component_instance_id)}</Badge>
              </Group>
              <Text size="sm">
                <Code>{cpu.model_name ?? "unknown model"}</Code>
              </Text>
              <Text size="sm">
                Vendor <Code>{cpu.vendor_id ?? "unknown"}</Code> · {cpu.logical_cpu_count} logical
                {cpu.physical_core_count ? ` · ${cpu.physical_core_count} physical cores` : ""}
              </Text>
              <Text size="sm">
                Family <Code>{cpu.family ?? "?"}</Code> · Model <Code>{cpu.model ?? "?"}</Code> · Stepping{" "}
                <Code>{cpu.stepping ?? "?"}</Code> · Microcode <Code>{cpu.microcode ?? "?"}</Code>
              </Text>
              <Text size="sm">
                First seen <Code>{formatUnixTs(cpu.lifecycle.first_seen_at_unix)}</Code>
              </Text>
            </Stack>
          </Card>
        ))}
      </InventorySection>

      <InventorySection
        title="Storage Devices"
        emptyLabel="No storage devices reported yet."
        itemCount={report?.inventory.storage_devices.length ?? 0}
      >
        {report?.inventory.storage_devices.map((device) => (
          <StorageDeviceCard key={device.component_instance_id} device={device} />
        ))}
      </InventorySection>

      <InventorySection
        title="Network Interfaces"
        emptyLabel="No network interfaces reported yet."
        itemCount={report?.inventory.network_interfaces.length ?? 0}
      >
        {report?.inventory.network_interfaces.map((iface) => (
          <NetworkInterfaceCard key={iface.component_instance_id} iface={iface} />
        ))}
      </InventorySection>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Group justify="space-between" align="flex-start">
            <Text fw={700}>Findings</Text>
            <Badge variant="light">{findings.length}</Badge>
          </Group>
          {report ? (
            findings.length > 0 ? (
              findings.map((finding) => (
                <Card key={`${finding.finding_code}-${finding.last_seen_at_unix}-${finding.component_ref ?? "node"}`} withBorder radius="md" padding="sm">
                  <Stack gap={4}>
                    <Group justify="space-between" align="flex-start">
                      <Group gap="xs">
                        <Badge color={findingSeverityColor(finding)} variant="light">
                          {finding.severity}
                        </Badge>
                        <Badge variant="light">{finding.source}</Badge>
                        <Badge variant="light">{finding.category}</Badge>
                      </Group>
                      <Code>{finding.finding_code}</Code>
                    </Group>
                    <Text size="sm">{finding.summary}</Text>
                    <Text size="sm">
                      Component <Code>{finding.component_ref ?? "node"}</Code> · First seen{" "}
                      <Code>{formatUnixTs(finding.first_seen_at_unix)}</Code> · Last seen{" "}
                      <Code>{formatUnixTs(finding.last_seen_at_unix)}</Code>
                    </Text>
                  </Stack>
                </Card>
              ))
            ) : (
              <Text c="dimmed">No active findings in the latest report.</Text>
            )
          ) : (
            <Text c="dimmed">No report loaded yet.</Text>
          )}
        </Stack>
      </Card>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Text fw={700}>JSON Export</Text>
          <Text c="dimmed" size="sm">
            This is the exact structured payload available to a future central fleet collector.
          </Text>
          <JsonBlock value={response ?? { status: "loading" }} />
        </Stack>
      </Card>
    </Stack>
  );
}

function InventorySection({
  title,
  emptyLabel,
  itemCount,
  children
}: {
  title: string;
  emptyLabel: string;
  itemCount: number;
  children: ReactNode;
}) {
  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="sm">
        <Group justify="space-between" align="flex-start">
          <Text fw={700}>{title}</Text>
          <Badge variant="light">{itemCount}</Badge>
        </Group>
        {itemCount > 0 ? <Grid>{children}</Grid> : <Text c="dimmed">{emptyLabel}</Text>}
      </Stack>
    </Card>
  );
}

function StorageDeviceCard({ device }: { device: HardwareStorageDevice }) {
  return (
    <Grid.Col span={{ base: 12, xl: 6 }}>
      <Card withBorder radius="md" padding="sm" h="100%">
        <Stack gap={4}>
          <Group justify="space-between" align="flex-start">
            <Text fw={600}>{device.component_ref}</Text>
            <Badge variant="light">{shortCode(device.component_instance_id)}</Badge>
          </Group>
          <Text size="sm">
            <Code>{device.vendor ?? "unknown vendor"}</Code> <Code>{device.model ?? "unknown model"}</Code>
          </Text>
          <Text size="sm">
            Firmware <Code>{device.firmware_version ?? "unknown"}</Code> · Capacity{" "}
            <Code>{formatBytes(device.capacity_bytes)}</Code>
          </Text>
          <Text size="sm">
            Interface <Code>{device.interface_type}</Code> · Bus <Code>{device.bus_type ?? "unknown"}</Code> · Driver{" "}
            <Code>{device.driver ?? "unknown"}</Code>
          </Text>
          <Text size="sm">
            PCI <Code>{device.pci_slot ?? "n/a"}</Code> · Rotational <Code>{formatBoolean(device.is_rotational)}</Code>
          </Text>
          <Text size="sm">
            First seen <Code>{formatUnixTs(device.lifecycle.first_seen_at_unix)}</Code>
          </Text>
          {device.smart ? (
            <Text size="sm">
              SMART {formatBoolean(device.smart.smart_passed)} · Power-on{" "}
              <Code>{formatCount(device.smart.power_on_hours, "h")}</Code> · Wear{" "}
              <Code>{formatCount(device.smart.percentage_used, "%")}</Code> · Temp{" "}
              <Code>{formatCount(device.smart.temperature_celsius, "C")}</Code>
            </Text>
          ) : (
            <Text size="sm" c="dimmed">
              No SMART/NVMe lifecycle data reported for this device.
            </Text>
          )}
        </Stack>
      </Card>
    </Grid.Col>
  );
}

function NetworkInterfaceCard({ iface }: { iface: HardwareNetworkInterface }) {
  return (
    <Grid.Col span={{ base: 12, xl: 6 }}>
      <Card withBorder radius="md" padding="sm" h="100%">
        <Stack gap={4}>
          <Group justify="space-between" align="flex-start">
            <Text fw={600}>{iface.component_ref}</Text>
            <Badge variant="light">{shortCode(iface.component_instance_id)}</Badge>
          </Group>
          <Text size="sm">
            Interface <Code>{iface.interface_name}</Code> · Speed <Code>{formatCount(iface.speed_mbps, "Mb/s")}</Code>
          </Text>
          <Text size="sm">
            State <Code>{iface.oper_state ?? "unknown"}</Code> · Carrier <Code>{formatBoolean(iface.carrier)}</Code>
          </Text>
          <Text size="sm">
            Driver <Code>{iface.driver ?? "unknown"}</Code> · PCI <Code>{iface.pci_slot ?? "n/a"}</Code>
          </Text>
          <Text size="sm">
            Vendor <Code>{iface.vendor_id ?? "unknown"}</Code> · Device <Code>{iface.device_id ?? "unknown"}</Code>
          </Text>
        </Stack>
      </Card>
    </Grid.Col>
  );
}

function collectorStateColor(collector: HardwareHealthCollectorStatus): string {
  switch (collector.state) {
    case "ready":
      return ironmeshPrimaryColor;
    case "degraded":
      return "yellow";
    case "unavailable":
      return "red";
  }
}

function findingSeverityColor(finding: HardwareHealthFinding): string {
  switch (finding.severity) {
    case "critical":
      return "red";
    case "warn":
      return "yellow";
    case "info":
      return ironmeshPrimaryColor;
  }
}

function shortCode(value?: string | null): string {
  if (!value) {
    return "unknown";
  }
  return value.slice(0, 12);
}

function formatBoolean(value?: boolean | null): string {
  if (value == null) {
    return "unknown";
  }
  return value ? "yes" : "no";
}

function formatCount(value?: number | null, suffix = ""): string {
  if (value == null || !Number.isFinite(value)) {
    return "unknown";
  }
  return `${value}${suffix}`;
}

function formatDuration(seconds?: number | null): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) {
    return "unknown";
  }
  if (seconds < 60) {
    return `${Math.trunc(seconds)}s`;
  }
  if (seconds < 60 * 60) {
    return `${Math.trunc(seconds / 60)}m`;
  }
  if (seconds < 60 * 60 * 24) {
    return `${Math.trunc(seconds / (60 * 60))}h`;
  }
  return `${Math.trunc(seconds / (60 * 60 * 24))}d`;
}
