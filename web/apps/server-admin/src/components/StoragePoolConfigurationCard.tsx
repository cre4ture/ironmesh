import {
  updateStoragePoolConfig,
  validateStoragePoolConfig,
  type StoragePoolConfig
} from "@ironmesh/api";
import { useMutation } from "@tanstack/react-query";
import { Alert, Button, Card, Code, Group, Stack, Text, Textarea } from "@mantine/core";
import { useEffect, useMemo, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";

type StoragePoolConfigurationCardProps = {
  config: StoragePoolConfig | null;
  configPath: string | null;
  loading: boolean;
};

type Notice =
  | { kind: "validated"; configPath: string }
  | { kind: "saved"; configPath: string };

export function StoragePoolConfigurationCard({
  config,
  configPath,
  loading
}: StoragePoolConfigurationCardProps) {
  const { adminTokenOverride } = useAdminAccess();
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const initialDraft = useMemo(() => (config ? JSON.stringify(config, null, 2) : ""), [config]);
  const [draftText, setDraftText] = useState(initialDraft);
  const [parseError, setParseError] = useState<string | null>(null);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);

  useEffect(() => {
    setDraftText(initialDraft);
    setParseError(null);
    setRequestError(null);
    setNotice(null);
  }, [initialDraft]);

  const validateMutation = useMutation({
    mutationFn: (next: StoragePoolConfig) =>
      validateStoragePoolConfig(next, normalizedAdminTokenOverride || undefined),
    onMutate: () => setRequestError(null),
    onSuccess: (response) => setNotice({ kind: "validated", configPath: response.config_path }),
    onError: (error) => setRequestError(firstErrorMessage(error) ?? "Validation failed.")
  });
  const saveMutation = useMutation({
    mutationFn: (next: StoragePoolConfig) =>
      updateStoragePoolConfig(next, normalizedAdminTokenOverride || undefined),
    onMutate: () => setRequestError(null),
    onSuccess: (response) => setNotice({ kind: "saved", configPath: response.config_path }),
    onError: (error) => setRequestError(firstErrorMessage(error) ?? "Saving the configuration failed.")
  });

  const parseDraft = (): StoragePoolConfig | null => {
    try {
      const parsed = JSON.parse(draftText) as StoragePoolConfig;
      setParseError(null);
      return parsed;
    } catch {
      setParseError("The storage-pool configuration must be valid JSON before it can be checked or saved.");
      return null;
    }
  };
  const validateDraft = () => {
    const parsed = parseDraft();
    if (parsed) {
      void validateMutation.mutateAsync(parsed);
    }
  };
  const saveDraft = () => {
    const parsed = parseDraft();
    if (parsed) {
      void saveMutation.mutateAsync(parsed);
    }
  };
  const mutationPending = validateMutation.isPending || saveMutation.isPending;

  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="md">
        <Stack gap={4}>
          <Text fw={700}>Storage-pool configuration</Text>
          <Text size="sm" c="dimmed" maw={860}>
            Validate and save the node-local JSON configuration here. Saving is atomic, but the running node keeps its
            current storage pool until the service is restarted.
          </Text>
          <Text size="xs" c="dimmed">
            Configuration file: <Code>{configPath ?? "loading…"}</Code>
          </Text>
        </Stack>

        <Alert color="blue" title="Host restart stays outside IronMesh">
          After saving, use Cockpit&apos;s separately authenticated host interface to restart the IronMesh service. IronMesh
          does not execute service restarts, updates, or host reboots itself.
        </Alert>

        {parseError ? (
          <Alert color="red" title="Invalid JSON" withCloseButton onClose={() => setParseError(null)}>
            {parseError}
          </Alert>
        ) : null}
        {requestError ? (
          <Alert color="red" title="Storage-pool configuration rejected">
            {requestError}
          </Alert>
        ) : null}
        {notice?.kind === "validated" ? (
          <Alert color="green" title="Configuration is valid" withCloseButton onClose={() => setNotice(null)}>
            The configuration passed the server-side checks for <Code>{notice.configPath}</Code>. Saving it will still
            require a service restart before the node uses it.
          </Alert>
        ) : null}
        {notice?.kind === "saved" ? (
          <Alert color="yellow" title="Configuration saved — restart required" withCloseButton onClose={() => setNotice(null)}>
            The next IronMesh service start will load <Code>{notice.configPath}</Code>. Use Cockpit separately to perform
            that restart when the node can be taken through a controlled restart.
          </Alert>
        ) : null}

        <Textarea
          label="Storage-pool JSON"
          description="Keep existing path IDs stable. Set a path to draining and restart before using the existing rebalance action."
          autosize
          minRows={14}
          maxRows={28}
          value={draftText}
          onChange={(event) => {
            setParseError(null);
            setRequestError(null);
            setNotice(null);
            setDraftText(event.currentTarget.value);
          }}
          disabled={loading || !config || mutationPending}
          styles={{ input: { fontFamily: "monospace", fontSize: 12 } }}
        />
        <Group justify="flex-end">
          <Button
            variant="subtle"
            onClick={() => {
              setDraftText(initialDraft);
              setParseError(null);
              setRequestError(null);
              setNotice(null);
            }}
            disabled={loading || !config || mutationPending}
          >
            Reset to running configuration
          </Button>
          <Button
            variant="light"
            onClick={validateDraft}
            loading={validateMutation.isPending}
            disabled={loading || !config || !draftText.trim() || saveMutation.isPending}
          >
            Validate configuration
          </Button>
          <Button
            onClick={saveDraft}
            loading={saveMutation.isPending}
            disabled={loading || !config || !draftText.trim() || validateMutation.isPending}
          >
            Save configuration
          </Button>
        </Group>
      </Stack>
    </Card>
  );
}

function firstErrorMessage(error: unknown): string | null {
  return error instanceof Error && error.message.trim() ? error.message : null;
}
