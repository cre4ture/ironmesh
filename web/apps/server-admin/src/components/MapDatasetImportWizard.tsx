import {
  Alert,
  Anchor,
  Button,
  Code,
  Group,
  NumberInput,
  Radio,
  Select,
  Stack,
  Stepper,
  Text,
  Textarea
} from "@mantine/core";
import { type ReactNode } from "react";

const MAP_IMPORT_WIZARD_STEPS = ["Import type", "Source", "Destination", "Review"];

export type MapImportProfile = "natural-earth-physical" | "remote-mbtiles";

export type MapDatasetImportWizardTarget = {
  key: string;
  variantId: string;
  asset: "raster" | "vector";
  label: string;
  manifestKey: string;
  provider: {
    label?: string;
    homepageUrl?: string;
    acquisitionHint: string;
  };
};

type MapDatasetImportWizardProps = {
  profile: MapImportProfile | null;
  step: number;
  source: string;
  partSizeGiB: number;
  selectedTargetKey: string | null;
  targets: MapDatasetImportWizardTarget[];
  selectedTarget: MapDatasetImportWizardTarget | null;
  naturalEarthTarget: MapDatasetImportWizardTarget | null;
  mapConfigurationLoading: boolean;
  controlsLocked: boolean;
  canStartImport: boolean;
  startingImport: boolean;
  onProfileChange: (profile: MapImportProfile) => void;
  onSourceChange: (source: string) => void;
  onPartSizeChange: (partSizeGiB: number) => void;
  onTargetChange: (targetKey: string | null) => void;
  onBack: () => void;
  onContinue: () => void;
  onStart: () => void;
};

export function MapDatasetImportWizard({
  profile,
  step,
  source,
  partSizeGiB,
  selectedTargetKey,
  targets,
  selectedTarget,
  naturalEarthTarget,
  mapConfigurationLoading,
  controlsLocked,
  canStartImport,
  startingImport,
  onProfileChange,
  onSourceChange,
  onPartSizeChange,
  onTargetChange,
  onBack,
  onContinue,
  onStart
}: MapDatasetImportWizardProps) {
  const selectedWizardTarget = profile === "natural-earth-physical" ? naturalEarthTarget : selectedTarget;
  const canContinue =
    (step === 0 && profile !== null) ||
    (step === 1 && (profile === "natural-earth-physical" || source.trim().length > 0)) ||
    (step === 2 && selectedWizardTarget !== null);

  return (
    <>
      <Stepper active={step} allowNextStepsSelect={false}>
        {MAP_IMPORT_WIZARD_STEPS.map((label) => (
          <Stepper.Step key={label} label={label} />
        ))}
      </Stepper>

      {step === 0 ? (
        <MapTypeStep
          profile={profile}
          controlsLocked={controlsLocked}
          onProfileChange={onProfileChange}
        />
      ) : null}
      {step === 1 ? (
        <MapSourceStep
          profile={profile}
          source={source}
          controlsLocked={controlsLocked}
          onSourceChange={onSourceChange}
        />
      ) : null}
      {step === 2 ? (
        <MapDestinationStep
          profile={profile}
          targets={targets}
          selectedTargetKey={selectedTargetKey}
          selectedTarget={selectedTarget}
          naturalEarthTarget={naturalEarthTarget}
          mapConfigurationLoading={mapConfigurationLoading}
          partSizeGiB={partSizeGiB}
          controlsLocked={controlsLocked}
          onTargetChange={onTargetChange}
          onPartSizeChange={onPartSizeChange}
        />
      ) : null}
      {step === 3 && profile ? (
        <MapReviewStep
          profile={profile}
          source={source}
          target={selectedWizardTarget}
          partSizeGiB={partSizeGiB}
        />
      ) : null}

      <Group justify="space-between">
        <Button variant="default" onClick={onBack} disabled={step === 0 || controlsLocked}>
          Back
        </Button>
        {step < MAP_IMPORT_WIZARD_STEPS.length - 1 ? (
          <Button onClick={onContinue} disabled={!canContinue || controlsLocked}>
            Continue
          </Button>
        ) : (
          <Button loading={startingImport} disabled={!canStartImport || controlsLocked} onClick={onStart}>
            Start background import
          </Button>
        )}
      </Group>
    </>
  );
}

function MapTypeStep({
  profile,
  controlsLocked,
  onProfileChange
}: Pick<MapDatasetImportWizardProps, "profile" | "controlsLocked" | "onProfileChange">) {
  return (
    <Radio.Group
      label="Which map would you like to import?"
      description="Choose a map profile rather than a file format. More profiles can be added without changing this workflow."
      value={profile ?? ""}
      onChange={(value) => onProfileChange(value as MapImportProfile)}
    >
      <Stack gap="sm" mt="xs">
        <Radio
          value="natural-earth-physical"
          label="Natural Earth physical world map"
          description="Download the official 10m physical source data and create the standard globe raster automatically."
          disabled={controlsLocked}
        />
        <Radio
          value="remote-mbtiles"
          label="An existing MBTiles package"
          description="Download a compatible MBTiles file from an HTTP URL and publish it to one configured map artifact."
          disabled={controlsLocked}
        />
      </Stack>
      <Alert color="blue" variant="light" mt="sm" title="Natural Earth source data">
        Natural Earth publishes its source data in the public domain. The physical world-map profile
        converts the official 10m data automatically.{" "}
        <Anchor href="https://www.naturalearthdata.com/" target="_blank" rel="noreferrer">
          Open Natural Earth
        </Anchor>
      </Alert>
    </Radio.Group>
  );
}

function MapSourceStep({
  profile,
  source,
  controlsLocked,
  onSourceChange
}: Pick<
  MapDatasetImportWizardProps,
  "profile" | "source" | "controlsLocked" | "onSourceChange"
>) {
  if (profile === "natural-earth-physical") {
    return (
      <Alert color="blue" variant="light" title="Official Natural Earth source">
        The server downloads the fixed Natural Earth 10m physical archive, then renders land, ocean,
        lakes, rivers, and coastlines. No URL or file needs to be supplied. GDAL and unzip must be
        installed on this node.
      </Alert>
    );
  }

  return (
    <Textarea
      label="MBTiles URL or pasted CLI command"
      description="The source URL is persisted server-side for resumable retries and restart-safe continuation, but the admin UI only shows a redacted display form afterward."
      placeholder="wget -c https://maps.example.org/natural-earth-globe.mbtiles"
      minRows={3}
      autosize
      value={source}
      onChange={(event) => onSourceChange(event.currentTarget.value)}
      disabled={controlsLocked}
    />
  );
}

function MapDestinationStep({
  profile,
  targets,
  selectedTargetKey,
  selectedTarget,
  naturalEarthTarget,
  mapConfigurationLoading,
  partSizeGiB,
  controlsLocked,
  onTargetChange,
  onPartSizeChange
}: Pick<
  MapDatasetImportWizardProps,
  | "profile"
  | "targets"
  | "selectedTargetKey"
  | "selectedTarget"
  | "naturalEarthTarget"
  | "mapConfigurationLoading"
  | "partSizeGiB"
  | "controlsLocked"
  | "onTargetChange"
  | "onPartSizeChange"
>) {
  if (profile === "natural-earth-physical") {
    return naturalEarthTarget ? (
      <Alert color="blue" variant="light" title="Configured Natural Earth destination">
        The generated raster will replace <Code>{naturalEarthTarget.label}</Code> at
        <Code> {naturalEarthTarget.manifestKey} </Code>. This target is fixed so the globe map always
        receives the expected projection and style.
      </Alert>
    ) : (
      <Alert color="red" title="Natural Earth destination is not configured">
        Add a raster artifact for the <Code>natural-earth-globe</Code> variant before starting this
        profile.
      </Alert>
    );
  }

  return (
    <Stack gap="sm">
      <Select
        label="Map variant artifact"
        description="Disabled variants can be imported first and made visible later in the map variant configuration."
        placeholder={
          mapConfigurationLoading ? "Loading configured map artifacts…" : "No map artifact configured"
        }
        value={selectedTargetKey}
        data={targets.map((target) => ({
          value: target.key,
          label: `${target.label} — ${target.asset}`
        }))}
        onChange={onTargetChange}
        disabled={controlsLocked || targets.length === 0}
        searchable
        nothingFoundMessage="No configured map artifact"
      />
      {selectedTarget ? <TargetProviderHint target={selectedTarget} /> : null}
      <NumberInput
        label="Part size"
        description="Each finalized part object keeps its own BerryKeep object key under sys/maps/."
        value={partSizeGiB}
        min={1}
        max={64}
        step={1}
        suffix=" GiB"
        allowDecimal={false}
        onChange={(value) =>
          onPartSizeChange(typeof value === "number" && Number.isFinite(value) ? value : 10)
        }
        w={220}
        disabled={controlsLocked}
      />
    </Stack>
  );
}

function TargetProviderHint({ target }: { target: MapDatasetImportWizardTarget }) {
  return (
    <>
      <Text size="xs" c="dimmed">
        Target manifest: <Code>{target.manifestKey}</Code>
      </Text>
      <Alert color="blue" variant="light" title="Find matching map data">
        <Text size="sm">
          {target.provider.acquisitionHint}{" "}
          {target.provider.homepageUrl && target.provider.label ? (
            <Anchor href={target.provider.homepageUrl} target="_blank" rel="noreferrer">
              Open {target.provider.label}
            </Anchor>
          ) : null}
        </Text>
      </Alert>
    </>
  );
}

function MapReviewStep({
  profile,
  source,
  target,
  partSizeGiB
}: {
  profile: MapImportProfile;
  source: string;
  target: MapDatasetImportWizardTarget | null;
  partSizeGiB: number;
}) {
  return (
    <Stack gap="sm">
      <Alert color="blue" variant="light" title="Review before starting the background job">
        <Stack gap={4}>
          <WizardDetail label="Map profile">
            <Text size="sm">
              {profile === "natural-earth-physical"
                ? "Natural Earth physical world map"
                : "Existing MBTiles package"}
            </Text>
          </WizardDetail>
          <WizardDetail label="Source">
            <Text size="sm">
              {profile === "natural-earth-physical"
                ? "Official Natural Earth 10m physical archive"
                : source.trim()}
            </Text>
          </WizardDetail>
          {target ? (
            <WizardDetail label="Destination">
              <Text size="sm">
                {target.label} — {target.asset}
              </Text>
              <Code>{target.manifestKey}</Code>
            </WizardDetail>
          ) : null}
          {profile === "remote-mbtiles" ? (
            <WizardDetail label="Part size">
              <Text size="sm">{partSizeGiB} GiB</Text>
            </WizardDetail>
          ) : null}
        </Stack>
      </Alert>
      <Text size="sm" c="dimmed">
        Starting the job returns immediately. Progress and any actionable error stay visible below
        while the server downloads, validates, and atomically publishes the map.
      </Text>
    </Stack>
  );
}

function WizardDetail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <Text size="sm" c="dimmed">
        {label}
      </Text>
      {children}
    </div>
  );
}
