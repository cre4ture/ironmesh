import { ActionIcon, Box, Code, Tooltip } from "@mantine/core";
import { useClipboard } from "@mantine/hooks";
import { IconCheck, IconCopy } from "@tabler/icons-react";
import { ironmeshPrimaryColor } from "../../theme/ironmesh-theme";

type JsonBlockProps = {
  value: unknown;
};

export function JsonBlock({ value }: JsonBlockProps) {
  const json = JSON.stringify(value, null, 2);
  const clipboard = useClipboard({ timeout: 1500 });

  return (
    <Box pos="relative">
      <Tooltip label={clipboard.copied ? "Copied" : "Copy JSON"}>
        <ActionIcon
          aria-label="Copy JSON to clipboard"
          color={clipboard.copied ? ironmeshPrimaryColor : "gray"}
          onClick={() => clipboard.copy(json)}
          size="sm"
          style={{
            position: "absolute",
            top: "0.5rem",
            right: "0.5rem",
            zIndex: 1
          }}
          variant="subtle"
        >
          {clipboard.copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
        </ActionIcon>
      </Tooltip>
      <Code
        block
        style={{
          boxSizing: "border-box",
          display: "block",
          width: "100%",
          maxWidth: "100%",
          height: "min(20rem, 60vh)",
          overflowX: "auto",
          overflowY: "scroll",
          scrollbarGutter: "stable",
          whiteSpace: "pre",
          overflowWrap: "normal",
          paddingTop: "2.25rem"
        }}
      >
        {json}
      </Code>
    </Box>
  );
}
