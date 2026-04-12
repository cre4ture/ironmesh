import { Code } from "@mantine/core";

type JsonBlockProps = {
  value: unknown;
};

export function JsonBlock({ value }: JsonBlockProps) {
  return (
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
        overflowWrap: "normal"
      }}
    >
      {JSON.stringify(value, null, 2)}
    </Code>
  );
}
