import { Code, ScrollArea } from "@mantine/core";

type JsonBlockProps = {
  value: unknown;
};

export function JsonBlock({ value }: JsonBlockProps) {
  return (
    <ScrollArea type="auto" mah={320}>
      <Code block>{JSON.stringify(value, null, 2)}</Code>
    </ScrollArea>
  );
}
