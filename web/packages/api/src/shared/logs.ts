export type ServerLogEntry = {
  captured_at_unix: number;
  line: string;
};

export type LogsResponse = {
  entries: ServerLogEntry[];
};
