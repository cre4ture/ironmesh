import "@mantine/core/styles.css";
import "./styles/globals.css";

import { MantineProvider } from "@mantine/core";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ironmeshTheme } from "@ironmesh/ui";
import { App } from "./App";

const root = document.getElementById("root");

if (!root) {
  throw new Error("root element is missing");
}

createRoot(root).render(
  <StrictMode>
    <MantineProvider theme={ironmeshTheme}>
      <App />
    </MantineProvider>
  </StrictMode>
);
