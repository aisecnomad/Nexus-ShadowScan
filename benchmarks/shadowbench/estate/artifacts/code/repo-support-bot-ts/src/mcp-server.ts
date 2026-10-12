import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { lookupShipment } from "./shipments.js";

const server = new McpServer({ name: "adatum-support-tools", version: "2.1.0" });

server.tool(
  "track_shipment",
  { trackingId: z.string() },
  async ({ trackingId }) => {
    const shipment = await lookupShipment(trackingId);
    return { content: [{ type: "text", text: JSON.stringify(shipment) }] };
  },
);

export async function serve(): Promise<void> {
  await server.connect(new StdioServerTransport());
}
