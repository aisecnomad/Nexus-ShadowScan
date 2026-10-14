export interface Shipment {
  trackingId: string;
  status: "created" | "in_transit" | "delivered";
  etaIso: string;
}

export async function lookupShipment(trackingId: string): Promise<Shipment> {
  const response = await fetch(
    `https://api.adatum.example/v2/shipments/${encodeURIComponent(trackingId)}`,
  );
  if (!response.ok) {
    throw new Error(`shipment lookup failed: ${response.status}`);
  }
  return (await response.json()) as Shipment;
}
