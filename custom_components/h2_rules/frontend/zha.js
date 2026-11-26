// Talking to an H2 switch through ZHA: the same websocket command and action that
// zha/rules_zha.py uses. Needs the h2-zigbee ZHA quirk (it defines these attributes).
// Attribute layout: common/h2_rules.h in the firmware.

const CLUSTER = 0xFCC0, MFG = 0x115F;
export const ATTR = { CONTROL: 0xFFC0, DATA: 0xFFC1, INFO: 0xFFC2, FAULT: 0xFFC3, DROPPED: 0xFFC4, LINK: 0xFFC8, VAR0: 0xFFA0 };
const OP = { BEGIN: 1, COMMIT: 2, ERASE: 3, READ: 5 };
const CHUNK = 48;
export const RESULTS = {
  0: "ok", 1: "nothing to commit", 2: "incomplete", 3: "refused by the checker",
  4: "storage error: the stored copy is lost, the old program runs until the switch restarts",
  5: "checksum mismatch", 6: "no room in the switch's settings store; the old program was kept",
};
export const FAULTS = {
  1: "not a valid program", 2: "an event took too many instructions", 3: "memory access outside the program's data",
  4: "a helper was unknown or refused the call", 5: "calls nested too deep",
};

export function crc16(data) {
  let crc = 0xFFFF;
  for (const b of data) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = crc & 1 ? (crc >>> 1) ^ 0xA001 : crc >>> 1;
  }
  return crc;
}
export const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
export const fromHex = (s) => new Uint8Array((s.match(/../g) || []).map((h) => parseInt(h, 16)));

export class Switch {
  constructor(hass, ieee) { this.hass = hass; this.ieee = ieee; }
  get base() { return { ieee: this.ieee, endpoint_id: 1, cluster_id: CLUSTER, cluster_type: "in", manufacturer: MFG }; }

  // The websocket command answers with the value as text, or null if the read failed.
  async readRaw(attribute) {
    const r = await this.hass.callWS({ type: "zha/devices/clusters/attributes/value", attribute, ...this.base });
    return r === null || r === undefined || r === "None" ? null : String(r);
  }
  async read(attribute) {
    const r = await this.readRaw(attribute);
    if (r === null) return null;
    const n = Number(r);
    return Number.isFinite(n) ? n >>> 0 : null;
  }
  async write(attribute, value) {
    await this.hass.callService("zha", "set_zigbee_cluster_attribute", { attribute, value, ...this.base });
  }

  // { program: {length, crc} | null, running, uploading, safeMode, lastResult, lastValue,
  //   faults: {count, code, at}, dropped, storeBytes, link }
  async status() {
    const [c, i, f, d] = [await this.read(ATTR.CONTROL), await this.read(ATTR.INFO), await this.read(ATTR.FAULT), await this.read(ATTR.DROPPED)];
    if (c === null || i === null) throw new Error("the switch did not answer (is the h2-zigbee ZHA quirk installed, and the switch powered?)");
    const flags = c >>> 24;
    return {
      program: i ? { length: i & 0xFFFF, crc: i >>> 16 } : null,
      running: !!(flags & 1), uploading: !!(flags & 2), safeMode: !!(flags & 4),
      lastResult: (c >>> 16) & 0xFF, lastValue: c & 0xFFFF,
      faults: f === null ? null : { count: (f >>> 16) & 0xFF, code: f >>> 24, at: f & 0xFFFF },
      dropped: d === null ? null : d & 0xFFFF,
      storeBytes: d === null ? null : d >>> 16,
    };
  }

  // Load an image onto the switch. progress(done, total). Resolves to the status afterwards;
  // throws with a readable reason if the switch refused it.
  async upload(image, progress = () => {}) {
    await this.write(ATTR.CONTROL, ((OP.BEGIN << 24) | image.length) >>> 0);
    for (let off = 0; off < image.length; off += CHUNK) {
      const part = image.subarray(off, off + CHUNK);
      await this.write(ATTR.DATA, toHex(Uint8Array.of(off & 0xFF, off >> 8, ...part)));
      progress(Math.min(off + CHUNK, image.length), image.length);
    }
    const c = await this.read(ATTR.CONTROL);
    if (c === null || (c & 0xFFFF) !== image.length || !((c >>> 24) & 2)) {
      throw new Error(`the switch has ${c === null ? "?" : c & 0xFFFF} of ${image.length} bytes; nothing was changed`);
    }
    const crc = crc16(image);
    await this.write(ATTR.CONTROL, ((OP.COMMIT << 24) | crc) >>> 0);
    const st = await this.status();
    if (st.lastResult !== 0 || !st.program || st.program.crc !== crc || st.program.length !== image.length) {
      let why = RESULTS[st.lastResult] || `result ${st.lastResult}`;
      if (st.lastResult === 3) why += ` at instruction ${st.lastValue}`;
      if (st.lastResult === 6) why += ` (it would hold ${st.lastValue} bytes)`;
      if (st.lastResult === 0) why = "the switch still reports a different program";
      const err = new Error(why); err.status = st; throw err;
    }
    return st;
  }

  // Read the installed program back (firmware 0x8B or later).
  async download(progress = () => {}) {
    const st = await this.status();
    if (!st.program) throw new Error("no program is installed on the switch");
    const { length, crc } = st.program;
    const out = new Uint8Array(length);
    let have = 0, stalls = 0;
    await this.write(ATTR.CONTROL, (OP.READ << 24) >>> 0);
    while (have < length) {
      const text = await this.readRaw(ATTR.DATA);
      const part = text && /^([0-9a-f]{2})+$/i.test(text) ? fromHex(text) : new Uint8Array(0);
      if (part.length <= 2 || (part[0] | (part[1] << 8)) !== have) {
        if (++stalls > 20) throw new Error(part.length === 0
          ? "the switch does not hand out its program (firmware before 0x8B, or an older quirk)"
          : `reading stopped at byte ${have}`);
        await this.write(ATTR.CONTROL, ((OP.READ << 24) | have) >>> 0);     // out of step: seek, ask again
        continue;
      }
      out.set(part.subarray(2, 2 + Math.min(part.length - 2, length - have)), have);
      have += part.length - 2;
      progress(Math.min(have, length), length);
    }
    if (crc16(out) !== crc) throw new Error("what was read does not match the switch's checksum; try again");
    return out;
  }

  async erase() { await this.write(ATTR.CONTROL, (OP.ERASE << 24) >>> 0); return this.status(); }
}

// H2 switches known to ZHA: [{ ieee, name, model, available, firmware }]
export async function listSwitches(hass) {
  const devices = await hass.callWS({ type: "zha/devices" });
  return devices
    .filter((d) => d.manufacturer === "h2-zigbee" || /^lumi\.switch\.agl0(09|10|11)$/.test(d.model || ""))
    .map((d) => ({
      ieee: d.ieee, name: d.user_given_name || d.name, model: d.model, available: d.available !== false,
      ours: d.manufacturer === "h2-zigbee", quirk: !!(d.quirk_applied && /h2_zigbee/.test(d.quirk_class || "")),
      area: d.area_id || "",
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}
