"""Upload a compiled rule program through ZHA (runs inside the Home Assistant container).
usage: rules_zha.py <ieee> info | erase | load <file.bpf>
Needs the h2-zigbee quirk (attributes rules_control/rules_data/rules_info/rules_fault)."""
import asyncio, aiohttp, json, os, sys, time
# HA_URL / HA_TOKEN in the environment select another Home Assistant than the local one.
CL, MFG = 0xFCC0, 0x115F
CONTROL, DATA, INFO, FAULT = 0xFFC0, 0xFFC1, 0xFFC2, 0xFFC3
RESULTS = {0: 'ok', 1: 'nothing to commit', 2: 'incomplete', 3: 'refused by the verifier', 4: 'storage error', 5: 'checksum mismatch'}

def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc

async def main():
    ieee, mode = sys.argv[1], sys.argv[2]
    tok = os.environ.get('HA_TOKEN') or open('/config/tools/token').read().strip()
    url = os.environ.get('HA_URL', 'http://127.0.0.1:8123')
    async with aiohttp.ClientSession() as s, s.ws_connect(url + '/api/websocket') as ws:
        await ws.receive_json(); await ws.send_json({'type': 'auth', 'access_token': tok}); await ws.receive_json()
        n = 0
        async def call(msg):
            nonlocal n
            n += 1; msg['id'] = n
            await ws.send_json(msg)
            while True:
                r = await ws.receive_json()
                if r.get('id') == n and r.get('type') == 'result':
                    return r
        base = {'ieee': ieee, 'endpoint_id': 1, 'cluster_id': CL, 'cluster_type': 'in', 'manufacturer': MFG}
        async def read(attr):
            r = await call({'type': 'zha/devices/clusters/attributes/value', 'attribute': attr, **base})
            return int(r['result']) if r.get('success') and r['result'] not in (None, 'None') else None
        async def write(attr, value):
            r = await call({'type': 'call_service', 'domain': 'zha', 'service': 'set_zigbee_cluster_attribute',
                            'service_data': {'attribute': attr, 'value': value, **base}})
            return r.get('success', False)
        async def show():
            c, i, f = await read(CONTROL), await read(INFO), await read(FAULT)
            if None in (c, i, f):
                sys.exit('could not read the rule attributes')
            flags = c >> 24
            print('program: %s' % ('%d bytes, checksum %04x' % (i & 0xFFFF, i >> 16) if i else 'none'))
            print('state:   %s%s%s' % ('running' if flags & 1 else 'not running',
                                       ', upload in progress' if flags & 2 else '', ', safe mode' if flags & 4 else ''))
            print('last upload: %s (value %d)' % (RESULTS.get((c >> 16) & 0xFF, '?'), c & 0xFFFF))
            print('faults: %d, last code %d at instruction %d' % ((f >> 16) & 0xFF, f >> 24, f & 0xFFFF))
            return c, i
        if mode == 'info':
            await show()
        elif mode == 'erase':
            print('erase:', 'ok' if await write(CONTROL, 3 << 24) else 'FAILED'); await show()
        else:
            blob = open(sys.argv[3], 'rb').read(); t0 = time.time()
            if not await write(CONTROL, (1 << 24) | len(blob)):
                sys.exit('begin refused')
            for off in range(0, len(blob), 48):
                if not await write(DATA, (bytes([off & 0xFF, off >> 8]) + blob[off:off + 48]).hex()):
                    sys.exit('data write failed at offset %d' % off)
            c = await read(CONTROL)
            if c is None or (c & 0xFFFF) != len(blob):
                sys.exit('device has %s of %d bytes' % (c and c & 0xFFFF, len(blob)))
            ok = await write(CONTROL, (2 << 24) | crc16(blob))
            print('%d bytes in %.1f s through ZHA: %s' % (len(blob), time.time() - t0, 'commit sent' if ok else 'commit FAILED'))
            c, i = await show()
            sys.exit(0 if i == ((crc16(blob) << 16) | len(blob)) and ((c >> 16) & 0xFF) == 0 else 1)
asyncio.run(main())
