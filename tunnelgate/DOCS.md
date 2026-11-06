# TunnelGate

Route only selected LAN devices (TV, streaming stick, console…) through a WireGuard (NordLynx) tunnel of your NordVPN subscription, and control it from Home Assistant.

> Unofficial project, not affiliated with Nord Security / NordVPN.

## 1. Before starting

- Turn **Protection mode off** on the *Info* tab: the add-on needs to manage routing and firewall rules on the host.
- Optional: install the **Mosquitto broker** add-on to get the MQTT entities (switch, selects, sensors).

## 2. Options

```yaml
token: "your-access-token"     # Nord Account → NordVPN → Manual setup → Generate new token
clients:
  - 192.168.1.118              # devices routed through the VPN
lan_interface: end0            # auto-detected if missing
default_country: US            # used on first start
default_city: ""               # empty = fastest server
kill_switch_on_stop: false     # true = devices offline while the add-on is stopped
language: en                   # en | it (entity names)
```

## 3. Configure each device

Static IPv4 configuration on the device:

- **IP**: the address listed in `clients` (reserve it in your router's DHCP)
- **Prefix**: `24`
- **Gateway**: the IP of this Home Assistant host
- **DNS**: `8.8.8.8`, `8.8.4.4` (IPv4 only)

## 4. Use

- **Sidebar → TunnelGate**: connect/disconnect, choose country and city, favourites, live traffic, map.
- **Entities**: `switch.tunnelgate_vpn`, `select.tunnelgate_country`, `select.tunnelgate_city`, status/server/IP/location sensors.

## Behaviour

| Situation | Devices in `clients` |
|---|---|
| VPN on, tunnel up | go out through the VPN |
| VPN on, tunnel down | blocked (kill switch) until it reconnects |
| VPN off | go out through your router, without VPN |
| Add-on stopped | without VPN (or blocked with `kill_switch_on_stop: true`) |
| Home Assistant host off | no internet → set the device back to DHCP |

## Troubleshooting

- **`ip_forward is 0`** → Protection mode is still on.
- **No handshake / no server answered** → try another location or *Refresh servers*.
- **Token invalid (401/403)** → generate a new token.
- **Streaming app still sees your real country** → make sure the device has no IPv6 DNS server (static IPv4 config, IPv4 DNS).

---

## Italiano

1. Disattiva **Modalità protezione** nella scheda *Info*.
2. Opzioni: `token` (Nord Account → NordVPN → Configurazione manuale → Genera nuovo token), `clients` (IP dei dispositivi), `language: it`.
3. Sul dispositivo: IP statico come in `clients`, prefisso `24`, **gateway = IP di Home Assistant**, DNS `8.8.8.8` / `8.8.4.4`.
4. Usa il pannello **TunnelGate** nella barra laterale o le entità MQTT.

Se Home Assistant è spento il dispositivo resta senza internet: rimetti la sua rete in automatico (DHCP).
