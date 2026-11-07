# Changelog

## 1.0.2

- New: on phones a top bar with a ☰ button opens the Home Assistant sidebar (HA hides it on narrow screens and add-on panels have no header of their own).

## 1.0.1

- Fix: on phones and narrow screens (e.g. the Home Assistant mobile app) the panel was ~30,000 px wide because the horizontal country row widened the layout. The page now fits the screen and the rows scroll.

## 1.0.0

First public release.

- WireGuard (NordLynx) gateway for selected LAN devices, with policy routing.
- Server choice from the provider's recommendations, automatic reconnection.
- Kill switch, DNS leak protection (AAAA/HTTPS hidden, DoT blocked), ICMP redirects suppressed.
- TCP MSS clamping for the 1420-byte tunnel MTU.
- Ingress panel: status, public IP, live traffic, world map, favourites, horizontal country/city browser.
- MQTT discovery: VPN switch, country/city selects, status/server/IP/location sensors.
- Options: `kill_switch_on_stop`, `language` (en/it).
- On stop, devices keep internet access without VPN (unless `kill_switch_on_stop`).
