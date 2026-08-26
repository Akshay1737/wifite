# WPA3 Support & Limitations

Wifite's WPA3 support works as follows:

* **Detection**: Targets advertising `WPA3` / `SAE` are detected during scanning
  and shown in purple (`WPA3-S`). Wifite distinguishes between:
  * **Transition mode** (`WPA2 WPA3` + `PSK SAE`): the AP accepts both protocols.
  * **WPA3-only** (`WPA3` + `SAE`): no WPA2 fallback.
* **Transition-mode targets**: deauthentication forces clients to reassociate,
  typically over WPA2-PSK. The resulting PBKDF2-based handshake is captured and
  cracked offline with `hashcat -m 22000`.
* **WPS**: attempted on transition-mode routers too (Pixie-Dust recovers the
  credential regardless of WPA3); skipped only on WPA3-only targets.
* **PMKID**: skipped on WPA3-only targets (SAE APs do not disclose a PSK-based
  PMKID); still attempted on transition-mode targets.
* **Pure WPA3-SAE**: captured honestly but practically **not crackable offline**
  from a wordlist — SAE (Dragonfly, a PAKE) is designed so that each password
  guess requires an online interaction with the AP. Wifite warns you instead of
  pretending otherwise.

> ⚠️ For **authorized testing only**, on networks you own or have permission to audit.

## Requirements for WPA3 auditing

* `hcxdumptool` + `hcxtools` (`hcxpcapngtool`) — SAE/PMKID capture & conversion
* `hashcat` ≥ 6.0 — `-m 22000` unified WPA-PBKDF2-PMKID+EAPOL mode
* A monitor-mode + injection-capable wireless adapter
