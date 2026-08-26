# Wifite — Enhanced Build (WPA3 + Channel-Following + Fast Capture)

Automated wireless network auditor based on **wifite2** (original by @derv82,
rewritten/maintained by @kimocoder). This build adds fixes and new capabilities
on top of upstream — see `README_upstream.md` for the original document.

| # | Enhancement | What it does |
|---|-------------|--------------|
| 1 | **Working WPA3 support** | Fixed hashcat mode (22000) & hcxpcapngtool invocation; detects *transition-mode* vs *WPA3-only* targets; Pixie-Dust now tried on transition routers; honest warnings for pure-SAE |
| 2 | **Channel-following capture** | If a target hops channels mid-attack, wifite relocates it automatically and resumes capturing on the new channel |
| 3 | **Fast handshake capture** | Deauth burst fires the instant a client is discovered instead of waiting out the deauth timer |
| 4 | **`crack_handshakes.sh`** | Stand-alone bash script: converts all captures → hashcat 22000 → runs wordlist → rules → escalating GPU mask ladder |

> ## ⚠️ Legal Disclaimer
> This tool is for **educational purposes and authorized testing only**.
> Only audit networks **you own** or have **explicit written permission** to test.
> Unauthorized access to computer networks is illegal in most jurisdictions.

---

## 1. Requirements

* **Linux** — Kali / Parrot OS recommended (will not run on Windows/macOS)
* **Wireless adapter** with monitor mode + packet injection
  (e.g. Alfa AWUS036ACH / AWUS036NHA, TP-Link TL-WN722N v1, Atheros AR9271)
* Python **3.8+**
* Tools — on Kali:

```bash
sudo apt update
sudo apt install -y aircrack-ng reaver bully tshark hashcat \
                    hcxdumptool hcxtools macchanger net-tools
```

Tool roles: `aircrack-ng` (scan/capture/inject) · `reaver`/`bully` (WPS/Pixie-Dust) ·
`hcxdumptool`+`hcxtools` (PMKID/SAE capture & conversion) · `hashcat` ≥ 6.0 (cracking).

### Python setup

```bash
cd wifite
python3 -m pip install -r requirements.txt   # pytest, scapy, chardet
```

## 2. Quick start

```bash
# 1. Put your adapter into monitor mode (replace wlan0 with your iface)
sudo airmon-ng start wlan0            # creates wlan0mon

# 2. Run wifite
sudo python3 wifite.py -i wlan0mon

# 3. Ctrl+C to stop scanning, type target number(s), press Enter.
#    Wifite picks the best attack chain per target automatically.
```

Target list legend (this build highlights WPA3 in purple):

```
NUM  ESSID        CH  ENCR    POWER  WPS   CLIENTS
  1  Home-5G      44  WPA3-S  42db   no      0     ← WPA3-only (SAE)
  2  Router-A     11  WPA2-P  55db   yes     2     ← WPA2 + WPS unlocked
  3  Mesh-Plus     6  WPA3-S  48db   yes     1     ← transition mode inside!
```

`WPA3-S` = SAE auth · `WPA2-P` = PSK · `-E` = Enterprise (skipped).

## 3. Flags reference (verified against this build)

### Scanning / general

| Flag | Meaning |
|---|---|
| `-i <iface>` | Monitor interface |
| `-c 1,3-6` | Scan only these channels |
| `-ab` | Scan **both** 2.4 + 5 GHz bands |
| `-5` / `-2` | 5 GHz only / 2.4 GHz only |
| `-p 10` | *Pillage*: auto-attack all targets after N seconds of scanning |
| `--first 3` | Stop after attacking N targets |
| `-pow 40` | Only attack targets with power ≥ value |
| `--kill` | Kill NetworkManager & friends first |
| `-mac` | Randomize your MAC address |
| `--skip-crack` | Capture handshakes but don't auto-crack inline |
| `-v`, `-vv`, `-vvv` | Verbosity levels |

### Filtering

| Flag | Meaning |
|---|---|
| `--wpa` | Show only WPA/WPA2 networks |
| `--wpa3` | Show only **WPA3** networks |
| `--wps-only` | Attack via WPS only |
| `--pmkid` / `--no-pmkid` | PMKID-only mode / disable PMKID |
| `-nd` (`--no-deauths`) | Passive mode, never deauth |

### WPA timing & storage

| Flag | Default | Meaning |
|---|---|---|
| `--wpat <sec>` | ~300 | Total handshake-capture budget per target |
| `--wpadt <sec>` | 10 | Seconds between deauth bursts (first burst = instant) |
| `--dict <file>` | bundled | Wordlist used for inline cracking |
| `--hs-dir <dir>` | `hs/` | Handshake/PMKID storage directory |
| `--new-hs` | off | Ignore stored captures; force fresh capture |

## 4. Channel-following capture (new)

Some routers change channels on their own (mesh band-steering, DFS radar
avoidance, "auto" channel mode). Stock wifite locked to one channel and **gave
up** if the AP moved. This build follows it:

1. Locked on channel `6`, listening for the target…
2. Target disappears for **5 s** → wifite runs an 8 s hopping scan filtered to
   that one BSSID across 2.4 + 5 GHz.
3. Found on channel `11` → live status prints:

```
 WPA  Mesh-Plus  Channel follow: Target moved 6 -> 11
```

4. Capture resumes automatically on the new channel; total time is still
   governed by `--wpat`.

Nothing to configure — it just works. Keep `-ab` in mind while scanning so you
*see* 5 GHz movers in the first place.

## 5. Faster handshakes (new)

| | Upstream behavior | This build |
|---|---|---|
| First deauth | after full `--wpadt` wait (~10 s dead air) | **instantly** when a client is seen |
| Client appears mid-attack | waits for next timer tick | deauthed on next loop pass |
| AP vanishes mid-attack | attack aborted | tolerated → relocation kicks in |

Typical capture with visible clients drops from ~15-20 s to **~3-5 s**.

## 6. WPA3 support — what actually works

Wifite now classifies every purple target into one of two cases and behaves
accordingly:

### A) Transition mode (`WPA2 WPA3` / `PSK SAE`) ← most real-world "WPA3"
* Deauth forces clients back onto **WPA2-PSK** → normal crackable handshake
* PMKID attempted as usual
* **Pixie-Dust tried too** if WPS shows unlocked — it leaks the credential
  regardless of protocol

### B) WPA3-only (`WPA3` / `SAE`)
* Handshake capture still offered (useful for records/John workflows)
* PMKID skipped with an explanation (SAE APs don't leak PSK-based PMKIDs)
* Honest warning printed: *pure SAE resists offline dictionary attacks by
  design* — cracking succeeds only if a captured client fell back to WPA2

Details & rationale: [`docs/WPA3.md`](docs/WPA3.md)

## 7. Cracking captures — `crack_handshakes.sh`

After any session your captures live in `hs/`
(`handshake_*.cap`, `pmkid_*.22000`). Crack everything with:

```bash
chmod +x crack_handshakes.sh

./crack_handshakes.sh                          # auto: finds hs/ + rockyou
./crack_handshakes.sh -d ~/hs                  # custom handshake dir
./crack_handshakes.sh -w my_wordlist.txt       # custom wordlist
./crack_handshakes.sh --aggressive             # add slow GPU masks
./crack_handshakes.sh --benchmark              # measure YOUR hashcat speed first!
```

### Attack ladder (fastest keyspaces first)

| Stage | Attack | Typical time* |
|---|---|---|
| 0 | Potfile reuse from earlier runs | instant |
| 1 | Dictionary (auto-finds rockyou on Kali) | minutes |
| 2 | Dictionary + best64 mutation rules | ~10× stage 1 |
| 3 | Mask `?d ×8` (8 digits, ~100M) | seconds |
| 3 | Mask `?d ×9` (~1B) | < minute |
| 3 | Mask `?l ×8` (8 lowercase) | GPU minutes |
| `--aggressive` | `?d ×10`, mixed-case ×8, printable ×7 | hours — strong GPU |

\* mid-range modern GPU; CPU-only falls back to `--force` automatically.

Cracked passwords print in green and are stored in `hs/.converted/wifite.pot`,
so re-running never repeats work.

> **Reality check:** brute-force speed = keyspace ÷ hardware. The ladder is
> ordered so human-typical passwords fall early; long random passwords are not
> realistically brute-forceable — that's physics, not tooling.

## 8. End-to-end example (your own router!)

```bash
sudo airmon-ng start wlan0
sudo python3 wifite.py -i wlan0mon -ab --wpadt 5 --dict /usr/share/wordlists/rockyou.txt
#    ... select your AP number, let it capture ...

# Inline crack failed / you skipped it? Finish the job:
./crack_handshakes.sh --benchmark     # see what your rig can do
./crack_handshakes.sh                 # run the ladder on everything in hs/
```

## 9. Testing this build

Unit tests run anywhere (no RF hardware needed):

```bash
python3 -m pytest tests/test_Target.py -v
# 7 passed — target parsing, WPA3-only vs transition-mode detection, display
```

Live capture/cracking must be validated on Linux with real hardware against a
network you are authorized to test.

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| No targets appear | Adapter not in monitor mode: `sudo airmon-ng start wlan0`; try `--kill` |
| Can't see 5 GHz APs | Add `-ab` or `-5`; ensure adapter supports 5 GHz |
| "not associated" / injection fails | Some drivers need `iw dev wlan0mon set channel N` first; try another adapter |
| Hashcat says no devices | CPU-only box → script auto-adds `--force`; expect slow masks |
| hcxpcapngtool converts nothing | Capture had only SAE frames from a WPA3-only net — expected; see docs/WPA3.md |
| Permission denied on script | `chmod +x crack_handshakes.sh` |

## 11. Credits

* Original wifite: **@derv82**
* wifite2 rewrite & maintenance: **@kimocoder** and contributors
* This build's changes: WPA3 pipeline fixes, transition-mode logic,
  channel-following capture, fast-deauth scheduling, `crack_handshakes.sh`

License: **GPL-2.0** (see LICENSE). Upstream documentation preserved in
`README_upstream.md`.
