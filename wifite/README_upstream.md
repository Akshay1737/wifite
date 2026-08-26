[![GitHub version](https://img.shields.io/badge/version-2.8.1-informational.svg)](#)
[![GitHub issues](https://img.shields.io/github/issues/kimocoder/wifite2.svg)](https://github.com/kimocoder/wifite2/issues)
[![GitHub forks](https://img.shields.io/github/forks/kimocoder/wifite2.svg)](https://github.com/kimocoder/wifite2/network)
[![GitHub stars](https://img.shields.io/github/stars/kimocoder/wifite2.svg)](https://github.com/kimocoder/wifite2/stargazers)
[![Android Supported](https://img.shields.io/badge/Android-Supported-green.svg)](#)
[![GitHub license](https://img.shields.io/github/license/kimocoder/wifite2.svg)](https://github.com/kimocoder/wifite2/blob/master/LICENSE)


Wifite
======

This repo is a complete re-write of [`wifite`](https://github.com/derv82/wifite), a Python script for auditing wireless networks.

Wifite runs existing wireless-auditing tools for you. Stop memorizing command arguments & switches!

Wifite is designed to use all known methods for retrieving the password of a wireless access point (router).  These methods include:
1. WPS: The [Offline Pixie-Dust attack](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Setup#Offline_brute-force_attack)
1. WPS: The [Online Brute-Force PIN attack](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Setup#Online_brute-force_attack)<br>
   WPS: The [Offline NULL PIN attack](https://github.com/t6x/reaver-wps-fork-t6x/wiki/Introducing-a-new-way-to-crack-WPS:-Option--p-with-an-Arbitrary-String)
2. WPA: The [WPA Handshake Capture](https://hashcat.net/forum/thread-7717.html) + offline crack.
3. WPA: The [PMKID Hash Capture](https://hashcat.net/forum/thread-7717.html) + offline crack.
4. WEP: Various known attacks against WEP, including *fragmentation*, *chop-chop*, *aireplay*, etc.
5. WIFI Signal jammer, block specific accesspoints or multiple.
   signal jamming only works for specific Atheros WiFi chipsets. 

Run wifite, select your targets, and Wifite will automatically start trying to capture or crack the password.

Supported Operating Systems
---------------------------

### Fully Supported ✅
* **[Kali Linux](https://www.kali.org/)** - Primary development platform (latest version recommended)
* **[ParrotSec](https://www.parrotsec.org/)** - Well-tested and supported
* **[BlackArch](https://blackarch.org/)** - Compatible with latest tool versions

### Mobile Support 📱
* **Kali NetHunter (Android)** - Requires custom kernel with monitor mode support
  * Tested on Android 10 to latest 16
  * Requires compatible wireless adapter and proper drivers
  * See [NetHunter Documentation](https://www.kali.org/docs/nethunter/) for setup

### Partially Supported ⚠️
* **Ubuntu/Debian** - May work with manual tool installation and updated drivers
* **Arch Linux** - Compatible with AUR packages and proper wireless drivers
* **Other Linux distributions** - Requires latest versions of all dependencies

### Requirements for All Platforms
* **Python 3.8+** (Python 3.11+ recommended)
* **Wireless adapter with monitor mode support**
* **Root/sudo access** for network interface manipulation
* **Latest versions of required tools** (see Required Tools section)

**Note:** Other penetration testing distributions may have outdated tool versions. Ensure you have the latest versions of aircrack-ng, hashcat, and related tools for best compatibility.

Required Tools
--------------
First and foremost, you will need a wireless card capable of "Monitor Mode" and packet injection (see [this tutorial for checking if your wireless card is compatible](https://www.aircrack-ng.org/doku.php?id=compatible_cards) and also [this guide](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Setup#Offline_brute-force_attack)). There are many cheap wireless cards that plug into USB available from online stores.

Second, only the latest versions of these programs are supported and must be installed for Wifite to work properly:

**Required:**

* Suggest using `python3` as `python2` was marked deprecated as of january 2020.
* As we moved from older python and changed to fully support and run on `python3.11`
* [`Iw`](https://wireless.wiki.kernel.org/en/users/documentation/iw): For identifying wireless devices already in Monitor Mode.
* [`Ip`](https://packages.debian.org/buster/net-tools): For starting/stopping wireless devices.
* [`Aircrack-ng`](https://aircrack-ng.org/) suite, includes:
   * [`airmon-ng`](https://tools.kali.org/wireless-attacks/airmon-ng): For enumerating and enabling Monitor Mode on wireless devices.
   * [`aircrack-ng`](https://tools.kali.org/wireless-attacks/aircrack-ng): For cracking WEP .cap files and WPA handshake captures.
   * [`aireplay-ng`](https://tools.kali.org/wireless-attacks/aireplay-ng): For deauthing access points, replaying capture files, various WEP attacks.
   * [`airodump-ng`](https://tools.kali.org/wireless-attacks/airodump-ng): For target scanning & capture file generation.
   * [`packetforge-ng`](https://tools.kali.org/wireless-attacks/packetforge-ng): For forging capture files.

**Optional, but Recommended:**

* [`tshark`](https://www.wireshark.org/docs/man-pages/tshark.html): For detecting WPS networks and inspecting handshake capture files.
* [`reaver`](https://github.com/t6x/reaver-wps-fork-t6x): For WPS Pixie-Dust & brute-force attacks.
   * Note: Reaver's `wash` tool can be used to detect WPS networks if `tshark` is not found.
* [`bully`](https://github.com/aanarchyy/bully): For WPS Pixie-Dust & brute-force attacks.
   * Alternative to Reaver. Specify `--bully` to use Bully instead of Reaver.
   * Bully is also used to fetch PSK if `reaver` cannot after cracking WPS PIN.
* [`john`](https://www.openwall.com/john): For CPU (OpenCL)/GPU cracking passwords fast.
* [`coWPAtty`](https://tools.kali.org/wireless-attacks/cowpatty): For detecting handshake captures.
* [`hashcat`](https://hashcat.net/): For cracking PMKID hashes.
   * [`hcxdumptool`](https://github.com/ZerBea/hcxdumptool): For capturing PMKID hashes.
   * [`hcxpcapngtool`](https://github.com/ZerBea/hcxtools): For converting PMKID packet captures into `hashcat`'s format.
* [`macchanger`](https://github.com/alobbs/macchanger): For randomizing MAC addresses to avoid detection and improve anonymity.
* [`pixiewps`](https://github.com/wiire-a/pixiewps): For WPS Pixie-Dust attacks (alternative implementation).



Installation
------------

### Quick Install (Recommended)

For most users on Kali Linux or similar distributions:

```bash
# Clone the repository
git clone https://github.com/kimocoder/wifite2.git
cd wifite2

# Install system-wide
sudo python3 setup.py install

# Run wifite
sudo wifite
```

### Development Install

For development or if you want to modify wifite:

```bash
# Clone and enter directory
git clone https://github.com/kimocoder/wifite2.git
cd wifite2

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip3 install -r requirements.txt

# Run directly from source
sudo python3 wifite.py
```

### Package Manager Install

On some distributions, wifite2 may be available through package managers:

```bash
# Kali Linux / Debian
sudo apt update && sudo apt install wifite

# Arch Linux (AUR)
yay -S wifite2-git
```

### Verify Installation

After installation, verify all dependencies are available:

```bash
sudo wifite --help
```

This will show if any required tools are missing.



Features
--------

### Attack Methods
* **[PMKID hash capture](https://hashcat.net/forum/thread-7717.html)** - Fast, clientless WPA/WPA2 attack (enabled by default)
* **WPS Pixie-Dust Attack** - Offline WPS PIN recovery (enabled by default, force with: `--wps-only --pixie`)
* **WPS PIN Attack** - Online WPS brute-force (enabled by default, force with: `--wps-only --no-pixie`)
* **WPA/WPA2 Handshake Capture** - Traditional 4-way handshake attack (enabled by default, force with: `--no-wps`)
* **WEP Attacks** - Multiple methods: replay, chopchop, fragment, hirte, p0841, caffe-latte
* **WPA3-SAE Support** - Modern WPA3 hash capture and cracking

### Smart Features
* **Automatic Target Detection** - Scans and identifies vulnerable networks
* **Hidden Network Decloaking** - Reveals hidden SSIDs during attacks
   * Works when channel is fixed with `-c <channel>`
   * Disable with `--no-deauths`
* **Multi-tool Validation** - Verifies handshakes with `tshark`, `cowpatty`, and `aircrack-ng`
* **5GHz Support** - Works with 5GHz networks (use `-5` switch)
   * Note: Some tools have limited 5GHz support
* **Result Management** - Automatically saves cracked passwords and handshakes
   * Includes detailed information (SSID, BSSID, date, method used)
   * View previous results with `--cracked`

### Performance & Reliability
* **Resource Management** - Automatic cleanup prevents system resource exhaustion
* **Memory Optimization** - Efficient handling of large target lists and long scans
* **Process Monitoring** - Prevents zombie processes and file descriptor leaks
* **Error Recovery** - Graceful handling of tool failures and system errors

### Convenience Features
* **Wordlist Cracking** - Test captured handshakes/PMKID against wordlists (`--crack`)
* **Flexible Targeting** - Target specific networks by BSSID, ESSID, or channel
* **Verbose Logging** - Detailed output for learning and debugging (`-v`, `-vv`, `-vvv`)
* **Automation Support** - Scriptable with various timeout and retry options

**💡 TIP:** Use `wifite -h -v` to see all available options and advanced settings!

Performance Tips
-----------------

### For Best Results
* **Use a dedicated wireless adapter** - USB adapters often perform better than built-in cards
* **Position matters** - Get closer to target networks for better signal strength
* **Choose the right channel** - Use `-c <channel>` to focus on specific channels
* **Limit concurrent attacks** - Use `--first 5` to attack only the strongest targets first

### Speed Optimization
* **PMKID first** - Try `--pmkid-only` for fastest WPA/WPA2 attacks (no clients needed)
* **Skip WPS on modern routers** - Use `--no-wps` on newer routers that likely have WPS disabled
* **Use wordlists efficiently** - Start with common passwords, use `--dict <wordlist>`

### Resource Management
* **Monitor system resources** - Watch CPU and memory usage during long scans
* **Regular breaks** - Stop and restart wifite periodically during extended sessions
* **Clean up** - Remove old capture files and temporary data regularly

### Core Features
* **Less bugs**
   * Cleaner process management. Does not leave processes running in the background (the old `wifite` was bad about this).
   * No longer "one monolithic script". Has working unit tests. Pull requests are less-painful!
* **Speed**
   * Target access points are refreshed every second instead of every 5 seconds.
* **Accuracy**
   * Displays realtime Power level of currently-attacked target.
   * Displays more information during an attack (e.g. % during WEP chopchop attacks, Pixie-Dust step index, etc)
* **Educational**
   * The `--verbose` option (expandable to `-vv` or `-vvv`) shows which commands are executed & the output of those commands.
   * This can help debug why Wifite is not working for you. Or so you can learn how these tools are used.
* More-actively developed, with some help from the awesome open-source community.
* Python 3 support.
* Sweet new ASCII banner.


Troubleshooting
---------------

### Common Issues

**"Too many open files" error:**
- This has been fixed in v2.7.3 with enhanced process management
- If you still encounter this, try reducing concurrent attacks or restart wifite

**Permission denied errors:**
- Ensure you're running wifite with `sudo`
- Check that your wireless interface supports monitor mode
- Verify all required tools are installed and accessible

**Interface not found:**
- Run `sudo airmon-ng` to see available interfaces
- Use `sudo airmon-ng start <interface>` to enable monitor mode manually
- Some interfaces require specific drivers or firmware

**WPS attacks failing:**
- Ensure `reaver` and/or `bully` are installed and up-to-date
- Some routers have WPS disabled or rate-limiting enabled
- Try the `--pixie` flag for Pixie-Dust attacks specifically

**Handshake capture issues:**
- Ensure clients are connected to the target network
- Use `--deauth-count` to increase deauth attempts
- Some networks may require longer capture times

### Getting Help

1. **Enable verbose mode:** Use `-v`, `-vv`, or `-vvv` to see detailed command output
2. **Check dependencies:** Run `wifite --help` to see if all tools are detected
3. **Update tools:** Ensure you have the latest versions of aircrack-ng, hashcat, etc.
4. **Check compatibility:** Verify your wireless card supports monitor mode and injection

For more help, please [open an issue](https://github.com/kimocoder/wifite2/issues) with:
- Your operating system and version
- Wireless card model and chipset
- Full command output with `-vvv` flag
- Error messages or unexpected behavior


Contributing
------------

Wifite2 is actively maintained and welcomes contributions! Here's how you can help:

### Reporting Issues
* Use the [GitHub issue tracker](https://github.com/kimocoder/wifite2/issues)
* Include your OS, wireless card model, and full error output
* Use verbose mode (`-vvv`) to capture detailed logs

### Contributing Code
* Fork the repository and create a feature branch
* Follow existing code style and add tests where possible
* Submit pull requests with clear descriptions of changes
* All contributions are welcome: bug fixes, new features, documentation improvements

### Testing
* Test on different wireless cards and operating systems
* Report compatibility issues and successful configurations
* Help verify fixes and new features

### Documentation
* Improve README sections, add examples, fix typos
* Create tutorials and guides for specific use cases
* Translate documentation to other languages

**Maintainer:** [@kimocoder](https://github.com/kimocoder)  
**Original Author:** [@derv82](https://github.com/derv82)

---

**⚠️ Legal Disclaimer:** This tool is for educational and authorized testing purposes only. Only use on networks you own or have explicit permission to test. Unauthorized access to computer networks is illegal.
