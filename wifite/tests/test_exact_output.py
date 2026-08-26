#!/usr/bin/env python3

import sys
sys.path.insert(0, '.')

from wifite.tools.airmon import Airmon

# Test with the exact current output
test_output = """
Found 6 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

    PID Name
   7044 avahi-daemon
   7105 avahi-daemon
   7183 wpa_supplicant
  25765 NetworkManager
2503235 dhclient
2523490 dhclient

PHY     Interface       Driver          Chipset

phy1    wlp4s0          iwlwifi         Intel Corporation Wi-Fi 6E(802.11ax) AX210/AX1675* 2x2 [Typhoon Peak] (rev 1a)
phy0    wlxd037456283c3 rtl8xxxu        TP-Link TL-WN821N v5/v6 [RTL8192EU]
                (mac80211 monitor mode already enabled for [phy0]wlxd037456283c3 on [phy0]10)
"""

print("Testing exact airmon-ng output...")
result = Airmon._parse_airmon_start(test_output)
print(f"Result: '{result}'")

# Let's debug the regex matching
import re

enabled_on_re = re.compile(r'.*\(mac80211 monitor mode (?:(?:vif )?enabled|already enabled) (?:for [^ ]+ )?on (?:\[\w+])?([a-zA-Z]\w+)\)?.*')
enabled_for_re = re.compile(r'.*\(mac80211 monitor mode (?:(?:vif )?enabled|already enabled) for (?:\[\w+])?(\w+).*on (?:\[\w+])?\d+\)?.*')

lines = test_output.split('\n')
for i, line in enumerate(lines):
    if 'mac80211 monitor mode' in line:
        print(f"\nLine {i}: {repr(line)}")

        match1 = enabled_on_re.match(line)
        if match1:
            print(f"  enabled_on_re matched: '{match1.group(1)}'")
        else:
            print("  enabled_on_re: no match")

        match2 = enabled_for_re.match(line)
        if match2:
            print(f"  enabled_for_re matched: '{match2.group(1)}'")
        else:
            print("  enabled_for_re: no match")

        # Check the legacy fallback
        if "monitor mode enabled" in line:
            print(f"  legacy fallback would return: '{line.split()[-1]}'")
        else:
            print("  legacy fallback: no match")
