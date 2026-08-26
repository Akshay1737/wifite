#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..config import Configuration
from ..util.process import Process
from ..util.color import Color
import os

hccapx_autoremove = False  # change this to True if you want the hccapx files to be automatically removed


class Hashcat(Dependency):
    dependency_required = False
    dependency_name = 'hashcat'
    dependency_url = 'https://hashcat.net/hashcat/'

    @staticmethod
    def should_use_force():
        command = ['hashcat', '-I']
        stderr = Process(command).stderr()
        return 'No devices found/left' or 'Unstable OpenCL driver detected!' in stderr

    @staticmethod
    def get_hashcat_mode():
        """
        Returns the hashcat mode used for wordlist-cracking captures.
        Mode 22000 (WPA-PBKDF2-PMKID+EAPOL) is hashcat's unified mode: it covers
        WPA/WPA2 EAPOL handshakes, PMKIDs, and WPA3-SAE captures as emitted by
        hcxpcapngtool ('WPA*...' hash lines).
        NOTE: Mode 22001 expects a *precomputed PMK* and CANNOT be attacked with
        a wordlist, so it must never be selected here.
        """
        return '22000'

    @staticmethod
    def crack_handshake(handshake_obj, target_is_wpa3_sae, show_command=False):
        """
        Cracks a handshake.
        handshake_obj: A Handshake object (should have .capfile attribute)
        target_is_wpa3_sae: True ONLY for *pure* WPA3-SAE targets (no WPA2
            fallback / not in transition mode). Used for user messaging only;
            the hashcat mode is identical either way.
        """
        hash_file = HcxPcapngTool.generate_hash_file(handshake_obj, target_is_wpa3_sae, show_command=show_command)

        key = None
        hashcat_mode = Hashcat.get_hashcat_mode()
        file_type_msg = "WPA3-SAE capture" if target_is_wpa3_sae else "WPA/WPA2 hash"

        Color.pl(f"{{+}} {{C}}Attempting to crack {file_type_msg} using Hashcat mode {hashcat_mode}{{W}}")

        if target_is_wpa3_sae:
            Color.pl('{!} {O}Pure WPA3-SAE associations resist offline dictionary attacks by design.{W}')
            Color.pl('{!} {O}Cracking can only succeed if the capture contains a WPA2-PSK association '
                     '(e.g., a client that fell back during a forced reassociation).{W}')

        # Crack hash_file
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',
                '-m', hashcat_mode,
                hash_file,
                Configuration.wordlist
            ]
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if show_command:
                Color.pl(f'{{+}} {{D}}Running: {{W}}{{P}}{" ".join(command)}{{W}}')
            process = Process(command)
            stdout, stderr = process.get_output()

            # Check for errors first
            if 'No hashes loaded' in stdout or 'No hashes loaded' in stderr:
                continue  # No valid hashes to crack

            if ':' not in stdout:
                continue  # No cracked results

            # Parse the key from hashcat output
            # Expected format: hash:password
            lines = stdout.strip().split('\n')
            for line in lines:
                if ':' in line and not line.startswith('The plugin') and 'hashcat.net' not in line:
                    # Take the last part after the last colon as the password
                    parts = line.split(':')
                    if len(parts) >= 2:
                        key = parts[-1].strip()
                        if key and len(key) > 0:
                            break
            else:
                continue
            break

        return key

    @staticmethod
    def crack_pmkid(pmkid_file, verbose=False):
        """
        Cracks a given pmkid_file using the PMKID/WPA2 attack (-m 22000)
        Returns:
            Key (str) if found; `None` if not found.
        """

        # Run hashcat once normally, then with --show if it failed
        # To catch cases where the password is already in the pot file.
        for additional_arg in ([], ['--show']):
            command = [
                'hashcat',
                '--quiet',      # Only output the password if found.
                '-m', '22000',  # WPA-PMKID-PBKDF2
                '-a', '0',      # Wordlist attack-mode
                pmkid_file,
                Configuration.wordlist,
                '-w', '3'
            ]
            if Hashcat.should_use_force():
                command.append('--force')
            command.extend(additional_arg)
            if verbose and additional_arg == []:
                Color.pl(f'{{+}} {{D}}Running: {{W}}{{P}}{" ".join(command)}{{W}}')

            # TODO: Check status of hashcat (%); it's impossible with --quiet

            hashcat_proc = Process(command)
            hashcat_proc.wait()
            stdout = hashcat_proc.stdout()

            if ':' not in stdout:
                # Failed
                continue
            else:
                # Hashcat PMKID output format: hash*bssid*station*essid:password
                # We only want the password (last part after the last colon)
                return stdout.strip().split(':')[-1]


class HcxDumpTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxdumptool'
    dependency_url = 'apt install hcxdumptool'

    def __init__(self, target, pcapng_file):
        if os.path.exists(pcapng_file):
            os.remove(pcapng_file)

        command = [
            'hcxdumptool',
            '-i', Configuration.interface,
            '-c', str(target.channel) + 'a',
            '-w', pcapng_file
        ]

        self.proc = Process(command)

    def poll(self):
        return self.proc.poll()

    def interrupt(self):
        if hasattr(self, 'proc') and self.proc:
            self.proc.interrupt()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.interrupt()


class HcxPcapngTool(Dependency):
    dependency_required = False
    dependency_name = 'hcxpcapngtool'
    dependency_url = 'apt install hcxtools'

    def __init__(self, target):
        self.target = target
        self.bssid = self.target.bssid.lower().replace(':', '')
        self.pmkid_file = Configuration.temp(f'pmkid-{self.bssid}.22000')

    @staticmethod
    def generate_hash_file(handshake_obj, is_wpa3_sae, show_command=False):
        """
        Generates a hash file suitable for Hashcat mode 22000 using hcxpcapngtool.
        A single '-o' invocation writes hashcat's unified 22000-format hash file,
        containing every convertible hash found in the capture: WPA/WPA2 EAPOL
        handshakes, PMKIDs, and WPA3-SAE data where present.
        NOTE: hcxpcapngtool has NO '--sae-hccapx' switch (the previous code failed
        here); '-o' handles all cases, including SAE captures.
        """
        hash_file = Configuration.temp('generated.22000')
        hcx_args = ['-o', hash_file]

        if os.path.exists(hash_file):
            os.remove(hash_file)

        command = [
            'hcxpcapngtool',
            *hcx_args,
            handshake_obj.capfile # Assuming handshake_obj has a capfile attribute
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(hash_file) or os.path.getsize(hash_file) == 0:
            error_msg = f'Failed to generate {"22000-format hash file (SAE-capable)" if is_wpa3_sae else "22000-format hash file"}.'
            error_msg += f'\nOutput from hcxpcapngtool:\nSTDOUT: {stdout}\nSTDERR: {stderr}'
            # Also include tshark check for WPA3
            if is_wpa3_sae:
                from .tshark import Tshark
                tshark_check_cmd = ['tshark', '-r', handshake_obj.capfile, '-Y', 'eapol && wlan.rsn.akms.type == 0.0.9f.6'] # OUI 00-0F-AC, type 8 or 9 for SAE
                # Type 8 (SAE) and Type 9 (SAE FT)
                # Alternative check might be wlan.rsn.ie.akms.selector == 0x000fac08 for SAE
                tshark_process = Process(tshark_check_cmd)
                tshark_stdout, _ = tshark_process.get_output()
                if not tshark_stdout:
                    error_msg += '\nAdditionally, tshark found no SAE AKM in the capture file. Ensure it is a valid WPA3-SAE handshake.'
                else:
                    error_msg += '\nTshark output for SAE AKM check:\n' + tshark_stdout

            raise ValueError(error_msg)
        return hash_file

    @staticmethod
    def generate_john_file(handshake, show_command=False):
        john_file = Configuration.temp('generated.john')
        if os.path.exists(john_file):
            os.remove(john_file)

        command = [
            'hcxpcapngtool',
            '--john', john_file,
            handshake.capfile
        ]

        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))

        process = Process(command)
        stdout, stderr = process.get_output()
        if not os.path.exists(john_file):
            raise ValueError('Failed to generate .john file, output: \n%s\n%s' % (
                stdout, stderr))

        return john_file

    def get_pmkid_hash(self, pcapng_file):
        if os.path.exists(self.pmkid_file):
            os.remove(self.pmkid_file)

        command = 'hcxpcapngtool -o ' + self.pmkid_file + " " + pcapng_file
        hcxpcap_proc = Process(command)
        hcxpcap_proc.wait()

        if not os.path.exists(self.pmkid_file):
            return None

        with open(self.pmkid_file, 'r') as f:
            output = f.read()
            # Each line looks like:
            # hash*bssid*station*essid

        # Note: The dumptool will record *anything* it finds, ignoring the filterlist.
        # Check that we got the right target (filter by BSSID)
        matching_pmkid_hash = None
        for line in output.split('\n'):
            fields = line.split('*')
            if len(fields) >= 3 and fields[3].lower() == self.bssid:
                # Found it
                matching_pmkid_hash = line
                break

        os.remove(self.pmkid_file)
        return matching_pmkid_hash
