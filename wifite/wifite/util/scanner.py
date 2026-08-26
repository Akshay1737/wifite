#!/usr/bin/env python
# -*- coding: utf-8 -*-

from time import sleep, time

from ..config import Configuration
from ..tools.airodump import Airodump
from ..util.color import Color
from shlex import quote as shlex_quote


class Scanner(object):
    """ Scans wifi networks & provides menu for selecting targets """

    # Console code for moving up one line
    UP_CHAR = '\033[1A'

    def __init__(self):
        self.previous_target_count = 0
        self.target_archives = {}
        self.targets = []
        self.target = None  # Target specified by user (based on ESSID/BSSID)
        self.err_msg = None
        self._max_targets = 1000  # Limit target list size to prevent memory bloat
        self._cleanup_counter = 0  # Counter for periodic cleanup

    def find_targets(self):
        """
        Scans for targets via Airodump.
        Loops until scan is interrupted via user or config.
        Sets this object `targets` attribute (list[Target]) on interruption
        """

        max_scan_time = Configuration.scan_time

        # Loads airodump with interface/channel/etc from Configuration
        try:
            with Airodump() as airodump:
                # Loop until interrupted (Ctrl+C)
                scan_start_time = time()

                while True:
                    if airodump.pid.poll() is not None:
                        return True  # Airodump process died

                    self.targets = airodump.get_targets(old_targets=self.targets,
                                                        target_archives=self.target_archives)

                    # Periodic memory cleanup
                    self._cleanup_counter += 1
                    if self._cleanup_counter % 10 == 0:  # Every 10 scans
                        self._cleanup_memory()

                    # Memory monitoring
                    if self._cleanup_counter % 50 == 0:  # Every 50 scans
                        from ..util.memory import MemoryMonitor
                        MemoryMonitor.periodic_check(self._cleanup_counter)

                    if self.found_target():
                        return True  # We found the target we want

                    if airodump.pid.poll() is not None:
                        return True  # Airodump process died

                    self.print_targets()

                    target_count = len(self.targets)
                    client_count = sum(len(t2.clients) for t2 in self.targets)

                    outline = '\r{+} Scanning'
                    if airodump.decloaking:
                        outline += ' & decloaking'
                    outline += '. Found'
                    outline += ' {G}%d{W} target(s),' % target_count
                    outline += ' {G}%d{W} client(s).' % client_count
                    outline += ' {O}Ctrl+C{W} when ready '
                    Color.clear_entire_line()
                    Color.p(outline)

                    if max_scan_time > 0 and time() > scan_start_time + max_scan_time:
                        return True

                    sleep(1)

        except KeyboardInterrupt:
            return self._extracted_from_find_targets_50()

    # TODO Rename this here and in `find_targets`
    def _extracted_from_find_targets_50(self):
        if not Configuration.infinite_mode:
            return True

        options = '({G}s{W}{D}, {W}{R}e{W})'
        prompt = '{+} Do you want to {G}start attacking{W} or {R}exit{W}%s?' % options

        self.print_targets()
        Color.clear_entire_line()
        Color.p(prompt)
        try:
            answer = input().lower()
        except KeyboardInterrupt:
            # If user presses Ctrl+C during input, default to exit
            Color.pl('\n{!} {O}Interrupted during input, exiting...{W}')
            return False  # Exit

        return not answer.startswith('e')

    def update_targets(self):
        """
        Archive all the old targets
        Returns: True if user wants to stop attack, False otherwise
        """
        self.previous_target_count = 0
        # for target in self.targets:
        # self.target_archives[target.bssid] = ArchivedTarget(target)

        self.targets = []
        return self.find_targets()

    def get_num_attacked(self):
        """
        Returns: number of attacked targets by this scanner
        """
        return sum(bool(target.attacked) for target in list(self.target_archives.values()))

    def found_target(self):
        """
        Detect if we found a target specified by the user (optional).
        Sets this object's `target` attribute if found.
        Returns: True if target was specified and found, False otherwise.
        """
        bssid = Configuration.target_bssid
        essid = Configuration.target_essid

        if bssid is None and essid is None:
            return False  # No specific target from user.

        for target in self.targets:
            # if Configuration.wps_only and target.wps not in [WPSState.UNLOCKED, WPSState.LOCKED]:
            #    continue
            if bssid and target.bssid and bssid.lower() == target.bssid.lower():
                self.target = target
                break
            if essid and target.essid and essid == target.essid:
                self.target = target
                break

        if self.target:
            Color.pl('\n{+} {C}found target{G} %s {W}({G}%s{W})' % (self.target.bssid, self.target.essid))
            return True

        return False

    @staticmethod
    def clr_scr():
        import platform
        import os

        cmdtorun = 'cls' if platform.system().lower() == "windows" else 'clear'
        os.system(shlex_quote(cmdtorun))

    def print_targets(self):
        """Prints targets selection menu (1 target per row)."""
        if len(self.targets) == 0:
            Color.p('\r')
            return

        # Always clear the screen before printing targets
        if Configuration.verbose <= 1:
            self.clr_scr()

        self.previous_target_count = len(self.targets)

        # Overwrite the current line
        Color.p('\r{W}{D}')

        # First row: columns
        Color.p('   NUM')
        Color.p('                      ESSID')
        if Configuration.show_bssids:
            Color.p('              BSSID')

        if Configuration.show_manufacturers:
            Color.p('           MANUFACTURER')

        Color.pl('   CH  ENCR     PWR   WPS  CLIENT')

        # Second row: separator
        Color.p('   ---')
        Color.p('  -------------------------')
        if Configuration.show_bssids:
            Color.p('  -----------------')

        if Configuration.show_manufacturers:
            Color.p('  ---------------------')

        Color.pl('  ---  -----    ----  ---  ------{W}')

        # Remaining rows: targets
        for idx, target in enumerate(self.targets, start=1):
            Color.clear_entire_line()
            Color.p('   {G}%s  ' % str(idx).rjust(3))
            Color.pl(target.to_str(
                Configuration.show_bssids,
                Configuration.show_manufacturers
            )
            )

    @staticmethod
    def get_terminal_height():
        import os
        (rows, columns) = os.popen('stty size', 'r').read().split()
        return int(rows)

    @staticmethod
    def get_terminal_width():
        import os
        (rows, columns) = os.popen('stty size', 'r').read().split()
        return int(columns)

    def select_targets(self):
        """
        Returns list(target)
        Either a specific target if user specified -bssid or --essid.
        If the user used pillage or infinite attack mode retuns all the targets
        Otherwise, prompts user to select targets and returns the selection.
        """

        if self.target:
            # When user specifies a specific target
            return [self.target]

        if len(self.targets) == 0:
            if self.err_msg is not None:
                Color.pl(self.err_msg)

            # TODO Print a more-helpful reason for failure.
            # 1. Link to wireless drivers wiki,
            # 2. How to check if your device supports monitor mode,
            # 3. Provide airodump-ng command being executed.
            raise Exception('No targets found.'
                            + ' You may need to wait longer,'
                            + ' or you may have issues with your wifi card')

        # Return all targets if user specified a wait time ('pillage').
        # A scan time is always set if run in infinite mode
        if Configuration.scan_time > 0:
            return self.targets

        # Ask user for targets if no automatic selection
        return self._prompt_user_for_targets()

    def _cleanup_memory(self):
        """Periodic memory cleanup to prevent bloat during long scans"""
        # Limit target list size
        if len(self.targets) > self._max_targets:
            # Keep only the strongest targets
            self.targets.sort(key=lambda x: x.power, reverse=True)
            self.targets = self.targets[:self._max_targets]

        # Clean up old archived targets (keep only recent ones)
        if len(self.target_archives) > 500:  # Limit archive size
            # Remove oldest entries, keep newest 300
            sorted_archives = sorted(self.target_archives.items(),
                                   key=lambda x: getattr(x[1], 'last_seen', 0),
                                   reverse=True)
            self.target_archives = dict(sorted_archives[:300])

        # Force garbage collection periodically
        if self._cleanup_counter % 50 == 0:  # Every 50 cleanup cycles
            import gc
            gc.collect()

    def _prompt_user_for_targets(self):
        """Prompt user to select targets from the list"""
        # Ask user for targets.
        self.print_targets()
        Color.clear_entire_line()

        if self.err_msg is not None:
            Color.pl(self.err_msg)

        input_str = '{+} Select target(s)'
        input_str += ' ({G}1-%d{W})' % len(self.targets)
        input_str += ' separated by commas, dashes'
        input_str += ' or {G}all{W}: '

        chosen_targets = []

        Color.p(input_str)
        try:
            user_input = input()
        except KeyboardInterrupt:
            # If user presses Ctrl+C during input, return empty list to exit
            Color.pl('\n{!} {O}Interrupted during target selection, exiting...{W}')
            return []

        for choice in user_input.split(','):
            choice = choice.strip()
            if choice.lower() == 'all':
                chosen_targets = self.targets
                break
            if '-' in choice:
                # User selected a range
                (lower, upper) = [int(x) - 1 for x in choice.split('-')]
                for i in range(lower, min(len(self.targets), upper + 1)):
                    chosen_targets.append(self.targets[i])
            elif choice.isdigit():
                choice = int(choice)
                if choice > len(self.targets):
                    Color.pl('    {!} {O}Invalid target index (%d)... ignoring' % choice)
                    continue

                chosen_targets.append(self.targets[choice - 1])

        return chosen_targets


if __name__ == '__main__':
    # 'Test' script will display targets and selects the appropriate one
    Configuration.initialize()
    targets = []
    try:
        s = Scanner()
        s.find_targets()
        targets = s.select_targets()
    except (OSError, IOError) as e:
        Color.pl('\r {!} {R}Scanner I/O Error{W}: %s' % str(e))
        Configuration.exit_gracefully()
    except subprocess.CalledProcessError as e:
        Color.pl('\r {!} {R}Scanner Command Failed{W}: %s' % str(e))
        Configuration.exit_gracefully()
    except ValueError as e:
        Color.pl('\r {!} {R}Scanner Configuration Error{W}: %s' % str(e))
        Configuration.exit_gracefully()
    except Exception as e:
        Color.pl('\r {!} {R}Unexpected Scanner Error{W}: %s' % str(e))
        if Configuration.verbose > 0:
            Color.pexception(e)
        Configuration.exit_gracefully()
    for t in targets:
        Color.pl('    {W}Selected: %s' % t)
    Configuration.exit_gracefully()
