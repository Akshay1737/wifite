#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from .config import Configuration
except (ValueError, ImportError) as e:
    raise Exception("You may need to run wifite from the root directory (which includes README.md)", e) from e


from .util.color import Color

import os
import subprocess


class Wifite(object):

    def __init__(self):
        """
        Initializes Wifite.
        Checks that its running under *nix, with root permissions and ensures dependencies are installed.
        """

        self.print_banner()

        Configuration.initialize(load_interface=False)

        if os.name == 'nt':
            Color.pl('{!} {R}error: {O}wifite{R} must be run under a {O}*NIX{W}{R} like OS')
            Configuration.exit_gracefully()
        if os.getuid() != 0:
            Color.pl('{!} {R}error: {O}wifite{R} must be run as {O}root{W}')
            Color.pl('{!} {R}re-run with {O}sudo{W}')
            Configuration.exit_gracefully()

        from .tools.dependency import Dependency
        Dependency.run_dependency_check()

    def start(self):
        """
        Starts target-scan + attack loop, or launches utilities depending on user input.
        """
        from .model.result import CrackResult
        from .model.handshake import Handshake
        from .util.crack import CrackHelper
        from .util.dbupdater import DBUpdater

        if Configuration.show_cracked:
            CrackResult.display('cracked')

        elif Configuration.show_ignored:
            CrackResult.display('ignored')

        elif Configuration.check_handshake:
            Handshake.check()

        elif Configuration.crack_handshake:
            CrackHelper.run()

        elif Configuration.update_db:
            DBUpdater.run()

        else:
            Configuration.get_monitor_mode_interface()
            self.scan_and_attack()

    @staticmethod
    def print_banner():
        """Displays ASCII art of the highest caliber."""
        Color.pl(r' {G}  .     {GR}{D}     {W}{G}     .    {W}')
        Color.pl(r' {G}.´  ·  .{GR}{D}     {W}{G}.  ·  `.  {G}wifite2 {D}%s{W}' % Configuration.version)
        Color.pl(r' {G}:  :  : {GR}{D} (¯) {W}{G} :  :  :  {W}{D}a wireless auditor by derv82{W}')
        Color.pl(r' {G}`.  ·  `{GR}{D} /¯\ {W}{G}´  ·  .´  {W}{D}maintained by kimocoder{W}')
        Color.pl(r' {G}  `     {GR}{D}/¯¯¯\{W}{G}     ´    {C}{D}https://github.com/kimocoder/wifite2{W}')
        Color.pl('')

    @staticmethod
    def scan_and_attack():
        """
        1) Scans for targets, asks user to select targets
        2) Attacks each target
        """
        from .util.scanner import Scanner
        from .attack.all import AttackAll

        Color.pl('')

        # Scan (no signal handler during scanning to allow proper target selection)
        s = Scanner()
        do_continue = s.find_targets()
        targets = s.select_targets()

        # Attack modules handle KeyboardInterrupt properly, no global handler needed

        if Configuration.infinite_mode:
            while do_continue:
                AttackAll.attack_multiple(targets)
                do_continue = s.update_targets()
                if not do_continue:
                    break
                targets = s.select_targets()
            attacked_targets = s.get_num_attacked()
        else:
            # Attack
            attacked_targets = AttackAll.attack_multiple(targets)

        Color.pl('{+} Finished attacking {C}%d{W} target(s), exiting' % attacked_targets)




def force_exit_handler(signum, frame):
    """Force exit on multiple Ctrl+C during cleanup"""
    import sys
    print('\n[!] Force exiting...')
    sys.exit(1)

def main():
    try:
        wifite = Wifite()
        wifite.start()
    except (OSError, IOError) as e:
        Color.pl('\n{!} {R}System Error{W}: %s' % str(e))
        Color.pl('\n{!} {R}Exiting{W}\n')
    except subprocess.CalledProcessError as e:
        Color.pl('\n{!} {R}Command Failed{W}: %s' % str(e))
        Color.pl('\n{!} {R}Exiting{W}\n')
    except PermissionError as e:
        Color.pl('\n{!} {R}Permission Error{W}: %s' % str(e))
        Color.pl('\n{!} {R}Try running with sudo{W}\n')
    except KeyboardInterrupt:
        Color.pl('\n{!} {O}Interrupted, Shutting down...{W}')
        # Set up force exit handler for cleanup phase
        import signal
        signal.signal(signal.SIGINT, force_exit_handler)
    except Exception as e:
        Color.pl('\n{!} {R}Unexpected Error{W}: %s' % str(e))
        Color.pexception(e)
        Color.pl('\n{!} {R}Exiting{W}\n')

    finally:
        # Set up aggressive force exit handler during cleanup
        import signal
        import sys

        def emergency_exit(signum, frame):
            print('\n[!] Emergency exit!')
            # Disable atexit callbacks and suppress stderr to prevent ugly exception messages
            import atexit
            import os
            atexit._clear()
            # Redirect stderr to devnull to hide any remaining cleanup exceptions
            os.dup2(os.open(os.devnull, os.O_WRONLY), 2)
            sys.exit(1)

        signal.signal(signal.SIGINT, emergency_exit)

        # Quick cleanup with short timeouts
        try:
            from .util.process import ProcessManager
            import threading

            # Run cleanup in thread with timeout
            cleanup_thread = threading.Thread(target=ProcessManager().cleanup_all)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            cleanup_thread.join(timeout=3)  # 3 second timeout
        except:
            pass  # Ignore cleanup errors

        # Delete Reaver .pcap quickly
        try:
            subprocess.run(["rm", "-f", "reaver_output.pcap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except:
            pass

        # Try graceful exit with timeout
        try:
            import threading

            def graceful_exit():
                Configuration.exit_gracefully()

            exit_thread = threading.Thread(target=graceful_exit)
            exit_thread.daemon = True
            exit_thread.start()
            exit_thread.join(timeout=2)  # 2 second timeout
        except:
            pass

        # Force exit regardless
        sys.exit(0)


if __name__ == '__main__':
    main()
