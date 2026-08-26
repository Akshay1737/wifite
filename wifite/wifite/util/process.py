#!/usr/bin/env python
# -*- coding: utf-8 -*-

import contextlib
import time
import signal
import os
import atexit
import threading
import subprocess
from subprocess import Popen, PIPE
from ..util.color import Color
from ..config import Configuration


class ProcessManager:
    """Global process manager to track and cleanup all processes"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._processes = set()
                    cls._instance._registered_cleanup = False
        return cls._instance

    def register_process(self, process):
        """Register a process for cleanup tracking"""
        with self._lock:
            # Limit total tracked processes to prevent resource exhaustion
            if len(self._processes) > 50:  # Reasonable limit
                # Clean up finished processes first
                finished_processes = {p for p in self._processes if hasattr(p, 'is_running') and not p.is_running()}
                self._processes -= finished_processes

                # If still too many, force cleanup of oldest
                if len(self._processes) > 50:
                    oldest_processes = list(self._processes)[:10]  # Remove oldest 10
                    for p in oldest_processes:
                        try:
                            p.force_kill()
                        except:
                            pass
                    self._processes -= set(oldest_processes)

            self._processes.add(process)
            if not self._registered_cleanup:
                atexit.register(self.cleanup_all)
                self._registered_cleanup = True

    def unregister_process(self, process):
        """Unregister a process (when it's properly cleaned up)"""
        with self._lock:
            self._processes.discard(process)

    def cleanup_all(self):
        """Emergency cleanup of all tracked processes"""
        with self._lock:
            for process in list(self._processes):
                try:
                    if process.pid and process.pid.poll() is None:
                        process.force_kill()
                except:
                    pass  # Ignore errors during emergency cleanup
            self._processes.clear()


class Process(object):
    """ Represents a running/ran process with enhanced cleanup """

    @staticmethod
    def devnull():
        """ Helper method for opening devnull """
        return open('/dev/null', 'w')

    @staticmethod
    def call(command, cwd=None, shell=False):
        """
            Calls a command (either string or list of args).
            Returns tuple:
                (stdout, stderr)
        """
        if type(command) is not str or ' ' in command or shell:
            shell = True
            if Configuration.verbose > 1:
                Color.pe('\n {C}[?] {W} Executing (Shell): {B}%s{W}' % command)
        else:
            shell = False
            if Configuration.verbose > 1:
                Color.pe('\n {C}[?]{W} Executing: {B}%s{W}' % command)

        pid = Popen(command, cwd=cwd, stdout=PIPE, stderr=PIPE, shell=shell)
        pid.wait()
        (stdout, stderr) = pid.communicate()

        # Python 3 compatibility
        if type(stdout) is bytes:
            stdout = stdout.decode('utf-8')
        if type(stderr) is bytes:
            stderr = stderr.decode('utf-8')

        if Configuration.verbose > 1 and stdout is not None and stdout.strip() != '':
            Color.pe('{P} [stdout] %s{W}' % '\n [stdout] '.join(stdout.strip().split('\n')))
        if Configuration.verbose > 1 and stderr is not None and stderr.strip() != '':
            Color.pe('{P} [stderr] %s{W}' % '\n [stderr] '.join(stderr.strip().split('\n')))

        return stdout, stderr

    @staticmethod
    def exists(program):
        """ Checks if program is installed on this system """

        if Configuration.initialized and program in set(Configuration.existing_commands.keys()):
            return Configuration.existing_commands[program]

        p2 = Process(['which', program])
        stdout = p2.stdout().strip()
        stderr = p2.stderr().strip()

        exist = not stdout == stderr == ''
        if Configuration.initialized:
            Configuration.existing_commands.update({program: exist})
        return exist

    def __init__(self, command, devnull=False, stdout=PIPE, stderr=PIPE, cwd=None, bufsize=0, stdin=PIPE):
        """ Starts executing command """

        if type(command) is str:
            # Commands have to be a list
            command = command.split(' ')

        self.command = command
        self._cleaned_up = False
        self._manager = ProcessManager()

        if Configuration.verbose > 1:
            Color.pe('\n {C}[?] {W} Executing: {B}%s{W}' % ' '.join(command))

        self.out = None
        self.err = None
        if devnull:
            sout = Process.devnull()
            serr = Process.devnull()
        else:
            sout = stdout
            serr = stderr

        self.start_time = time.time()

        # Add file descriptor limit checking
        try:
            self.pid = Popen(command, stdout=sout, stderr=serr, stdin=stdin, cwd=cwd, bufsize=bufsize)
        except OSError as e:
            if e.errno == 24:  # Too many open files
                # Force cleanup of zombie processes and try again
                ProcessManager().cleanup_all()
                Process.cleanup_zombies()
                time.sleep(0.1)  # Brief pause
                try:
                    self.pid = Popen(command, stdout=sout, stderr=serr, stdin=stdin, cwd=cwd, bufsize=bufsize)
                except OSError as e2:
                    if e2.errno == 24:
                        raise OSError("Too many open files - system resource exhausted. Try reducing concurrent attacks.") from e2
                    raise
            else:
                raise

        # Register with process manager for cleanup tracking
        self._manager.register_process(self)

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup"""
        self.cleanup()

    def __del__(self):
        """
            Ran when object is GC'd.
            If process is still running at this point, it should die.
        """
        self.cleanup()

    def stdout(self):
        """ Waits for process to finish, returns stdout output """
        self.get_output()
        if Configuration.verbose > 1 and self.out is not None and self.out.strip() != '':
            Color.pe('{P} [stdout] %s{W}' % '\n [stdout] '.join(self.out.strip().split('\n')))
        return self.out

    def stderr(self):
        """ Waits for process to finish, returns stderr output """
        self.get_output()
        if Configuration.verbose > 1 and self.err is not None and self.err.strip() != '':
            Color.pe('{P} [stderr] %s{W}' % '\n [stderr] '.join(self.err.strip().split('\n')))
        return self.err

    def stdoutln(self):
        return self.pid.stdout.readline()

    def stderrln(self):
        return self.pid.stderr.readline()

    def stdin(self, text):
        if self.pid.stdin:
            self.pid.stdin.write(text.encode('utf-8'))
            self.pid.stdin.flush()

    def get_output(self):
        """ Waits for process to finish, sets stdout & stderr """
        if self.pid.poll() is None:
            try:
                self.pid.wait(timeout=30)  # 30 second timeout
            except subprocess.TimeoutExpired:
                # Force kill if process doesn't finish in time
                self.force_kill()
        if self.out is None:
            try:
                (self.out, self.err) = self.pid.communicate(timeout=10)  # 10 second timeout
            except subprocess.TimeoutExpired:
                # Force kill and get partial output
                self.force_kill()
                (self.out, self.err) = self.pid.communicate()

        if type(self.out) is bytes:
            self.out = self.out.decode('utf-8')

        if type(self.err) is bytes:
            self.err = self.err.decode('utf-8')

        # Limit output size to prevent memory bloat
        max_output_size = 1024 * 1024  # 1MB limit
        if self.out and len(self.out) > max_output_size:
            self.out = self.out[-max_output_size:] + "\n[... output truncated ...]"
        if self.err and len(self.err) > max_output_size:
            self.err = self.err[-max_output_size:] + "\n[... error output truncated ...]"

        return self.out, self.err

    def poll(self):
        """ Returns exit code if process is dead, otherwise 'None' """
        return self.pid.poll()

    def wait(self):
        self.pid.wait()

    def running_time(self):
        """ Returns number of seconds since process was started """
        return int(time.time() - self.start_time)

    def cleanup(self):
        """Properly cleanup the process"""
        if getattr(self, '_cleaned_up', False):
            return

        try:
            if hasattr(self, 'pid') and self.pid and self.pid.poll() is None:
                self.interrupt()
        except:
            pass  # Ignore errors during cleanup
        finally:
            self._cleaned_up = True
            # Use try-except for manager cleanup to handle shutdown scenarios
            try:
                if hasattr(self, '_manager'):
                    self._manager.unregister_process(self)
            except:
                pass  # Ignore errors during shutdown

    def interrupt(self, wait_time=2.0):
        """
            Send interrupt to current process.
            If process fails to exit within `wait_time` seconds, terminates it.
        """
        if not hasattr(self, 'pid') or not self.pid:
            return

        try:
            self._graceful_shutdown(wait_time)
        except OSError as e:
            if 'No such process' in str(e):
                return
            # Process might be in zombie state, try to clean it up
            try:
                self.pid.wait()
            except:
                pass

    def _graceful_shutdown(self, wait_time):
        """Attempt graceful shutdown with escalating signals"""
        if self.pid.poll() is not None:
            return  # Already dead

        pid = self.pid.pid
        cmd = ' '.join(self.command) if isinstance(self.command, list) else str(self.command)

        if Configuration.verbose > 1:
            Color.pe('\n {C}[?] {W} sending interrupt to PID %d (%s)' % (pid, cmd))

        # Step 1: Try SIGINT (graceful)
        try:
            os.kill(pid, signal.SIGINT)
        except OSError:
            return  # Process already dead

        # Wait for graceful shutdown
        start_time = time.time()
        while self.pid.poll() is None and (time.time() - start_time) < wait_time:
            try:
                time.sleep(0.1)
            except KeyboardInterrupt:
                break  # User wants to abort

        # Step 2: Try SIGTERM if still running
        if self.pid.poll() is None:
            if Configuration.verbose > 1:
                Color.pe('\n {C}[?] {W} Process still running, sending SIGTERM to PID %d' % pid)
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(1.0)  # Give it a moment
            except OSError:
                pass

        # Step 3: Force kill with SIGKILL if still running
        if self.pid.poll() is None:
            if Configuration.verbose > 1:
                Color.pe('\n {C}[?] {W} Force killing PID %d' % pid)
            try:
                os.kill(pid, signal.SIGKILL)
                self.pid.kill()
            except OSError:
                pass

        # Final cleanup
        try:
            self.pid.wait()
        except:
            pass

    def force_kill(self):
        """Force kill the process immediately"""
        if not hasattr(self, 'pid') or not self.pid:
            return

        try:
            if self.pid.poll() is None:
                self.pid.kill()
                self.pid.wait()
        except:
            pass

    def is_running(self):
        """Check if process is still running"""
        return hasattr(self, 'pid') and self.pid and self.pid.poll() is None

    @staticmethod
    def cleanup_zombies():
        """Clean up any zombie processes"""
        try:
            # Reap any zombie children
            while True:
                try:
                    pid, status = os.waitpid(-1, os.WNOHANG)
                    if pid == 0:
                        break
                    if Configuration.verbose > 2:
                        Color.pe(f'\n {{C}}[?]{{W}} Reaped zombie process PID {pid}')
                except OSError:
                    break
        except:
            pass

    @staticmethod
    def get_open_fd_count():
        """Get current number of open file descriptors"""
        try:
            import os
            proc_fd_dir = f'/proc/{os.getpid()}/fd'
            if os.path.exists(proc_fd_dir):
                return len(os.listdir(proc_fd_dir))
        except:
            pass
        return -1

    @staticmethod
    def check_fd_limit():
        """Check if we're approaching file descriptor limits"""
        try:
            import resource
            soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
            current_fds = Process.get_open_fd_count()

            if current_fds > 0 and current_fds > (soft_limit * 0.8):  # 80% of limit
                Color.pl(f'\n{{!}} {{O}}Warning: High file descriptor usage ({current_fds}/{soft_limit}){{W}}')
                ProcessManager().cleanup_all()
                Process.cleanup_zombies()
                return True
        except:
            pass
        return False


if __name__ == '__main__':
    Configuration.initialize(False)
    p = Process('ls')
    print((p.stdout()))
    print((p.stderr()))
    p.interrupt()

    # Calling as list of arguments
    (out, err) = Process.call(['ls', '-lah'])
    print(out)
    print(err)

    print('\n---------------------\n')

    # Calling as string
    (out, err) = Process.call('ls -l | head -2')
    print(out)
    print(err)

    print(f""""reaver" exists: {Process.exists('reaver')}""")

    # Test on never-ending process
    p = Process('yes')
    print('Running yes...')
    time.sleep(1)
    print('yes should stop now')
    # After program loses reference to instance in 'p', process dies.
