#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import gc
from ..util.color import Color
from ..config import Configuration


class MemoryMonitor:
    """Memory monitoring and optimization utilities"""

    @staticmethod
    def get_memory_usage():
        """Get current memory usage in MB"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except ImportError:
            # Fallback method using /proc/self/status on Linux
            try:
                with open('/proc/self/status', 'r') as f:
                    for line in f:
                        if line.startswith('VmRSS:'):
                            # Extract memory in kB and convert to MB
                            mem_kb = int(line.split()[1])
                            return mem_kb / 1024
            except (OSError, IOError, ValueError):
                pass
        return None

    @staticmethod
    def check_memory_usage(threshold_mb=500):
        """Check if memory usage exceeds threshold and warn user"""
        memory_mb = MemoryMonitor.get_memory_usage()
        if memory_mb and memory_mb > threshold_mb:
            if Configuration.verbose > 0:
                Color.pl('{!} {O}Memory usage: {R}%.1f MB{W} (threshold: %d MB)' % (memory_mb, threshold_mb))
            return True
        return False

    @staticmethod
    def force_cleanup():
        """Force garbage collection and memory cleanup"""
        # Clear any large temporary data structures
        gc.collect()

        # Clean up configuration cache
        Configuration.cleanup_memory()

        if Configuration.verbose > 1:
            memory_after = MemoryMonitor.get_memory_usage()
            if memory_after:
                Color.pl('{+} {G}Memory cleanup completed{W}: %.1f MB' % memory_after)

    @staticmethod
    def periodic_check(counter, check_interval=100):
        """Perform periodic memory checks and cleanup"""
        if counter % check_interval == 0:
            if MemoryMonitor.check_memory_usage():
                MemoryMonitor.force_cleanup()
                return True
        return False
