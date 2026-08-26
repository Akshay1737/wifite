#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from wifite.tools.airodump import Airodump
from wifite.model.target import Target


def make_target(privacy='WPA2', auth='PSK'):
    """Helper: builds a Target directly from airodump-ng CSV-style fields."""
    fields = ('AA:BB:CC:DD:EE:FF,2015-05-27 19:28:44,2015-05-27 19:28:46,'
              f'1,54,{privacy},CCMP TKIP,{auth},-58,2,0,0.0.0.0,9,HOME-ABCD,').split(',')
    return Target(fields)


class TestTarget(unittest.TestCase):
    """ Test suite for Target parsing an generation """
    airodump_csv = 'airodump.csv'

    def getTargets(self, filename):
        """ Helper method to parse targets from filename """
        import os
        import inspect
        this_file = os.path.abspath(inspect.getsourcefile(TestTarget.getTargets))
        this_dir = os.path.dirname(this_file)
        csv_file = os.path.join(this_dir, 'files', filename)
        # Load targets from CSV file
        return Airodump.get_targets_from_csv(csv_file)

    def testTargetParsing(self):
        """ Asserts target parsing finds targets """
        targets = self.getTargets(TestTarget.airodump_csv)
        assert(len(targets) > 0)

    def testTargetClients(self):
        """ Asserts target parsing captures clients properly """
        targets = self.getTargets(TestTarget.airodump_csv)
        for t in targets:
            if t.bssid == '00:1D:D5:9B:11:00':
                assert(len(t.clients) > 0)


class TestWpa3Support(unittest.TestCase):
    """ Tests for WPA3 / transition-mode detection added for WPA3 compatibility """

    def testWpa3OnlyParsing(self):
        t = make_target(privacy='WPA3', auth='SAE')
        assert t.primary_encryption == 'WPA3'
        assert t.primary_authentication == 'SAE'
        assert t.is_wpa3_only is True
        assert t.is_transition_mode is False

    def testTransitionModeParsing(self):
        t = make_target(privacy='WPA2 WPA3', auth='PSK SAE')
        assert t.primary_encryption == 'WPA3'
        assert t.is_transition_mode is True
        assert t.is_wpa3_only is False

    def testWpa2UnaffectedByWpa3Flags(self):
        t = make_target(privacy='WPA2', auth='PSK')
        assert t.primary_encryption == 'WPA2'
        assert t.primary_authentication == 'PSK'
        assert t.is_transition_mode is False
        assert t.is_wpa3_only is False

    def testWpa3OnlyDisplayDoesNotCrash(self):
        s = make_target(privacy='WPA3', auth='SAE').to_str()
        assert isinstance(s, str) and len(s) > 0

    def testTransitionModeDisplayDoesNotCrash(self):
        s = make_target(privacy='WPA2 WPA3', auth='PSK SAE').to_str()
        assert isinstance(s, str) and len(s) > 0


if __name__ == '__main__':
    unittest.main()
