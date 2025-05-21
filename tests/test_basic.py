#!/usr/bin/env python3
"""
Basic tests for the Apple-Defence system.

This module contains basic tests to verify that the core components
of the Apple-Defence system are working correctly.
"""

import unittest
import sys
import os
import json
import time

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from red_agent.agent import RedAgent
from blue_agent.agent import BlueAgent
from shared.communication import MessageBus
from red_agent.discovery.scanner import VulnerabilityScanner
from blue_agent.analysis.analyzer import ThreatAnalyzer
from blue_agent.mitigation.patcher import SecurityPatcher

class TestBasicFunctionality(unittest.TestCase):
    """Test basic functionality of the Apple-Defence system."""

    def setUp(self):
        """Set up test fixtures."""
        self.message_bus = MessageBus()
        self.red_agent = RedAgent({})
        self.blue_agent = BlueAgent({})
        self.target = {
            "ios_version": "15.0",
            "device_type": "iPhone",
            "name": "Test Device"
        }

    def tearDown(self):
        """Tear down test fixtures."""
        self.red_agent.stop()
        self.blue_agent.stop()
        self.message_bus.stop()

    def test_red_agent_initialization(self):
        """Test that the Red Agent initializes correctly."""
        self.assertIsNotNone(self.red_agent)
        self.assertFalse(self.red_agent.active)

    def test_blue_agent_initialization(self):
        """Test that the Blue Agent initializes correctly."""
        self.assertIsNotNone(self.blue_agent)
        self.assertFalse(self.blue_agent.active)

    def test_message_bus(self):
        """Test that the Message Bus works correctly."""
        test_message = {"test": "message"}
        received_message = None

        def message_handler(message):
            nonlocal received_message
            received_message = message

        self.message_bus.subscribe("test_topic", message_handler)

        # Use the synchronous publish method for testing
        self.message_bus.publish_sync("test_topic", test_message)

        self.assertEqual(received_message, test_message)

    def test_vulnerability_scanner(self):
        """Test that the Vulnerability Scanner works correctly."""
        scanner = VulnerabilityScanner({})
        vulnerabilities = scanner.scan(self.target)

        self.assertIsInstance(vulnerabilities, list)
        self.assertTrue(len(vulnerabilities) > 0)

        for vuln in vulnerabilities:
            self.assertIn("id", vuln)
            self.assertIn("type", vuln)
            self.assertIn("severity", vuln)

    def test_threat_analyzer(self):
        """Test that the Threat Analyzer works correctly."""
        scanner = VulnerabilityScanner({})
        vulnerabilities = scanner.scan(self.target)

        analyzer = ThreatAnalyzer({})

        for vuln in vulnerabilities:
            analysis = analyzer.analyze(vuln)

            self.assertIsInstance(analysis, dict)
            self.assertIn("severity", analysis)
            self.assertIn("impact", analysis)
            self.assertIn("potential_mitigations", analysis)

    def test_security_patcher(self):
        """Test that the Security Patcher works correctly."""
        scanner = VulnerabilityScanner({})
        vulnerabilities = scanner.scan(self.target)

        analyzer = ThreatAnalyzer({})
        patcher = SecurityPatcher({})

        for vuln in vulnerabilities:
            analysis = analyzer.analyze(vuln)
            patch = patcher.generate_patch(vuln, analysis)

            if patch:
                self.assertIsInstance(patch, dict)
                self.assertIn("id", patch)
                self.assertIn("vulnerability_id", patch)
                self.assertIn("code", patch)

                result = patcher.apply_patch(patch)
                self.assertIsInstance(result, dict)
                self.assertIn("success", result)

    def test_red_agent_scan(self):
        """Test that the Red Agent can scan for vulnerabilities."""
        vulnerabilities = self.red_agent.scan_for_vulnerabilities(self.target)

        self.assertIsInstance(vulnerabilities, list)
        self.assertTrue(len(vulnerabilities) > 0)

    def test_blue_agent_report(self):
        """Test that the Blue Agent can generate a security report."""
        report = self.blue_agent.get_security_report()

        self.assertIsInstance(report, dict)
        self.assertIn("vulnerabilities", report)
        self.assertIn("patches", report)
        self.assertIn("timestamp", report)

if __name__ == '__main__':
    unittest.main()
