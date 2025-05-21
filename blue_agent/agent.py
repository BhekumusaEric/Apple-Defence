"""
Blue Agent Core Module

This module defines the core functionality of the Blue Agent, which is responsible
for learning from the Red Agent's exploits and implementing security fixes.
"""

import logging
from typing import Dict, List, Any, Optional
import time

from shared.communication import MessageBus
from blue_agent.monitoring.monitor import SecurityMonitor
from blue_agent.analysis.analyzer import ThreatAnalyzer
from blue_agent.mitigation.patcher import SecurityPatcher

logger = logging.getLogger(__name__)

class BlueAgent:
    """
    The Blue Agent is a defensive security AI that learns from the Red Agent's
    exploits and implements fixes to secure iOS systems.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Blue Agent with configuration parameters.
        
        Args:
            config: Configuration dictionary for the Blue Agent
        """
        self.config = config
        self.message_bus = MessageBus()
        self.monitor = SecurityMonitor(config.get("monitor_config", {}))
        self.analyzer = ThreatAnalyzer(config.get("analyzer_config", {}))
        self.patcher = SecurityPatcher(config.get("patcher_config", {}))
        self.active = False
        self.known_vulnerabilities = []
        self.applied_patches = []
        
        # Subscribe to Red Agent messages
        self.message_bus.subscribe("vulnerability_discovered", self._handle_vulnerability)
        self.message_bus.subscribe("exploitation_result", self._handle_exploitation)
        
        logger.info("Blue Agent initialized with configuration: %s", config)
    
    def start(self) -> None:
        """Start the Blue Agent's operations."""
        self.active = True
        self.monitor.start()
        logger.info("Blue Agent started")
        
    def stop(self) -> None:
        """Stop the Blue Agent's operations."""
        self.active = False
        self.monitor.stop()
        logger.info("Blue Agent stopped")
    
    def _handle_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """
        Handle a vulnerability discovered by the Red Agent.
        
        Args:
            vulnerability: Information about the discovered vulnerability
        """
        logger.info("Received vulnerability: %s", vulnerability.get("id"))
        
        # Add to known vulnerabilities if not already known
        if vulnerability not in self.known_vulnerabilities:
            self.known_vulnerabilities.append(vulnerability)
        
        # Analyze the vulnerability
        analysis_result = self.analyzer.analyze(vulnerability)
        
        # Determine if a patch is needed
        if analysis_result.get("severity", 0) > self.config.get("patch_threshold", 5):
            self._develop_patch(vulnerability, analysis_result)
    
    def _handle_exploitation(self, exploitation_data: Dict[str, Any]) -> None:
        """
        Handle an exploitation result from the Red Agent.
        
        Args:
            exploitation_data: Information about the exploitation attempt
        """
        vulnerability_id = exploitation_data.get("vulnerability_id")
        result = exploitation_data.get("result", {})
        
        logger.info("Received exploitation result for vulnerability %s: %s", 
                   vulnerability_id, "Success" if result.get("success") else "Failure")
        
        # Update vulnerability information with exploitation results
        for vuln in self.known_vulnerabilities:
            if vuln.get("id") == vulnerability_id:
                vuln["exploited"] = result.get("success", False)
                vuln["exploitation_details"] = result
                break
        
        # If exploitation was successful, prioritize patching
        if result.get("success", False):
            vulnerability = next((v for v in self.known_vulnerabilities 
                                if v.get("id") == vulnerability_id), None)
            if vulnerability:
                analysis_result = self.analyzer.analyze(vulnerability)
                self._develop_patch(vulnerability, analysis_result, priority="high")
    
    def _develop_patch(self, vulnerability: Dict[str, Any], 
                      analysis_result: Dict[str, Any],
                      priority: str = "normal") -> None:
        """
        Develop a security patch for a vulnerability.
        
        Args:
            vulnerability: Information about the vulnerability
            analysis_result: Analysis of the vulnerability
            priority: Priority level for the patch development
        """
        logger.info("Developing patch for vulnerability %s with priority %s", 
                   vulnerability.get("id"), priority)
        
        # Generate patch
        patch = self.patcher.generate_patch(vulnerability, analysis_result)
        
        if patch:
            # Apply the patch
            application_result = self.patcher.apply_patch(patch)
            
            if application_result.get("success", False):
                logger.info("Successfully applied patch for vulnerability %s", 
                           vulnerability.get("id"))
                self.applied_patches.append({
                    "vulnerability_id": vulnerability.get("id"),
                    "patch": patch,
                    "timestamp": time.time(),
                    "result": application_result
                })
                
                # Notify about the patch
                self.message_bus.publish("patch_applied", {
                    "vulnerability_id": vulnerability.get("id"),
                    "patch_id": patch.get("id"),
                    "success": True
                })
            else:
                logger.error("Failed to apply patch for vulnerability %s: %s", 
                            vulnerability.get("id"), application_result.get("error"))
                
                # Notify about the failure
                self.message_bus.publish("patch_applied", {
                    "vulnerability_id": vulnerability.get("id"),
                    "patch_id": patch.get("id"),
                    "success": False,
                    "error": application_result.get("error")
                })
        else:
            logger.error("Failed to generate patch for vulnerability %s", 
                        vulnerability.get("id"))
    
    def get_security_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive security report.
        
        Returns:
            Security report with vulnerabilities and patches
        """
        return {
            "vulnerabilities": {
                "total": len(self.known_vulnerabilities),
                "patched": len(self.applied_patches),
                "unpatched": len(self.known_vulnerabilities) - len(self.applied_patches),
                "details": self.known_vulnerabilities
            },
            "patches": {
                "total": len(self.applied_patches),
                "details": self.applied_patches
            },
            "timestamp": time.time()
        }
