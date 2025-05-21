#!/usr/bin/env python3
"""
Apple-Defence Main Module

This is the main entry point for the Apple-Defence system, which coordinates
the Red and Blue Agents for iOS security.
"""

import argparse
import logging
import sys
import time
import yaml
import json
from typing import Dict, Any

from red_agent.agent import RedAgent
from blue_agent.agent import BlueAgent
from shared.communication import MessageBus

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('apple_defence.log')
    ]
)

logger = logging.getLogger(__name__)

def load_config(config_file: str) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        Configuration dictionary
    """
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        logger.info("Loaded configuration from %s", config_file)
        return config
    except Exception as e:
        logger.error("Failed to load configuration from %s: %s", config_file, e)
        return {}

def save_report(report: Dict[str, Any], report_file: str) -> None:
    """
    Save a report to a JSON file.
    
    Args:
        report: Report data
        report_file: Path to the report file
    """
    try:
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info("Saved report to %s", report_file)
    except Exception as e:
        logger.error("Failed to save report to %s: %s", report_file, e)

def main():
    """Main entry point for the Apple-Defence system."""
    parser = argparse.ArgumentParser(description='Apple-Defence: Red and Blue Agent Twin Security System for iOS')
    parser.add_argument('--config', default='config.yaml', help='Path to configuration file')
    parser.add_argument('--report', default='security_report.json', help='Path to output report file')
    parser.add_argument('--duration', type=int, default=60, help='Duration to run in seconds')
    parser.add_argument('--target', default='{"ios_version": "15.0", "device_type": "iPhone", "name": "Test Device"}', 
                        help='Target device information as JSON string')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Parse target information
    try:
        target = json.loads(args.target)
    except json.JSONDecodeError:
        logger.error("Invalid target JSON: %s", args.target)
        target = {"ios_version": "15.0", "device_type": "iPhone", "name": "Test Device"}
    
    # Initialize message bus (singleton)
    message_bus = MessageBus()
    
    # Initialize agents
    red_agent = RedAgent(config.get('red_agent', {}))
    blue_agent = BlueAgent(config.get('blue_agent', {}))
    
    try:
        # Start agents
        logger.info("Starting Apple-Defence system")
        blue_agent.start()
        red_agent.start()
        
        # Run the system for the specified duration
        logger.info("Running for %d seconds", args.duration)
        
        # Scan for vulnerabilities
        red_agent.scan_for_vulnerabilities(target)
        
        # Wait for the specified duration
        time.sleep(args.duration)
        
        # Generate security report
        report = blue_agent.get_security_report()
        save_report(report, args.report)
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error("Error in main loop: %s", e)
    finally:
        # Stop agents
        logger.info("Stopping Apple-Defence system")
        red_agent.stop()
        blue_agent.stop()
        message_bus.stop()

if __name__ == '__main__':
    main()
