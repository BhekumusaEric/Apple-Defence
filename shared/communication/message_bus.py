"""
Message Bus Module

This module provides a publish-subscribe messaging system for communication
between the Red and Blue Agents.
"""

import logging
from typing import Dict, List, Any, Callable
import threading
import queue
import time

logger = logging.getLogger(__name__)

class MessageBus:
    """
    A simple publish-subscribe message bus for inter-agent communication.

    This implementation uses a thread-safe approach with queues to handle
    asynchronous message processing.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Implement as a singleton to ensure all components use the same bus."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MessageBus, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        """Initialize the message bus if not already initialized."""
        if self._initialized:
            return

        self._subscribers = {}
        self._message_queue = queue.Queue()
        self._running = False
        self._worker_thread = None
        self._initialized = True

        logger.info("Message Bus initialized")

        # Start the message processing thread
        self.start()

    def start(self):
        """Start the message processing thread."""
        if self._running:
            return

        self._running = True
        self._worker_thread = threading.Thread(target=self._process_messages)
        self._worker_thread.daemon = True
        self._worker_thread.start()

        logger.info("Message Bus started")

    def stop(self):
        """Stop the message processing thread."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=1.0)
            self._worker_thread = None

        logger.info("Message Bus stopped")

    def subscribe(self, topic: str, callback: Callable[[Any], None]) -> None:
        """
        Subscribe to a topic.

        Args:
            topic: The topic to subscribe to
            callback: Function to call when a message is published to the topic
        """
        if topic not in self._subscribers:
            self._subscribers[topic] = []

        if callback not in self._subscribers[topic]:
            self._subscribers[topic].append(callback)
            logger.debug("Subscribed to topic: %s", topic)

    def unsubscribe(self, topic: str, callback: Callable[[Any], None]) -> None:
        """
        Unsubscribe from a topic.

        Args:
            topic: The topic to unsubscribe from
            callback: The callback function to remove
        """
        if topic in self._subscribers and callback in self._subscribers[topic]:
            self._subscribers[topic].remove(callback)
            logger.debug("Unsubscribed from topic: %s", topic)

            if not self._subscribers[topic]:
                del self._subscribers[topic]

    def publish(self, topic: str, message: Any) -> None:
        """
        Publish a message to a topic.

        Args:
            topic: The topic to publish to
            message: The message to publish
        """
        self._message_queue.put((topic, message))
        logger.debug("Published message to topic: %s", topic)

    def _process_messages(self) -> None:
        """Process messages from the queue and dispatch to subscribers."""
        while self._running:
            try:
                # Get a message from the queue with a timeout to allow checking _running
                try:
                    topic, message = self._message_queue.get(timeout=0.1)
                except queue.Empty:
                    continue

                # Dispatch the message to all subscribers
                if topic in self._subscribers:
                    for callback in self._subscribers[topic]:
                        try:
                            callback(message)
                        except Exception as e:
                            logger.error("Error in subscriber callback for topic %s: %s", topic, e)

                # Mark the task as done
                self._message_queue.task_done()

            except Exception as e:
                logger.error("Error processing message: %s", e)
                time.sleep(0.1)  # Avoid tight loop in case of persistent errors

    def publish_sync(self, topic: str, message: Any) -> None:
        """
        Publish a message to a topic and process it synchronously.

        This is useful for testing when you need to ensure the message
        is processed immediately.

        Args:
            topic: The topic to publish to
            message: The message to publish
        """
        if topic in self._subscribers:
            for callback in self._subscribers[topic]:
                try:
                    callback(message)
                except Exception as e:
                    logger.error("Error in subscriber callback for topic %s: %s", topic, e)
