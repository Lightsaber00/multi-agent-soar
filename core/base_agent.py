"""
Multi-Agent SOAR - Base Agent
Basisklasse für alle SOAR-Agenten
"""
from __future__ import annotations
import logging
import threading
import queue
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import AgentMessage
from .store import get_store


logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstrakte Basisklasse für alle SOAR-Agenten"""

    def __init__(self, name: str, description: str = ""):
        self.name        = name
        self.description = description
        self.store       = get_store()
        self._inbox: queue.Queue[AgentMessage] = queue.Queue()
        self._running    = False
        self._thread: Optional[threading.Thread] = None
        self._agent_registry: Dict[str, "BaseAgent"] = {}
        self.logger = logging.getLogger(f"soar.agent.{name}")

    # ─────────────────────────────────────────────────────────
    #  Lifecycle
    # ─────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, name=f"agent-{self.name}", daemon=True
        )
        self._thread.start()
        self.logger.info(f"Agent '{self.name}' gestartet.")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info(f"Agent '{self.name}' gestoppt.")

    def _run_loop(self):
        while self._running:
            try:
                msg = self._inbox.get(timeout=1.0)
                self._handle_message(msg)
            except queue.Empty:
                pass
            except Exception as e:
                self.logger.error(f"Fehler in Message Loop: {e}", exc_info=True)

    # ─────────────────────────────────────────────────────────
    #  Messaging
    # ─────────────────────────────────────────────────────────

    def register_agents(self, registry: Dict[str, "BaseAgent"]):
        """Registriert alle bekannten Agenten"""
        self._agent_registry = registry

    def receive(self, message: AgentMessage):
        """Eingehende Nachricht in Inbox legen"""
        self._inbox.put(message)

    def send(self, recipient: str, message_type: str,
             payload: Dict[str, Any], correlation_id: str = ""):
        """Sendet Nachricht an anderen Agenten"""
        msg = AgentMessage(
            sender=self.name,
            recipient=recipient,
            message_type=message_type,
            payload=payload,
            correlation_id=correlation_id
        )
        if recipient == "broadcast":
            for agent in self._agent_registry.values():
                if agent.name != self.name:
                    agent.receive(msg)
        elif recipient in self._agent_registry:
            self._agent_registry[recipient].receive(msg)
        else:
            self.logger.warning(f"Unbekannter Empfänger: {recipient}")

    def _handle_message(self, msg: AgentMessage):
        """Verarbeitet eingehende Nachricht"""
        msg.processed = True
        self.logger.debug(f"Nachricht von '{msg.sender}': {msg.message_type}")
        self.handle_message(msg)

    # ─────────────────────────────────────────────────────────
    #  Abstract Methods
    # ─────────────────────────────────────────────────────────

    @abstractmethod
    def handle_message(self, message: AgentMessage):
        """Muss von Unterklassen implementiert werden"""
        ...

    # ─────────────────────────────────────────────────────────
    #  Utility
    # ─────────────────────────────────────────────────────────

    def log_action(self, action: str, details: str = "", data: Dict = None):
        self.logger.info(f"[{self.name}] {action}: {details}")

    def __repr__(self):
        return f"<Agent: {self.name}>"
