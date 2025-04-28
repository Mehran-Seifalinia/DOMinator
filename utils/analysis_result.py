"""
Analysis Result Module
Defines data structures and methods for storing and managing analysis results.
"""

from typing import List, Dict, Optional, TypedDict, Any
from dataclasses import dataclass
from datetime import datetime

class Occurrence(TypedDict):
    """
    Type definition for a vulnerability occurrence.
    
    Attributes:
        line (Optional[int]): Line number where the occurrence was found
        column (Optional[int]): Column number where the occurrence was found
        pattern (str): The pattern that was matched
        context (str): Context around the occurrence
        risk_level (str): Risk level of the occurrence
        priority (str): Priority level of the occurrence
        source (str): Source of the occurrence ('static', 'dynamic', or 'event_handler')
    """
    line: Optional[int]
    column: Optional[int]
    pattern: str
    context: str
    risk_level: str
    priority: str
    source: str

@dataclass
class EventHandler:
    """
    Data class for storing event handler information.
    
    Attributes:
        tag (str): HTML tag containing the event handler
        attribute (str): Event handler attribute name
        handler (str): Event handler code
        line (Optional[int]): Line number where the handler was found
        column (Optional[int]): Column number where the handler was found
        risk_level (str): Risk level of the handler
        priority (str): Priority level of the handler
    """
    tag: str
    attribute: str
    handler: str
    line: Optional[int] = None
    column: Optional[int] = None
    risk_level: str = 'unknown'
    priority: str = 'unknown'

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event handler to a dictionary.
        
        Returns:
            Dict[str, Any]: Dictionary representation of the event handler
        """
        return {
            'tag': self.tag,
            'attribute': self.attribute,
            'handler': self.handler,
            'line': self.line,
            'column': self.column,
            'risk_level': self.risk_level,
            'priority': self.priority
        }

class AnalysisResult:
    """
    A class for storing and managing analysis results.
    
    This class provides methods to store and retrieve various types of
    analysis results, including static and dynamic occurrences, event
    handlers, and external script risks.
    """
    
    def __init__(self) -> None:
        """Initialize an empty analysis result."""
        self.static_occurrences: List[Occurrence] = []
        self.dynamic_occurrences: List[Occurrence] = []
        self.event_handlers: Dict[str, List[EventHandler]] = {}
        self.external_script_risks: List[Occurrence] = []
        self.analysis_time: datetime = datetime.now()
        self.url: Optional[str] = None
        self.status: str = 'pending'  # 'pending', 'completed', 'error'
        self.error_message: Optional[str] = None

    def add_static_occurrence(self, occurrence: Occurrence) -> None:
        """
        Add a static analysis occurrence.
        
        Args:
            occurrence (Occurrence): The occurrence to add
        """
        occurrence['source'] = 'static'
        self.static_occurrences.append(occurrence)

    def add_dynamic_occurrence(self, occurrence: Occurrence) -> None:
        """
        Add a dynamic analysis occurrence.
        
        Args:
            occurrence (Occurrence): The occurrence to add
        """
        occurrence['source'] = 'dynamic'
        self.dynamic_occurrences.append(occurrence)

    def add_event_handler(self, event_type: str, handler: EventHandler) -> None:
        """
        Add an event handler.
        
        Args:
            event_type (str): Type of the event
            handler (EventHandler): The event handler to add
        """
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)

    def add_external_script_risk(self, occurrence: Occurrence) -> None:
        """
        Add an external script risk.
        
        Args:
            occurrence (Occurrence): The occurrence to add
        """
        occurrence['source'] = 'external'
        self.external_script_risks.append(occurrence)

    def set_error(self, error_message: str) -> None:
        """
        Set the analysis result to error state.
        
        Args:
            error_message (str): Error message to set
        """
        self.status = 'error'
        self.error_message = error_message

    def set_completed(self) -> None:
        """Set the analysis result to completed state."""
        self.status = 'completed'

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the analysis result to a dictionary.
        
        Returns:
            Dict[str, Any]: Dictionary representation of the analysis result
        """
        return {
            'static_occurrences': self.static_occurrences,
            'dynamic_occurrences': self.dynamic_occurrences,
            'event_handlers': {
                event_type: [handler.to_dict() for handler in handlers]
                for event_type, handlers in self.event_handlers.items()
            },
            'external_script_risks': self.external_script_risks,
            'analysis_time': self.analysis_time.isoformat(),
            'url': self.url,
            'status': self.status,
            'error_message': self.error_message
        }

    def get_all_occurrences(self) -> List[Occurrence]:
        """
        Get all occurrences from all sources.
        
        Returns:
            List[Occurrence]: List of all occurrences
        """
        return (
            self.static_occurrences +
            self.dynamic_occurrences +
            self.external_script_risks
        )

    def get_high_risk_occurrences(self) -> List[Occurrence]:
        """
        Get all high-risk occurrences.
        
        Returns:
            List[Occurrence]: List of high-risk occurrences
        """
        return [
            occ for occ in self.get_all_occurrences()
            if occ['risk_level'] == 'high'
        ]

    def get_occurrences_by_source(self, source: str) -> List[Occurrence]:
        """
        Get all occurrences from a specific source.
        
        Args:
            source (str): Source to filter by ('static', 'dynamic', or 'external')
            
        Returns:
            List[Occurrence]: List of occurrences from the specified source
        """
        return [
            occ for occ in self.get_all_occurrences()
            if occ['source'] == source
        ] 
