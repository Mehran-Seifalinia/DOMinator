from typing import List, Dict, Optional, TypedDict
from dataclasses import dataclass
from datetime import datetime

class Occurrence(TypedDict):
    line: Optional[int]
    column: Optional[int]
    pattern: str
    context: str
    risk_level: str
    priority: str
    source: str  # 'static', 'dynamic', or 'event_handler'

@dataclass
class EventHandler:
    tag: str
    attribute: str
    handler: str
    line: Optional[int] = None
    column: Optional[int] = None
    risk_level: str = 'unknown'
    priority: str = 'unknown'

    def to_dict(self) -> Dict:
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
    def __init__(self):
        self.static_occurrences: List[Occurrence] = []
        self.dynamic_occurrences: List[Occurrence] = []
        self.event_handlers: Dict[str, List[EventHandler]] = {}
        self.external_script_risks: List[Occurrence] = []
        self.analysis_time: datetime = datetime.now()
        self.url: Optional[str] = None
        self.status: str = 'pending'  # 'pending', 'completed', 'error'
        self.error_message: Optional[str] = None

    def add_static_occurrence(self, occurrence: Occurrence) -> None:
        occurrence['source'] = 'static'
        self.static_occurrences.append(occurrence)

    def add_dynamic_occurrence(self, occurrence: Occurrence) -> None:
        occurrence['source'] = 'dynamic'
        self.dynamic_occurrences.append(occurrence)

    def add_event_handler(self, event_type: str, handler: EventHandler) -> None:
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)

    def add_external_script_risk(self, occurrence: Occurrence) -> None:
        occurrence['source'] = 'external'
        self.external_script_risks.append(occurrence)

    def set_error(self, error_message: str) -> None:
        self.status = 'error'
        self.error_message = error_message

    def set_completed(self) -> None:
        self.status = 'completed'

    def to_dict(self) -> Dict:
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
        return (
            self.static_occurrences +
            self.dynamic_occurrences +
            self.external_script_risks
        )

    def get_high_risk_occurrences(self) -> List[Occurrence]:
        return [
            occ for occ in self.get_all_occurrences()
            if occ['risk_level'] == 'high'
        ]

    def get_occurrences_by_source(self, source: str) -> List[Occurrence]:
        return [
            occ for occ in self.get_all_occurrences()
            if occ['source'] == source
        ] 
