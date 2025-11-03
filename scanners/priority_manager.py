"""
Priority Manager Module
Manages and calculates priority levels for detected DOM XSS vulnerabilities.
"""

from enum import Enum
from typing import List, Dict, Optional, Tuple, Union
from utils.logger import get_logger

class RiskLevel(Enum):
    """Enumeration of different risk levels in DOM XSS vulnerabilities."""
    EVAL = "eval"
    DOCUMENT_WRITE = "document.write"
    INNER_HTML = "innerHTML"
    SET_TIMEOUT = "setTimeout"
    SET_INTERVAL = "setInterval"
    LOCATION = "location"
    COOKIE = "cookie"
    WEB_SOCKET = "webSocket"
    DOCUMENT_DOMAIN = "document.domain"
    DOCUMENT_REFERRER = "document.referrer"
    LOCAL_STORAGE = "localStorage"  # Added to fix combination_risk pairs
    POST_MESSAGE = "postMessage"    # Added to fix combination_risk pairs

class ExploitComplexity(Enum):
    """Enumeration of different exploit complexity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class AttackVector(Enum):
    """Enumeration of different attack vectors for DOM XSS."""
    URL = "url"
    REFERRER = "referrer"
    WINDOW_NAME = "window.name"
    POST_MESSAGE = "postMessage"
    LOCAL_STORAGE = "localStorage"
    SESSION_STORAGE = "sessionStorage"
    INDEXED_DB = "indexedDB"
    FILE_API = "fileAPI"

class ResponseType(Enum):
    """Enumeration of different response types."""
    HTML = "html"
    JSON = "json"
    XML = "xml"

class SecurityMechanisms(Enum):
    """Enumeration of different security mechanisms."""
    CSP = "CSP"
    X_XSS_PROTECTION = "X-XSS-Protection"

class PriorityManager:
    """
    A class for managing and calculating priority levels for DOM XSS vulnerabilities.
    
    This class provides methods to calculate various risk scores and determine
    the overall priority of detected vulnerabilities.
    """
    
    def __init__(self, normalization_factor: int = 100) -> None:
        """
        Initialize the PriorityManager with configuration parameters.
        
        Args:
            normalization_factor (int): Factor used to normalize priority scores
        """
        self.logger = get_logger(__name__)
        self.normalization_factor = normalization_factor

        self.risk_levels = {
            RiskLevel.EVAL: {"base": 10, "weight": 1.6},
            RiskLevel.DOCUMENT_WRITE: {"base": 9, "weight": 1.5},
            RiskLevel.INNER_HTML: {"base": 8, "weight": 1.4},
            RiskLevel.SET_TIMEOUT: {"base": 6, "weight": 1.1},
            RiskLevel.SET_INTERVAL: {"base": 6, "weight": 1.1},
            RiskLevel.LOCATION: {"base": 5, "weight": 1.0},
            RiskLevel.COOKIE: {"base": 4, "weight": 1.0},
            RiskLevel.WEB_SOCKET: {"base": 4, "weight": 1.0},
            RiskLevel.DOCUMENT_DOMAIN: {"base": 7, "weight": 1.4},
            RiskLevel.DOCUMENT_REFERRER: {"base": 6, "weight": 1.3},
            RiskLevel.LOCAL_STORAGE: {"base": 5, "weight": 1.4},
            RiskLevel.POST_MESSAGE: {"base": 4, "weight": 1.3},
        }

        self.exploit_complexity = {
            ExploitComplexity.LOW: {"score": 3, "impact": 1.6},
            ExploitComplexity.MEDIUM: {"score": 2, "impact": 1.2},
            ExploitComplexity.HIGH: {"score": 1, "impact": 0.8},
        }

        self.attack_vectors = {
            AttackVector.URL: {"risk": 3, "multiplier": 1.2},
            AttackVector.REFERRER: {"risk": 2, "multiplier": 1.0},
            AttackVector.WINDOW_NAME: {"risk": 3, "multiplier": 1.1},
            AttackVector.POST_MESSAGE: {"risk": 4, "multiplier": 1.3},
            AttackVector.LOCAL_STORAGE: {"risk": 5, "multiplier": 1.4},
            AttackVector.SESSION_STORAGE: {"risk": 4, "multiplier": 1.3},
            AttackVector.INDEXED_DB: {"risk": 5, "multiplier": 1.5},
            AttackVector.FILE_API: {"risk": 4, "multiplier": 1.4},
        }

        self.response_types = {
            ResponseType.HTML: {"risk": 6, "multiplier": 1.5},
            ResponseType.JSON: {"risk": 3, "multiplier": 1.2},
            ResponseType.XML: {"risk": 4, "multiplier": 1.3},
        }

        self.security_mechanisms = {
            SecurityMechanisms.CSP: {"risk_reduction": 0.7},
            SecurityMechanisms.X_XSS_PROTECTION: {"risk_reduction": 0.5},
        }

        self.combination_risk = {
            (RiskLevel.EVAL, RiskLevel.DOCUMENT_WRITE): 3,
            (RiskLevel.INNER_HTML, RiskLevel.SET_TIMEOUT): 2,
            (RiskLevel.COOKIE, RiskLevel.LOCATION): 1,
            (RiskLevel.LOCAL_STORAGE, RiskLevel.POST_MESSAGE): 3,
        }

    def calculate_method_score(self, methods: List[RiskLevel]) -> float:
        """
        Calculate the risk score for a list of methods.
        
        Args:
            methods (List[RiskLevel]): List of risk levels to calculate score for
            
        Returns:
            float: Calculated method score
            
        Raises:
            ValueError: If invalid RiskLevel is provided
        """
        self.logger.debug("Calculating method score for methods: %s", methods)
        try:
            score = 0.0
            for method in methods:
                if method not in self.risk_levels:
                    raise ValueError(f"Invalid RiskLevel: {method}")
                score += self.risk_levels[method]["base"] * self.risk_levels[method]["weight"]
            self.logger.info("Calculated method score: %.2f", score)
            return score
        except ValueError as e:
            self.logger.error("ValueError in method score calculation: %s", str(e))
            raise
        except Exception as e:
            self.logger.error("Unexpected error calculating method score: %s", str(e))
            raise

    def calculate_complexity_score(self, complexity: ExploitComplexity) -> float:
        """
        Calculate the complexity score for an exploit.
        
        Args:
            complexity (ExploitComplexity): The complexity level to calculate score for
            
        Returns:
            float: Calculated complexity score
            
        Raises:
            ValueError: If invalid ExploitComplexity is provided
        """
        self.logger.debug("Calculating complexity score for complexity: %s", complexity)
        try:
            if complexity not in self.exploit_complexity:
                raise ValueError(f"Invalid ExploitComplexity: {complexity}")
            score = self.exploit_complexity[complexity]["score"]
            self.logger.info("Calculated complexity score: %.2f", score)
            return score
        except ValueError as e:
            self.logger.error("ValueError in complexity score calculation: %s", str(e))
            raise
        except Exception as e:
            self.logger.error("Unexpected error calculating complexity score: %s", str(e))
            raise

    def calculate_attack_vector_score(self, attack_vector: AttackVector) -> float:
        """
        Calculate the risk score for an attack vector.
        
        Args:
            attack_vector (AttackVector): The attack vector to calculate score for
            
        Returns:
            float: Calculated attack vector score
            
        Raises:
            ValueError: If invalid AttackVector is provided
        """
        self.logger.debug("Calculating attack vector score for vector: %s", attack_vector)
        try:
            if attack_vector not in self.attack_vectors:
                raise ValueError(f"Invalid AttackVector: {attack_vector}")
            data = self.attack_vectors[attack_vector]
            score = data["risk"] * data["multiplier"]
            self.logger.info("Calculated attack vector score: %.2f", score)
            return score
        except ValueError as e:
            self.logger.error("ValueError in attack vector score calculation: %s", str(e))
            raise
        except Exception as e:
            self.logger.error("Unexpected error calculating attack vector score: %s", str(e))
            raise

    def calculate_combination_risk(self, methods: List[RiskLevel]) -> float:
        """
        Calculate the risk score for combinations of methods.
        
        Args:
            methods (List[RiskLevel]): List of methods to calculate combination risk for
            
        Returns:
            float: Calculated combination risk score
            
        Raises:
            ValueError: If invalid RiskLevel in methods
        """
        self.logger.debug("Calculating combination risk for methods: %s", methods)
        try:
            risk = 0.0
            for pair, pair_risk in self.combination_risk.items():
                if all(m in methods for m in pair):
                    risk += pair_risk * 1.2
            self.logger.info("Calculated combination risk: %.2f", risk)
            return risk
        except ValueError as e:
            self.logger.error("ValueError in combination risk calculation: %s", str(e))
            raise
        except Exception as e:
            self.logger.error("Unexpected error calculating combination risk: %s", str(e))
            raise

    def calculate_security_mechanisms_impact(self, mechanisms: List[SecurityMechanisms]) -> float:
        """
        Calculate the impact of security mechanisms on risk.
        
        Args:
            mechanisms (List[SecurityMechanisms]): List of security mechanisms
            
        Returns:
            float: Calculated security mechanisms impact
            
        Raises:
            ValueError: If invalid SecurityMechanisms provided
        """
        self.logger.debug("Calculating security mechanisms impact for mechanisms: %s", mechanisms)
        try:
            total_reduction = 0.0
            for m in mechanisms:
                if m not in self.security_mechanisms:
                    raise ValueError(f"Invalid SecurityMechanisms: {m}")
                total_reduction += self.security_mechanisms[m]["risk_reduction"]
            impact = max(0.1, 1 - total_reduction)
            self.logger.info("Calculated security mechanisms impact: %.2f", impact)
            return impact
        except ValueError as e:
            self.logger.error("ValueError in security mechanisms impact calculation: %s", str(e))
            raise
        except Exception as e:
            self.logger.error("Unexpected error calculating security mechanisms impact: %s", str(e))
            raise

    def process_event_handlers(self, event_handlers: List[str]) -> float:
        """
        Process event handlers and calculate their risk score.
        
        Args:
            event_handlers (List[str]): List of event handlers to process
            
        Returns:
            float: Calculated event handler score
            
        Raises:
            ValueError: If processing fails due to invalid data
        """
        self.logger.debug("Processing event handlers (truncated): %s", str(event_handlers)[:100])  # Truncate for security
        try:
            methods = []
            for handler in event_handlers:
                handler_lower = handler.lower()
                if "onclick" in handler_lower:
                    methods.append(RiskLevel.DOCUMENT_WRITE)
                if "onload" in handler_lower:
                    methods.append(RiskLevel.INNER_HTML)
                # Add more pattern matching as needed for better accuracy
            score = self.calculate_method_score(methods)
            self.logger.info("Processed event handlers with score: %.2f", score)
            return score
        except ValueError as e:
            self.logger.error("ValueError processing event handlers: %s", str(e))
            raise
        except Exception as e:
            self.logger.error("Unexpected error processing event handlers: %s", str(e))
            raise

    def process_dom_results(self, dom_results: List[str]) -> float:
        """
        Process DOM results and calculate their risk score.
        
        Args:
            dom_results (List[str]): List of DOM results to process
            
        Returns:
            float: Calculated DOM results score
            
        Raises:
            ValueError: If processing fails due to invalid data
        """
        self.logger.debug("Processing DOM results (truncated): %s", str(dom_results)[:100])  # Truncate for security
        try:
            methods = []
            for result in dom_results:
                result_lower = result.lower()
                if "<script>" in result_lower or "javascript:" in result_lower:
                    methods.append(RiskLevel.EVAL)
                # Add more pattern matching as needed for better accuracy
            score = self.calculate_method_score(methods)
            self.logger.info("Processed DOM results with score: %.2f", score)
            return score
        except ValueError as e:
            self.logger.error("ValueError processing DOM results: %s", str(e))
            raise
        except Exception as e:
            self.logger.error("Unexpected error processing DOM results: %s", str(e))
            raise

    def calculate_optimized_priority(
        self,
        methods: List[RiskLevel],
        complexity: ExploitComplexity,
        attack_vector: Optional[AttackVector] = None,
        response_type: Optional[ResponseType] = None,
        mechanisms: Optional[List[SecurityMechanisms]] = None,
        event_handlers: Optional[List[str]] = None,
        dom_results: Optional[List[str]] = None
    ) -> Tuple[float, str]:
        """
        Calculate the optimized priority score for a vulnerability.
        
        Args:
            methods (List[RiskLevel]): List of risk levels
            complexity (ExploitComplexity): Exploit complexity
            attack_vector (Optional[AttackVector]): Attack vector
            response_type (Optional[ResponseType]): Response type
            mechanisms (Optional[List[SecurityMechanisms]]): Security mechanisms
            event_handlers (Optional[List[str]]): Event handlers
            dom_results (Optional[List[str]]): DOM results
            
        Returns:
            Tuple[float, str]: Final priority score and severity label
            
        Raises:
            ValueError: If invalid inputs are provided
        """
        self.logger.debug("Calculating optimized priority for methods: %s", methods)
        try:
            method_score = self.calculate_method_score(methods)
            event_handler_score = self.process_event_handlers(event_handlers or [])
            dom_result_score = self.process_dom_results(dom_results or [])
            complexity_score = self.calculate_complexity_score(complexity)
            attack_vector_score = self.calculate_attack_vector_score(attack_vector) if attack_vector else 0.0

            response_data = self.response_types.get(response_type, {"risk": 0, "multiplier": 1}) if response_type else {"risk": 0, "multiplier": 1}
            response_risk = response_data["risk"] * response_data["multiplier"]

            combination_risk = self.calculate_combination_risk(methods)
            security_impact = self.calculate_security_mechanisms_impact(mechanisms or [])

            total_score = (
                method_score + event_handler_score + dom_result_score +
                complexity_score + attack_vector_score +
                response_risk + combination_risk
            ) * security_impact

            risk_factor = self.exploit_complexity.get(complexity, {"impact": 1})["impact"]
            weight_factor = 1 + (total_score / self.normalization_factor)

            final_priority = total_score * risk_factor * weight_factor

            thresholds = [15, 35, 55, 75]
            labels = ["Informative", "Low", "Medium", "High", "Critical"]
            severity = labels[sum(final_priority >= t for t in thresholds)]

            self.logger.info("Final priority score: %.2f", final_priority)
            self.logger.info("Severity: %s", severity)

            return final_priority, severity
        except ValueError as e:
            self.logger.error("ValueError calculating optimized priority: %s", str(e))
            raise
        except Exception as e:
            self.logger.error("Unexpected error calculating optimized priority: %s", str(e))
            raise
