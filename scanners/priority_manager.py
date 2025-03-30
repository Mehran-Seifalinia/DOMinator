from utils.logger import get_logger
from enum import Enum

class RiskLevel(Enum):
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

class ExploitComplexity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class AttackVector(Enum):
    URL = "url"
    REFERRER = "referrer"
    WINDOW_NAME = "window.name"
    POST_MESSAGE = "postMessage"
    LOCAL_STORAGE = "localStorage"
    SESSION_STORAGE = "sessionStorage"
    INDEXED_DB = "indexedDB"
    FILE_API = "fileAPI"

class ResponseType(Enum):
    HTML = "html"
    JSON = "json"
    XML = "xml"

class SecurityMechanisms(Enum):
    CSP = "CSP"
    X_XSS_PROTECTION = "X-XSS-Protection"

class PriorityManager:
    def __init__(self, normalization_factor=100):
        self.logger = get_logger()
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

    def calculate_method_score(self, methods):
        self.logger.debug("Calculating method score for methods: %s", methods)
        try:
            score = sum(
                self.risk_levels[method]["base"] * self.risk_levels[method]["weight"]
                for method in methods if method in self.risk_levels
            )
            self.logger.info("Calculated method score: %d", score)
            return score
        except Exception as e:
            self.logger.error("Error calculating method score: %s", e)
            raise

    def calculate_complexity_score(self, complexity):
        self.logger.debug("Calculating complexity score for complexity: %s", complexity)
        try:
            score = self.exploit_complexity.get(complexity, {"score": 0})["score"]
            self.logger.info("Calculated complexity score: %d", score)
            return score
        except Exception as e:
            self.logger.error("Error calculating complexity score: %s", e)
            raise

    def calculate_attack_vector_score(self, attack_vector):
        self.logger.debug("Calculating attack vector score for vector: %s", attack_vector)
        try:
            data = self.attack_vectors.get(attack_vector)
            score = (data["risk"] * data["multiplier"]) if data else 0
            self.logger.info("Calculated attack vector score: %d", score)
            return score
        except Exception as e:
            self.logger.error("Error calculating attack vector score: %s", e)
            raise

    def calculate_combination_risk(self, methods):
        self.logger.debug("Calculating combination risk for methods: %s", methods)
        try:
            risk = sum(
                risk * 1.2 for pair, risk in self.combination_risk.items()
                if all(m in methods for m in pair)
            )
            self.logger.info("Calculated combination risk: %d", risk)
            return risk
        except Exception as e:
            self.logger.error("Error calculating combination risk: %s", e)
            raise

    def calculate_security_mechanisms_impact(self, mechanisms):
        self.logger.debug("Calculating security mechanisms impact for mechanisms: %s", mechanisms)
        try:
            impact = max(
                0.1,
                1 - sum(
                    self.security_mechanisms.get(m, {"risk_reduction": 0})["risk_reduction"]
                    for m in mechanisms
                )
            )
            self.logger.info("Calculated security mechanisms impact: %.2f", impact)
            return impact
        except Exception as e:
            self.logger.error("Error calculating security mechanisms impact: %s", e)
            raise

    def process_event_handlers(self, event_handlers):
        self.logger.debug("Processing event handlers: %s", event_handlers)
        try:
            methods = []
            for handler in event_handlers:
                if "onclick" in handler:
                    methods.append(RiskLevel.DOCUMENT_WRITE)
                if "onload" in handler:
                    methods.append(RiskLevel.INNER_HTML)
            score = self.calculate_method_score(methods)
            self.logger.info("Processed event handlers with score: %d", score)
            return score
        except Exception as e:
            self.logger.error("Error processing event handlers: %s", e)
            raise

    def process_dom_results(self, dom_results):
        self.logger.debug("Processing DOM results: %s", dom_results)
        try:
            methods = []
            for result in dom_results:
                if "<script>" in result or "javascript:" in result:
                    methods.append(RiskLevel.EVAL)
            score = self.calculate_method_score(methods)
            self.logger.info("Processed DOM results with score: %d", score)
            return score
        except Exception as e:
            self.logger.error("Error processing DOM results: %s", e)
            raise

    def calculate_optimized_priority(self, methods, complexity, attack_vector=None, response_type=None, mechanisms=None, event_handlers=None, dom_results=None):
        self.logger.debug("Calculating optimized priority for methods: %s", methods)
        try:
            method_score = self.calculate_method_score(methods)
            event_handler_score = self.process_event_handlers(event_handlers) if event_handlers else 0
            dom_result_score = self.process_dom_results(dom_results) if dom_results else 0
            complexity_score = self.calculate_complexity_score(complexity)
            attack_vector_score = self.calculate_attack_vector_score(attack_vector)

            response_data = self.response_types.get(response_type, {"risk": 0, "multiplier": 1})
            response_risk = response_data["risk"] * response_data["multiplier"]

            combination_risk = self.calculate_combination_risk(methods)
            security_impact = self.calculate_security_mechanisms_impact(mechanisms)

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
        except Exception as e:
            self.logger.error("Error calculating optimized priority: %s", e)
            raise
