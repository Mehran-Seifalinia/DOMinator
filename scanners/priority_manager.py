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
            RiskLevel.DOCUMENT_REFERRER: {"base": 6, "weight": 1.3}
        }

        self.exploit_complexity = {
            ExploitComplexity.LOW: {"score": 3, "impact": 1.6},
            ExploitComplexity.MEDIUM: {"score": 2, "impact": 1.2},
            ExploitComplexity.HIGH: {"score": 1, "impact": 0.8}
        }

        self.attack_vectors = {
            AttackVector.URL: {"risk": 3, "multiplier": 1.2},
            AttackVector.REFERRER: {"risk": 2, "multiplier": 1.0},
            AttackVector.WINDOW_NAME: {"risk": 3, "multiplier": 1.1},
            AttackVector.POST_MESSAGE: {"risk": 4, "multiplier": 1.3},
            AttackVector.LOCAL_STORAGE: {"risk": 5, "multiplier": 1.4},
            AttackVector.SESSION_STORAGE: {"risk": 4, "multiplier": 1.3},
            AttackVector.INDEXED_DB: {"risk": 5, "multiplier": 1.5},
            AttackVector.FILE_API: {"risk": 4, "multiplier": 1.4}
        }

        self.response_types = {
            ResponseType.HTML: {"risk": 6, "multiplier": 1.5},
            ResponseType.JSON: {"risk": 3, "multiplier": 1.2},
            ResponseType.XML: {"risk": 4, "multiplier": 1.3}
        }

        self.security_mechanisms = {
            SecurityMechanisms.CSP: {"risk_reduction": 0.7},
            SecurityMechanisms.X_XSS_PROTECTION: {"risk_reduction": 0.5}
        }

        self.combination_risk = {
            (RiskLevel.EVAL, RiskLevel.DOCUMENT_WRITE): 3,
            (RiskLevel.INNER_HTML, RiskLevel.SET_TIMEOUT): 2,
            (RiskLevel.COOKIE, RiskLevel.LOCATION): 1,
            (RiskLevel.LOCAL_STORAGE, RiskLevel.POST_MESSAGE): 3
        }

    def calculate_method_score(self, methods):
        return sum(self.risk_levels[method]["base"] * self.risk_levels[method]["weight"] for method in methods if method in self.risk_levels)

    def calculate_complexity_score(self, complexity):
        return self.exploit_complexity.get(complexity, {"score": 0})["score"]

    def calculate_attack_vector_score(self, attack_vector):
        data = self.attack_vectors.get(attack_vector)
        return (data["risk"] * data["multiplier"]) if data else 0

    def calculate_combination_risk(self, methods):
        return sum(risk * 1.2 for pair, risk in self.combination_risk.items() if all(m in methods for m in pair))

    def calculate_security_mechanisms_impact(self, mechanisms=None):
        mechanisms = mechanisms or []
        return max(0.1, 1 - sum(self.security_mechanisms.get(m, {"risk_reduction": 0})["risk_reduction"] for m in mechanisms))

    def calculate_optimized_priority(self, methods, complexity, attack_vector=None, response_type=None, mechanisms=None):
        method_score = self.calculate_method_score(methods)
        complexity_score = self.calculate_complexity_score(complexity)
        attack_vector_score = self.calculate_attack_vector_score(attack_vector)
        response_type_data = self.response_types.get(response_type, {"risk": 0, "multiplier": 1})
        response_risk = response_type_data["risk"] * response_type_data["multiplier"]
        combination_risk = self.calculate_combination_risk(methods)
        security_impact = self.calculate_security_mechanisms_impact(mechanisms)

        total_score = (method_score + complexity_score + attack_vector_score + response_risk + combination_risk) * security_impact
        risk_factor = self.exploit_complexity.get(complexity, {"impact": 1})["impact"]
        weight_factor = 1 + (total_score / self.normalization_factor)

        final_priority = total_score * risk_factor * weight_factor

        if final_priority >= 75:
            return final_priority, "Critical"
        elif final_priority >= 55:
            return final_priority, "High"
        elif final_priority >= 35:
            return final_priority, "Medium"
        elif final_priority >= 15:
            return final_priority, "Low"
        else:
            return final_priority, "Informative"
