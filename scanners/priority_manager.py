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

class PriorityManager:
    def __init__(self):
        # Risk levels for different methods
        self.risk_levels = {
            RiskLevel.EVAL: {"base": 9, "weight": 1.5},
            RiskLevel.DOCUMENT_WRITE: {"base": 8, "weight": 1.3},
            RiskLevel.INNER_HTML: {"base": 7, "weight": 1.2},
            RiskLevel.SET_TIMEOUT: {"base": 6, "weight": 1.1},
            RiskLevel.SET_INTERVAL: {"base": 6, "weight": 1.1},
            RiskLevel.LOCATION: {"base": 5, "weight": 1.0},
            RiskLevel.COOKIE: {"base": 4, "weight": 1.0},
            RiskLevel.WEB_SOCKET: {"base": 3, "weight": 0.8}
        }
        
        # Exploit complexity levels and their impact
        self.exploit_complexity = {
            ExploitComplexity.LOW: {"score": 3, "impact": 1.5},
            ExploitComplexity.MEDIUM: {"score": 2, "impact": 1.2},
            ExploitComplexity.HIGH: {"score": 1, "impact": 1.0}
        }

        # Attack vector risks and multipliers
        self.attack_vectors = {
            AttackVector.URL: {"risk": 3, "multiplier": 1.2},
            AttackVector.REFERRER: {"risk": 2, "multiplier": 1.1},
            AttackVector.WINDOW_NAME: {"risk": 2, "multiplier": 1.0},
            AttackVector.POST_MESSAGE: {"risk": 4, "multiplier": 1.3},
            AttackVector.LOCAL_STORAGE: {"risk": 5, "multiplier": 1.4},
            AttackVector.SESSION_STORAGE: {"risk": 4, "multiplier": 1.3}
        }
        
        # Combination risks for specific method pairs
        self.combination_risk = {
            (RiskLevel.EVAL, RiskLevel.DOCUMENT_WRITE): 2,
            (RiskLevel.INNER_HTML, RiskLevel.SET_TIMEOUT): 1,
            (RiskLevel.COOKIE, RiskLevel.LOCATION): 1,
            (RiskLevel.LOCAL_STORAGE, RiskLevel.POST_MESSAGE): 2
        }

    def calculate_method_score(self, methods):
        """Calculate total score based on methods used."""
        total_score = 0
        for method in methods:
            if method in self.risk_levels:
                method_score = self.risk_levels[method]["base"]
                weight = self.risk_levels[method]["weight"]
                total_score += method_score * weight
        return total_score

    def calculate_complexity_score(self, complexity):
        """Calculate score based on exploit complexity."""
        if complexity in self.exploit_complexity:
            return self.exploit_complexity[complexity]["score"]
        return 0

    def calculate_attack_vector_score(self, attack_vector):
        """Calculate score based on the attack vector used."""
        if attack_vector and attack_vector in self.attack_vectors:
            return self.attack_vectors[attack_vector]["risk"] * self.attack_vectors[attack_vector]["multiplier"]
        return 0

    def calculate_combination_risk(self, methods):
        """Calculate risk based on combination of dangerous methods."""
        risk = 0
        for method_pair, additional_risk in self.combination_risk.items():
            if set(methods).issuperset(set(method_pair)):
                risk += additional_risk
        return risk

    def calculate_priority(self, methods, complexity, attack_vector=None):
        """Calculate the final priority score based on multiple factors."""
        method_score = self.calculate_method_score(methods)
        complexity_score = self.calculate_complexity_score(complexity)
        attack_vector_score = self.calculate_attack_vector_score(attack_vector)
        combination_risk = self.calculate_combination_risk(methods)

        total_score = method_score + complexity_score + attack_vector_score + combination_risk
        risk_factor = self.exploit_complexity[complexity]["impact"] if complexity in self.exploit_complexity else 1

        final_priority = total_score * risk_factor
        
        # Set threshold for serious threat
        THRESHOLD = 50
        if final_priority >= THRESHOLD:
            return final_priority, "High priority"
        return final_priority, "Normal priority"
