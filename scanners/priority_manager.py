class PriorityManager:
    def __init__(self):
        # Risk levels for sensitive methods with their base score and weight
        self.risk_levels = {
            "eval": {"base": 9, "weight": 1.5},
            "document.write": {"base": 8, "weight": 1.3},
            "innerHTML": {"base": 7, "weight": 1.2},
            "setTimeout": {"base": 6, "weight": 1.1},
            "setInterval": {"base": 6, "weight": 1.1},
            "location": {"base": 5, "weight": 1.0},
            "cookie": {"base": 4, "weight": 1.0},
            "webSocket": {"base": 3, "weight": 0.8}
        }

        # Exploit complexity with its score and impact multiplier
        self.exploit_complexity = {
            "low": {"score": 3, "impact": 1.5},
            "medium": {"score": 2, "impact": 1.2},
            "high": {"score": 1, "impact": 1.0}
        }

        # Attack vectors categorized with risk level and multiplier for impact
        self.attack_vectors = {
            "url": {"risk": 3, "multiplier": 1.2},
            "referrer": {"risk": 2, "multiplier": 1.1},
            "window.name": {"risk": 2, "multiplier": 1.0},
            "postMessage": {"risk": 4, "multiplier": 1.3},
            "localStorage": {"risk": 5, "multiplier": 1.4},
            "sessionStorage": {"risk": 4, "multiplier": 1.3}
        }

        # Combination risks (higher risk when multiple dangerous methods are combined)
        self.combination_risk = {
            ("eval", "document.write"): 2,
            ("innerHTML", "setTimeout"): 1,
            ("cookie", "location"): 1,
            ("localStorage", "postMessage"): 2
        }

    # Method to calculate the priority score based on different parameters
    def calculate_priority(self, methods, complexity, attack_vector=None):
        total_score = 0
        risk_factor = 0

        # Calculate risk score based on methods used
        for method in methods:
            if method in self.risk_levels:
                method_score = self.risk_levels[method]["base"]
                weight = self.risk_levels[method]["weight"]
                total_score += method_score * weight

        # Adjust score based on the exploit complexity
        if complexity in self.exploit_complexity:
            total_score += self.exploit_complexity[complexity]["score"]
            risk_factor = self.exploit_complexity[complexity]["impact"]

        # Add the effect of the attack vector if provided
        if attack_vector and attack_vector in self.attack_vectors:
            total_score += self.attack_vectors[attack_vector]["risk"] * self.attack_vectors[attack_vector]["multiplier"]

        # Check if any combination of dangerous methods is present
        for method_pair, additional_risk in self.combination_risk.items():
            if set(methods).issuperset(set(method_pair)):
                total_score += additional_risk

        # Final priority score is the total score adjusted by the risk factor
        final_priority = total_score * risk_factor

        return final_priority
