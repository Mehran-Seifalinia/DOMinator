from json import dump, load, JSONDecodeError
from enum import Enum
from typing import List, Optional, Dict, Union
from threading import Lock
from utils.logger import get_logger

class PayloadType(Enum):
    SIMPLE = "simple"
    OBFUSCATED = "obfuscated"
    ENCODED = "encoded"
    EVENT_HANDLER = "event_handler"
    ATTRIBUTE = "attribute"
    DYNAMIC = "dynamic"

class Encoding(Enum):
    NONE = None
    BASE64 = "base64"
    URL = "url"
    UNICODE = "unicode"

class Payloads:
    def __init__(self) -> None:
        """
        Initializes the Payloads class, creating an empty list of payloads.
        """
        self.payload_list: List[Dict[str, Union[str, PayloadType, Encoding]]] = []
        self.logger = get_logger()  # Get the logger instance from utils/logger.py
        self.lock = Lock()  # For thread safety

    def get_payloads(self, payload_type: Optional[PayloadType] = None, encoding: Optional[Encoding] = None) -> List[Dict[str, Union[str, PayloadType, Encoding]]]:
        """
        Returns a list of payloads, optionally filtered by type and encoding.
        """
        result = self.payload_list
        if payload_type:
            result = [p for p in result if p["type"] == payload_type]
        if encoding:
            result = [p for p in result if p["encoding"] == encoding]
        return result

    def add_payload(self, payload: str, payload_type: PayloadType = PayloadType.SIMPLE, encoding: Encoding = Encoding.NONE) -> None:
        """
        Adds a new payload to the payload list after validation.
        """
        if not self._is_valid_payload(payload):
            self.logger.error(f"Invalid payload: {payload}")
            raise ValueError(f"Invalid payload: {payload}")
        
        # Check uniqueness based on payload, type, and encoding
        if any(p['payload'] == payload and p['type'] == payload_type and p['encoding'] == encoding for p in self.payload_list):
            self.logger.warning(f"Payload already exists: {payload}")
            return
        
        # Validate PayloadType and Encoding
        if payload_type not in PayloadType:
            self.logger.error(f"Invalid PayloadType: {payload_type}")
            raise ValueError(f"Invalid PayloadType: {payload_type}")
        if encoding not in Encoding:
            self.logger.error(f"Invalid Encoding: {encoding}")
            raise ValueError(f"Invalid Encoding: {encoding}")
        
        new_payload = {"type": payload_type, "payload": payload, "encoding": encoding}
        self.payload_list.append(new_payload)
        self.logger.info(f"Payload added: {payload}")

    def update_payload(self, old_payload: str, new_payload: str, payload_type: PayloadType = PayloadType.SIMPLE, encoding: Encoding = Encoding.NONE) -> None:
        """
        Updates an existing payload in the payload list.
        """
        for p in self.payload_list:
            if p['payload'] == old_payload and p['type'] == payload_type and p['encoding'] == encoding:
                p['payload'] = new_payload
                self.logger.info(f"Payload updated: {old_payload} -> {new_payload}")
                return
        self.logger.warning(f"Payload not found for update: {old_payload}")

    def remove_payload(self, payload: str) -> None:
        """
        Removes the first occurrence of a payload from the payload list.
        """
        for p in self.payload_list:
            if p['payload'] == payload:
                self.payload_list.remove(p)
                self.logger.info(f"Payload removed: {payload}")
                return
        self.logger.warning(f"Payload not found for removal: {payload}")

    def _is_valid_payload(self, payload: str) -> bool:
        """
        Validates if the payload is a non-empty string.
        """
        return bool(payload)

    def save_to_file(self, file_path: str) -> None:
        """
        Saves the payload list to a file.
        """
        try:
            with open(file_path, 'w') as file:
                dump(self.payload_list, file, default=str)
            self.logger.info(f"Payloads saved to {file_path}")
        except Exception as e:
            self.logger.error(f"Error saving payloads to file {file_path}: {e}")

    def load_from_file(self, file_path: str) -> None:
        """
        Loads the payload list from a file.
        """
        try:
            with open(file_path, 'r') as file:
                self.payload_list = load(file)
            self.logger.info(f"Payloads loaded from {file_path}")
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
        except JSONDecodeError:
            self.logger.error(f"Error decoding JSON from file: {file_path}")
        except Exception as e:
            self.logger.error(f"Error loading payloads from file: {e}")

    def search_payloads(self, search_term: str) -> List[Dict[str, Union[str, PayloadType, Encoding]]]:
        """
        Searches for payloads that contain the search term.
        """
        return [p for p in self.payload_list if search_term in p['payload']]

if __name__ == "__main__":
    payloads = Payloads()
    payloads.add_payload("<script>alert('XSS')</script>")
    print(payloads.get_payloads(payload_type=PayloadType.SIMPLE))
    payloads.add_payload("<script>alert('New XSS')</script>")
    print(payloads.get_payloads())
    payloads.update_payload("<script>alert('XSS')</script>", "<script>alert('Updated XSS')</script>")
    payloads.remove_payload("<script>alert('Updated XSS')</script>")
    payloads.save_to_file("payloads.json")
    payloads.load_from_file("payloads.json")
