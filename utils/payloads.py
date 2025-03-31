from json import dump, load, JSONDecodeError
from enum import Enum
from typing import List, Optional
from threading import Lock
from utils.logger import get_logger
from dataclasses import dataclass

class PayloadType(Enum):
    SIMPLE = "simple"
    OBFUSCATED = "obfuscated"
    ENCODED = "encoded"
    EVENT_HANDLER = "event_handler"
    ATTRIBUTE = "attribute"
    DYNAMIC = "dynamic"

class Encoding(Enum):
    BASE64 = "base64"
    URL = "url"
    UNICODE = "unicode"

@dataclass(frozen=True)
class Payload:
    payload: str
    payload_type: PayloadType
    encoding: Encoding

    def __hash__(self):
        return hash((self.payload, self.payload_type, self.encoding))

class Payloads:
    def __init__(self) -> None:
        self.payload_list: List[Payload] = []
        self.payload_set: set = set()
        self.logger = get_logger()
        self.lock = Lock()

    def get_payloads(self, payload_type: Optional[PayloadType] = None, encoding: Optional[Encoding] = None) -> List[Payload]:
        with self.lock:
            result = self.payload_list
            if payload_type:
                result = [p for p in result if p.payload_type == payload_type]
            if encoding:
                result = [p for p in result if p.encoding == encoding]
            return result

    def add_payload(self, payload: str, payload_type: PayloadType = PayloadType.SIMPLE, encoding: Encoding = Encoding.BASE64) -> None:
        if not self._is_valid_payload(payload):
            self.logger.error(f"Invalid payload: {payload}")
            raise ValueError(f"Invalid payload: {payload}")

        new_payload = Payload(payload, payload_type, encoding)
        
        with self.lock:
            if new_payload in self.payload_set:
                self.logger.warning(f"Payload already exists: {payload}")
                return

            self.payload_list.append(new_payload)
            self.payload_set.add(new_payload)
            self.logger.info(f"Payload added: {payload}")

    def update_payload(self, old_payload: str, new_payload: str, payload_type: PayloadType = PayloadType.SIMPLE, encoding: Encoding = Encoding.BASE64) -> None:
        with self.lock:
            for index, p in enumerate(self.payload_list):
                if p.payload == old_payload and p.payload_type == payload_type and p.encoding == encoding:
                    updated_payload = Payload(new_payload, payload_type, encoding)
                    self.payload_list[index] = updated_payload
                    self.payload_set.discard(p)
                    self.payload_set.add(updated_payload)
                    self.logger.info(f"Payload updated: {old_payload} -> {new_payload}")
                    return
            self.logger.warning(f"Payload not found for update: {old_payload}")

    def remove_payload(self, payload: str) -> None:
        with self.lock:
            payloads_to_remove = [p for p in self.payload_list if p.payload == payload]
            if not payloads_to_remove:
                self.logger.warning(f"Payload not found for removal: {payload}")
                return
            for p in payloads_to_remove:
                self.payload_list.remove(p)
                self.payload_set.discard(p)
                self.logger.info(f"Payload removed: {payload}")

    def _is_valid_payload(self, payload: str) -> bool:
        return isinstance(payload, str) and bool(payload.strip())

    def save_to_file(self, file_path: str) -> None:
        with self.lock:
            try:
                with open(file_path, 'w') as file:
                    dump([p.__dict__ for p in self.payload_list], file, default=str, indent=4)
                self.logger.info(f"Payloads saved to {file_path}")
            except (OSError, IOError) as e:
                self.logger.error(f"Error saving payloads to file {file_path}: {e}")

    def load_from_file(self, file_path: str) -> None:
        with self.lock:
            try:
                with open(file_path, 'r') as file:
                    data = load(file)
                    if not isinstance(data, list):
                        raise ValueError("Invalid data format in file")
                    for p in data:
                        try:
                            payload_type = PayloadType(p["payload_type"])
                            encoding = Encoding(p["encoding"])
                            payload = Payload(p["payload"], payload_type, encoding)
                            if payload not in self.payload_set:
                                self.payload_list.append(payload)
                                self.payload_set.add(payload)
                        except ValueError:
                            self.logger.error(f"Invalid payload type or encoding in file: {p}")
                            continue
                self.logger.info(f"Payloads loaded from {file_path}")
            except FileNotFoundError:
                self.logger.error(f"File not found: {file_path}")
            except JSONDecodeError:
                self.logger.error(f"Error decoding JSON from file: {file_path}")
            except (ValueError, KeyError) as e:
                self.logger.error(f"Invalid data format in file: {file_path}, Error: {e}")

    def search_payloads(self, search_term: str) -> List[Payload]:
        with self.lock:
            return [p for p in self.payload_list if search_term.lower() in p.payload.lower()]

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
