from re import compile
from typing import List, Pattern, Set

# JavaScript dangerous patterns
DANGEROUS_JS_PATTERNS: List[Pattern] = [
    compile(r"(?i)\beval\s*\("),
    compile(r"(?i)\bFunction\s*\("),
    compile(r"(?i)window\s*\[\s*['\"]eval['\"]\s*\]"),
    compile(r"(?i)document\.(write|writeln|open)\s*\("),
    compile(r"(?i)(setTimeout|setInterval)\s*\("),
    compile(r"(?i)new\s+(ActiveXObject|XMLHttpRequest)\s*\("),
    compile(r"(?i)document\.cookie\s*="),
    compile(r"(?i)localStorage\s*="),
    compile(r"(?i)sessionStorage\s*="),
    compile(r"(?i)window\.location\s*="),
    compile(r"(?i)fetch\s*\("),
]

# HTML dangerous patterns
DANGEROUS_HTML_PATTERNS: List[Pattern] = [
    compile(r"(?i)on\w+\s*="),
    compile(r"(?i)javascript\s*:"),
    compile(r"(?i)data\s*:\s*text\s*/\s*html"),
    compile(r"(?i)<\s*script[^>]*>.*<\s*/\s*script\s*>"),
    compile(r"(?i)<\s*iframe[^>]*>.*<\s*/\s*iframe\s*>"),
    compile(r"(?i)<\s*object\s*data\s*=\s*['\"].*['\"]\s*>"),
]

# Event handler attributes
EVENT_HANDLER_ATTRIBUTES: Set[str] = {
    # Window Events
    'onload', 'onerror', 'onbeforeunload', 'onunload',
    'onpageshow', 'onpagehide', 'onresize', 'onscroll',
    
    # Mouse Events
    'onclick', 'ondblclick', 'onmouseover', 'onmouseout',
    'oncontextmenu',
    
    # Keyboard Events
    'onkeydown', 'onkeyup', 'onkeypress',
    
    # Form Events
    'onchange', 'oninput', 'oninvalid', 'onselect', 'onsubmit',
    'onreset', 'onfocus', 'onblur', 'onfocusin', 'onfocusout',
    
    # Media Events
    'onabort', 'oncanplay', 'oncanplaythrough', 'ondurationchange',
    'onemptied', 'onended', 'onloadeddata', 'onloadedmetadata',
    'onloadstart', 'onpause', 'onplay', 'onplaying', 'onseeked',
    'onseeking', 'onstalled', 'onsuspend', 'ontimeupdate',
    'onvolumechange', 'onwaiting',
    
    # Drag and Drop Events
    'ondrag', 'ondragend', 'ondragenter', 'ondragleave',
    'ondragover', 'ondragstart', 'ondrop',
    
    # Clipboard Events
    'oncopy', 'oncut', 'onpaste',
    
    # HTML5 Events
    'onsearch', 'onstorage', 'onhashchange',
    'onpopstate', 'onanimationstart', 'onanimationend', 'onanimationiteration',
    'ontransitionend', 'onfullscreenchange', 'onfullscreenerror',
    
    # Mobile/Touch Events
    'ontouchstart', 'ontouchmove', 'ontouchend', 'ontouchcancel',
    'ongesturestart', 'ongesturechange', 'ongestureend',
    'onorientationchange', 'ondevicemotion', 'ondeviceorientation',
    'onpointerdown', 'onpointermove', 'onpointerup', 'onpointercancel',
    
    # Pointer Events
    'onpointerenter', 'onpointerleave', 'onpointerover', 'onpointerout',
    
    # File API Events
    'onprogress', 'ontimeout', 'onratechange',
    
    # Fetch and Service Worker Events
    'onfetch', 'oninstall', 'onactivate', 'onmessage', 'onpush',
    'onpushsubscriptionchange', 'onbeforeinstallprompt'
}

# Risk levels for different patterns
RISK_LEVELS = {
    'eval': 'high',
    'Function': 'high',
    'innerHTML': 'medium',
    'onclick': 'medium',
    'document.write': 'high',
    'setTimeout': 'medium',
    'setInterval': 'medium',
    'fetch': 'medium',
    'XMLHttpRequest': 'medium',
    'localStorage': 'low',
    'sessionStorage': 'low',
    'window.location': 'high',
}

def get_risk_level(pattern: str) -> str:
    """
    Get the risk level for a given pattern.
    :param pattern: The pattern to check
    :return: Risk level ('high', 'medium', 'low', or 'unknown')
    """
    for key in RISK_LEVELS:
        if key.lower() in pattern.lower():
            return RISK_LEVELS[key]
    return 'unknown' 
