"""
Patterns Module
Defines patterns and risk levels for DOM XSS vulnerability detection.
"""

from re import compile, Pattern

# JavaScript dangerous patterns
DANGEROUS_JS_PATTERNS: list[Pattern] = [
    compile(r"(?i)\beval\s*\("),
    compile(r"(?i)\bFunction\s*\("),
    compile(r"(?i)window\s*\[\s*['\"]eval['\"]\s*\]"),
    compile(r"(?i)document\.(write|writeln|open)\s*\("),
    compile(r"(?i)(setTimeout|setInterval)\s*\("),
    compile(r"(?i)new\s+(ActiveXObject|XMLHttpRequest)\s*\("),
    compile(r"(?i)document\.cookie\s*="),
    compile(r"(?i)localStorage\s*(?:\.|\(|=)"),
    compile(r"(?i)sessionStorage\s*(?:\.|\(|=)"),
    compile(r"(?i)window\.location\s*="),
    compile(r"(?i)fetch\s*\("),
    compile(r"(?i)\.innerHTML\s*="),
    compile(r"(?i)\.outerHTML\s*="),
    compile(r"(?i)\.insertAdjacentHTML\s*\("),
]

# HTML dangerous patterns
DANGEROUS_HTML_PATTERNS: list[Pattern] = [
    compile(r"(?i)javascript\s*:"),
    compile(r"(?i)data\s*:\s*text\s*/\s*html"),
]

# DOM source patterns (where attacker-controlled data can enter)
DOM_SOURCES_PATTERNS: list[Pattern] = [
    compile(r"location\.hash"),
    compile(r"location\.search"),
    compile(r"location\.href"),
    compile(r"location\.pathname"),
    compile(r"document\.baseURI"),
    compile(r"document\.URL"),
    compile(r"document\.documentURI"),
    compile(r"document\.referrer"),
    compile(r"window\.name"),
    compile(r"document\.cookie"),
    compile(r"sessionStorage\s*\.getItem"),
    compile(r"localStorage\s*\.getItem"),
]

# Event handler attributes
EVENT_HANDLER_ATTRIBUTES: set[str] = {
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

# Precompiled patterns with risk levels for efficient detection
RISK_PATTERNS: list[tuple[Pattern, str]] = [
    (compile(r"(?i)\beval\s*\("), 'critical'),
    (compile(r"(?i)\.innerHTML\s*="), 'critical'),
    (compile(r"(?i)document\.write\s*\("), 'critical'),
    (compile(r"(?i)\.outerHTML\s*="), 'critical'),
    (compile(r"(?i)\bFunction\s*\("), 'high'),
    (compile(r"(?i)window\.location\s*="), 'high'),
    (compile(r"(?i)setTimeout\s*\("), 'medium'),
    (compile(r"(?i)setInterval\s*\("), 'medium'),
    (compile(r"(?i)fetch\s*\("), 'medium'),
    (compile(r"(?i)new\s+XMLHttpRequest\s*\("), 'medium'),
    (compile(r"(?i)localStorage\s*(?:\.|\(|=)"), 'low'),
    (compile(r"(?i)sessionStorage\s*(?:\.|\(|=)"), 'low'),
    (compile(r"(?i)onclick\s*="), 'medium'),
]

def get_risk_level(pattern: str, _complexity: int = 1) -> str:
    """Return risk level based on compiled patterns. _complexity is ignored."""
    try:
        for pat, risk in RISK_PATTERNS:
            if pat.search(pattern):
                return risk
        return 'unknown'
    except Exception:
        return 'unknown'
