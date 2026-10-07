# DOM XSS lab target

A small deliberately vulnerable page used to verify DOMinator end to end on a
local target. It exposes the sources and sinks the scanner looks for:
`location.hash` and `location.search` feeding `innerHTML` and `eval`, an inline
`onerror` handler, a `javascript:` URI, `localStorage`, `sessionStorage` and
`document.cookie` usage, and an external script.

## Serve it

```bash
python -m http.server 8899 --directory labs/dom-xss-lab
```

## Scan it

```bash
python dominator.py -u "http://127.0.0.1:8899/" -l 3 -o scan.json -r json -v
```

Run this only against your own machine.
