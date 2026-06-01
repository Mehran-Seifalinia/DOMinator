/**
 * DOMinator Instrumentation Script
 * Hooks dangerous DOM sinks and tracks data flow from user-controllable sources.
 * Results are collected in window.__DOMINATOR_RESULTS__ array.
 */
(function() {
    // Avoid double instrumentation
    if (window.__DOMINATOR_INSTRUMENTED__) return;
    window.__DOMINATOR_INSTRUMENTED__ = true;
    window.__DOMINATOR_RESULTS__ = [];

    const REPORT_PREFIX = 'DOMINATOR';

    function report(sink, source, payloadSuggestion, context) {
        window.__DOMINATOR_RESULTS__.push({
            sink: sink,
            source: source,
            payloadSuggestion: payloadSuggestion,
            context: context,
            timestamp: Date.now()
        });
    }

    // Helper: check if a string comes from a user-controllable source
        function detectSource(value) {
        if (typeof value !== 'string' || value.length === 0) return null;
        
        const hash = location.hash;      // e.g., "#<img src=x>"
        const search = location.search;  // e.g., "?code=alert(1)"
        const referrer = document.referrer;
        const windowName = window.name;
        
        // Decode URL components once for comparison
        let decodedHash = '';
        let decodedSearch = '';
        try {
            if (hash && hash.length > 1) decodedHash = decodeURIComponent(hash.substring(1));
            if (search && search.length > 1) decodedSearch = decodeURIComponent(search.substring(1));
        } catch(e) { /* ignore decode errors */ }
        
        // Check if value appears in decoded hash or search (after decoding)
        if (decodedHash && value.indexOf(decodedHash) !== -1) return 'location.hash';
        if (decodedSearch && value.indexOf(decodedSearch) !== -1) return 'location.search';
        
        // Also check raw (encoded) versions as fallback
        if (hash && hash.length > 1 && value.indexOf(hash.substring(1)) !== -1) return 'location.hash';
        if (search && search.length > 1 && value.indexOf(search.substring(1)) !== -1) return 'location.search';
        
        // Check other sources
        if (windowName && value.indexOf(windowName) !== -1) return 'window.name';
        if (referrer && value.indexOf(referrer) !== -1) return 'document.referrer';
        
        return null;
    }

    // Hook Element.prototype.innerHTML (setter)
    const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (originalInnerHTMLDescriptor && originalInnerHTMLDescriptor.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                const source = detectSource(value);
                if (source) {
                    report('innerHTML', source, '<img src=x onerror=alert(1)>', `innerHTML set to: ${value.substring(0, 80)}`);
                }
                return originalInnerHTMLDescriptor.set.call(this, value);
            },
            get: originalInnerHTMLDescriptor.get,
            configurable: true
        });
    }

    // Hook document.write
    const originalWrite = document.write;
    document.write = function(...args) {
        const html = args.join('');
        const source = detectSource(html);
        if (source) {
            report('document.write', source, '<img src=x onerror=alert(1)>', `document.write with: ${html.substring(0, 80)}`);
        }
        return originalWrite.apply(this, args);
    };

    // Hook document.writeln similarly
    const originalWriteln = document.writeln;
    document.writeln = function(...args) {
        const html = args.join('');
        const source = detectSource(html);
        if (source) {
            report('document.writeln', source, '<img src=x onerror=alert(1)>', `document.writeln with: ${html.substring(0, 80)}`);
        }
        return originalWriteln.apply(this, args);
    };

    // Hook eval
    const originalEval = window.eval;
    window.eval = function(code) {
        const str = String(code);
        const source = detectSource(str);
        if (source) {
            report('eval', source, 'alert(1)', `eval with: ${str.substring(0, 80)}`);
        }
        return originalEval.call(window, code);
    };

    // Hook iframe srcdoc attribute (setAttribute and direct property)
    const originalSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
        if (name === 'srcdoc' && typeof value === 'string') {
            const source = detectSource(value);
            if (source) {
                report('srcdoc', source, '<img src=x onerror=alert(1)>', `iframe srcdoc set to: ${value.substring(0, 80)}`);
            }
        }
        return originalSetAttribute.call(this, name, value);
    };
    
    // Hook iframe.srcdoc property setter
    const iframeProto = HTMLIFrameElement.prototype;
    const srcdocDescriptor = Object.getOwnPropertyDescriptor(iframeProto, 'srcdoc');
    if (srcdocDescriptor && srcdocDescriptor.set) {
        Object.defineProperty(iframeProto, 'srcdoc', {
            set: function(value) {
                const source = detectSource(value);
                if (source) {
                    report('srcdoc', source, '<img src=x onerror=alert(1)>', `iframe.srcdoc set to: ${value.substring(0, 80)}`);
                }
                return srcdocDescriptor.set.call(this, value);
            },
            get: srcdocDescriptor.get,
            configurable: true
        });
    }

    // Hook Function constructor
    const originalFunction = window.Function;
    window.Function = function(...args) {
        const body = args.pop();
        const strBody = String(body);
        const source = detectSource(strBody);
        if (source) {
            report('Function', source, 'alert(1)', `new Function with body: ${strBody.substring(0, 80)}`);
        }
        return originalFunction.apply(this, args.concat(body));
    };

    // Hook setTimeout/setInterval with string argument
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function(handler, timeout, ...args) {
        if (typeof handler === 'string') {
            const source = detectSource(handler);
            if (source) {
                report('setTimeout', source, 'alert(1)', `setTimeout with string: ${handler}`);
            }
        }
        return originalSetTimeout.call(this, handler, timeout, ...args);
    };
    const originalSetInterval = window.setInterval;
    window.setInterval = function(handler, timeout, ...args) {
        if (typeof handler === 'string') {
            const source = detectSource(handler);
            if (source) {
                report('setInterval', source, 'alert(1)', `setInterval with string: ${handler}`);
            }
        }
        return originalSetInterval.call(this, handler, timeout, ...args);
    };

    // Hook location.hash / location.href setter? We could monitor assignment to location = '...' 
    // But it's complex; we'll rely on sinks that use those values after page load.
    // However, we can also observe direct location assignment by replacing the property.
    // For simplicity, we skip assignment hooks; instead we detect when a sink uses a source value.

    // Hook postMessage listener to detect incoming messages (source = postMessage)
    const originalAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, listener, options) {
        if (type === 'message') {
            // Wrap listener to capture data
            const wrappedListener = function(event) {
                if (event.data && typeof event.data === 'string') {
                    // Not a sink directly, but we can later see if event.data flows to sink.
                    // We'll just store as potential source.
                    window.__DOMINATOR_MESSAGE_DATA__ = event.data;
                } else if (event.data && typeof event.data === 'object') {
                    window.__DOMINATOR_MESSAGE_DATA__ = JSON.stringify(event.data);
                }
                return listener.call(this, event);
            };
            return originalAddEventListener.call(this, type, wrappedListener, options);
        }
        return originalAddEventListener.call(this, type, listener, options);
    };

    // Also hook window.name setter? We detect via detectSource when sink uses window.name.
    // That's already covered.

    console.log('DOMinator instrumentation loaded.');
})();
