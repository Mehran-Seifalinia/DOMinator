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

    function report(sink, source, payloadSuggestion, context) {
        window.__DOMINATOR_RESULTS__.push({
            sink: sink,
            source: source,
            payloadSuggestion: payloadSuggestion,
            context: context,
            timestamp: Date.now()
        });
    }

    function detectSource(value) {
        if (typeof value !== 'string' || value.length === 0) return null;
        
        const hash = location.hash;
        const search = location.search;
        const referrer = document.referrer;
        const windowName = window.name;
        
        let decodedHash = '';
        let decodedSearch = '';
        try {
            if (hash && hash.length > 1) decodedHash = decodeURIComponent(hash.substring(1));
            if (search && search.length > 1) decodedSearch = decodeURIComponent(search.substring(1));
        } catch(e) { }

        if (search && search.length > 1) {
            const params = new URLSearchParams(search.substring(1));
            for (let [key, val] of params) {
                if (value === val) return 'location.search (param value)';
                try {
                    const decodedVal = decodeURIComponent(val);
                    if (value === decodedVal) return 'location.search (param value decoded)';
                } catch(e) {}
            }
        }
        
        if (hash && hash.length > 1) {
            const rawHash = hash.substring(1);
            if (value === rawHash) return 'location.hash (exact)';
            try {
                const decodedHashVal = decodeURIComponent(rawHash);
                if (value === decodedHashVal) return 'location.hash (exact decoded)';
            } catch(e) {}
        }
        
        if (decodedHash.length > 0 && value.indexOf(decodedHash) !== -1) return 'location.hash (substring)';
        if (decodedSearch.length > 0 && value.indexOf(decodedSearch) !== -1) return 'location.search (substring)';
        
        const rawHash = hash && hash.length > 1 ? hash.substring(1) : '';
        const rawSearch = search && search.length > 1 ? search.substring(1) : '';
        if (rawHash.length > 0 && value.indexOf(rawHash) !== -1) return 'location.hash (raw substring)';
        if (rawSearch.length > 0 && value.indexOf(rawSearch) !== -1) return 'location.search (raw substring)';
        
        if (windowName && windowName.length > 0 && value.indexOf(windowName) !== -1) return 'window.name';
        if (referrer && referrer.length > 0 && value.indexOf(referrer) !== -1) return 'document.referrer';
        
        const currentUrl = document.URL;
        const currentHref = location.href;
        if (currentUrl && currentUrl.length > 0 && value.indexOf(currentUrl) !== -1) return 'document.URL';
        if (currentHref && currentHref.length > 0 && value.indexOf(currentHref) !== -1) return 'location.href';
        
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
    } else {
        Element.prototype.__defineSetter__('innerHTML', function(value) {
            const source = detectSource(value);
            if (source) {
                report('innerHTML', source, '<img src=x onerror=alert(1)>', `innerHTML set to: ${value.substring(0, 80)}`);
            }
            this.innerHTML = value;
        });
    }

    // Hook Element.prototype.outerHTML setter
    const originalOuterHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (originalOuterHTMLDescriptor && originalOuterHTMLDescriptor.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(value) {
                const source = detectSource(value);
                if (source) {
                    report('outerHTML', source, '<img src=x onerror=alert(1)>', `outerHTML set to: ${value.substring(0, 80)}`);
                }
                return originalOuterHTMLDescriptor.set.call(this, value);
            },
            get: originalOuterHTMLDescriptor.get,
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

    // Hook Element.prototype.insertAdjacentHTML
    const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, html) {
        const source = detectSource(html);
        if (source) {
            report('insertAdjacentHTML', source, '<img src=x onerror=alert(1)>', `insertAdjacentHTML with: ${html.substring(0, 80)}`);
        }
        return originalInsertAdjacentHTML.call(this, position, html);
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

    // Hook Function constructor (حفظ new)
    const originalFunction = window.Function;
    function HookedFunction(...args) {
        const body = args.pop();
        const strBody = String(body);
        const source = detectSource(strBody);
        if (source) {
            report('Function', source, 'alert(1)', `new Function with body: ${strBody.substring(0, 80)}`);
        }
        if (new.target) {
            return new originalFunction(...args, body);
        }
        return originalFunction(...args, body);
    }
    HookedFunction.prototype = originalFunction.prototype;
    window.Function = HookedFunction;

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

    // Hook location.href setter and location.assign
    const locationProto = window.location.constructor.prototype;
    // location.href setter
    const hrefDescriptor = Object.getOwnPropertyDescriptor(locationProto, 'href');
    if (hrefDescriptor && hrefDescriptor.set) {
        Object.defineProperty(locationProto, 'href', {
            set: function(value) {
                const source = detectSource(value);
                if (source) {
                    report('location.href', source, 'javascript:alert(1)', `location.href set to: ${value.substring(0, 80)}`);
                }
                return hrefDescriptor.set.call(this, value);
            },
            get: hrefDescriptor.get,
            configurable: true
        });
    }
    // location.assign
    const originalAssign = locationProto.assign;
    if (originalAssign) {
        locationProto.assign = function(url) {
            const source = detectSource(url);
            if (source) {
                report('location.assign', source, 'javascript:alert(1)', `location.assign called with: ${url.substring(0, 80)}`);
            }
            return originalAssign.call(this, url);
        };
    }


    console.log('DOMinator instrumentation loaded.');
})();
