// Security script to prevent inspection, console access, and provide DDoS protection (PoW)
(function() {
    // 0. Clickjacking Protection
    if (window.self !== window.top) {
        window.top.location = window.self.location;
    }

    // 1. DevTools Protection
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
    });

    document.addEventListener('keydown', function(e) {
        if (e.keyCode === 123) { e.preventDefault(); return false; }
        if (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67)) {
            e.preventDefault();
            return false;
        }
        if (e.ctrlKey && e.keyCode === 85) { e.preventDefault(); return false; }
    });

    setInterval(function() {
        const threshold = 160;
        if (window.outerWidth - window.innerWidth > threshold || window.outerHeight - window.innerHeight > threshold) {
            document.body.innerHTML = "<h1>Acesso Negado</h1><p>O uso de ferramentas de desenvolvedor não é permitido.</p>";
            window.location.href = "about:blank";
        }
    }, 1000);

    if (typeof console !== "undefined") {
        const methods = ["log", "debug", "info", "warn", "error", "table", "clear"];
        methods.forEach(method => { console[method] = function() {}; });
    }

    // 2. DDoS Protection (Proof of Work / "Blockchain" mechanism)
    async function calculatePoW(data, difficulty = 4) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        let nonce = 0;
        const target = '0'.repeat(difficulty);

        while (true) {
            const nonceBuffer = encoder.encode(nonce.toString());
            const combinedBuffer = new Uint8Array(dataBuffer.length + nonceBuffer.length);
            combinedBuffer.set(dataBuffer);
            combinedBuffer.set(nonceBuffer, dataBuffer.length);

            const hashBuffer = await crypto.subtle.digest('SHA-256', combinedBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

            if (hashHex.startsWith(target)) {
                return nonce;
            }
            nonce++;
            // Yield to avoid freezing the UI for very high difficulties
            if (nonce % 1000 === 0) await new Promise(r => setTimeout(r, 0));
        }
    }

    const originalFetch = window.fetch;
    window.fetch = async (...args) => {
        let [url, options] = args;
        
        // Only apply to our API calls and mutations
        if (url.includes('/api/') && options && (options.method === 'POST' || options.method === 'PUT')) {
            const body = options.body || '';
            const nonce = await calculatePoW(body);
            options.headers = options.headers || {};
            options.headers['x-pow-nonce'] = nonce.toString();
        }
        return originalFetch(url, options);
    };
})();
