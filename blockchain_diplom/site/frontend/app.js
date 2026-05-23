const API = window.location.origin;

function esc(str) {
    const d = document.createElement('div');
    d.textContent = str || '';
    return d.innerHTML;
}

async function loadStatus() {
    try {
        const [health, config] = await Promise.all([
            fetch(`${API}/api/health`).then(r => r.json()),
            fetch(`${API}/api/config`).then(r => r.json()),
        ]);
        const statusDiv = document.getElementById('status');
        statusDiv.innerHTML = `
            <div class="status-item ${health.status === 'ok' ? 'ok' : 'err'}">
                Backend: ${esc(health.status)}
            </div>
            <div class="status-item">FactRegistry: <code>${esc(config.fact_registry_address || 'not set')}</code></div>
            <div class="status-item">Verifier: <code>${esc(config.verifier_id)}</code></div>
        `;
        if (config.verifier_id_hash) {
            document.getElementById('verifierIdHash').value = config.verifier_id_hash;
        }
    } catch (e) {
        document.getElementById('status').textContent = 'Backend unreachable';
    }
}

document.getElementById('lookupForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('lookupBtn');
    btn.disabled = true;
    btn.textContent = 'Looking up...';

    const verifierIdHash = document.getElementById('verifierIdHash').value.trim();
    const subjectTag = document.getElementById('subjectTag').value.trim();
    const factTypeHash = document.getElementById('factTypeHash').value.trim();

    const fieldHex = /^0x[0-9a-fA-F]{1,64}$/;
    if (!fieldHex.test(verifierIdHash) || !fieldHex.test(subjectTag) || !fieldHex.test(factTypeHash)) {
        document.getElementById('result').innerHTML = '<div class="result-card err"><h3>Error</h3><p>Invalid hex format. Values must start with 0x.</p></div>';
        btn.disabled = false;
        btn.textContent = 'Lookup Fact On-Chain';
        return;
    }

    const params = new URLSearchParams({
        verifier_id_hash: verifierIdHash,
        subject_tag: subjectTag,
        fact_type_hash: factTypeHash,
    });

    const resultDiv = document.getElementById('result');

    try {
        const res = await fetch(`${API}/api/lookup?${params}`);
        const data = await res.json();

        if (data.error) {
            resultDiv.innerHTML = `<div class="result-card err"><h3>Error</h3><p>${esc(data.error)}</p></div>`;
        } else if (data.exists) {
            resultDiv.innerHTML = `
                <div class="result-card valid">
                    <h3>FACT VERIFIED</h3>
                    <table>
                        <tr><td>Status</td><td><strong>Valid</strong></td></tr>
                        <tr><td>Verified At</td><td>${esc(data.verified_at)}</td></tr>
                        <tr><td>Nullifier</td><td><code>${esc(shorten(data.nullifier))}</code></td></tr>
                        <tr><td>Policy Root</td><td><code>${esc(shorten(data.issuer_policy_root))}</code></td></tr>
                        <tr><td>Schema Hash</td><td><code>${esc(shorten(data.schema_hash))}</code></td></tr>
                    </table>
                </div>
            `;
        } else {
            resultDiv.innerHTML = '<div class="result-card not-found"><h3>FACT NOT FOUND</h3><p>No verified fact exists for this subject_tag + fact_type combination.</p></div>';
        }
    } catch (err) {
        resultDiv.innerHTML = `<div class="result-card err"><h3>Error</h3><p>${esc(err.message)}</p></div>`;
    } finally {
        btn.disabled = false;
        btn.textContent = 'Lookup Fact On-Chain';
    }
});

function shorten(hex) {
    if (!hex || hex.length < 20) return hex || '';
    return hex.slice(0, 10) + '...' + hex.slice(-8);
}

loadStatus();
