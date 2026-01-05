document.getElementById('url-form').addEventListener('submit', async function (e) {
    e.preventDefault();

    const urlInput = document.getElementById('url-input');
    const resultDiv = document.getElementById('result');
    const submitBtn = document.getElementById('submit-btn');
    const btnText = submitBtn.querySelector('.btn-text');
    const spinner = submitBtn.querySelector('.spinner');

    // Show loading state
    submitBtn.disabled = true;
    btnText.textContent = 'Checking...';
    spinner.classList.remove('hidden');
    resultDiv.innerHTML = '<p class="loading">Scanning URL with security APIs...</p>';

    try {
        // Use relative URL - works with Docker reverse proxy
        const response = await fetch('/api/check_url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput.value })
        });

        const data = await response.json();

        if (data.error) {
            resultDiv.innerHTML = `<p class="error">Error: ${escapeHtml(data.error)}</p>`;
        } else {
            const statusClass = data.is_malicious ? 'malicious' : 'safe';
            const statusText = data.is_malicious ? '⚠️ MALICIOUS' : '✅ SAFE';

            // Build detailed results HTML
            let detailsHtml = '';
            const vt = data.detailed_results.VirusTotal;
            const gsb = data.detailed_results.GoogleSafeBrowsing;

            // VirusTotal results
            if (vt.error) {
                detailsHtml += `<li class="service-error">VirusTotal: ${escapeHtml(vt.error)}</li>`;
            } else {
                const vtStatus = vt.is_malicious ? 'Flagged' : 'Clean';
                detailsHtml += `<li class="${vt.is_malicious ? 'flagged' : 'clean'}">
                    VirusTotal: ${vtStatus}
                    ${vt.malicious_count !== undefined ? `(${vt.malicious_count}/${vt.total_engines} engines)` : ''}
                </li>`;
            }

            // Google Safe Browsing results
            if (gsb.error) {
                detailsHtml += `<li class="service-error">Google Safe Browsing: ${escapeHtml(gsb.error)}</li>`;
            } else {
                const gsbStatus = gsb.is_malicious ? 'Flagged' : 'Clean';
                let threatInfo = '';
                if (gsb.threats && gsb.threats.length > 0) {
                    const threatLabels = gsb.threats.map(t => t.replace(/_/g, ' ')).join(', ');
                    threatInfo = ` (${threatLabels})`;
                }
                detailsHtml += `<li class="${gsb.is_malicious ? 'flagged' : 'clean'}">
                    Google Safe Browsing: ${gsbStatus}${threatInfo}
                </li>`;
            }

            // URLScan results
            const urlscan = data.detailed_results.URLScan;
            if (urlscan.error) {
                detailsHtml += `<li class="service-error">URLScan.io: ${escapeHtml(urlscan.error)}</li>`;
            } else {
                const urlscanStatus = urlscan.is_malicious ? 'Flagged' : 'Clean';
                detailsHtml += `<li class="${urlscan.is_malicious ? 'flagged' : 'clean'}">
                    URLScan.io: ${urlscanStatus} (Score: ${urlscan.score}/100)
                </li>`;
            }

            // Build screenshot section if available
            let screenshotHtml = '';
            if (urlscan.screenshot_url) {
                screenshotHtml = `
                    <div class="screenshot-section">
                        <p><strong>Page Preview:</strong></p>
                        <img src="${escapeHtml(urlscan.screenshot_url)}" alt="Page screenshot" class="screenshot">
                    </div>
                `;
            }

            resultDiv.innerHTML = `
                <div class="result-card ${statusClass}">
                    <p class="status">${statusText}</p>
                    <p class="url"><strong>URL:</strong> ${escapeHtml(data.url)}</p>
                    <div class="details">
                        <p><strong>Scan Results:</strong></p>
                        <ul>${detailsHtml}</ul>
                    </div>
                    ${screenshotHtml}
                </div>
            `;
        }
    } catch (error) {
        resultDiv.innerHTML = `<p class="error">Connection error: ${escapeHtml(error.message)}</p>`;
    } finally {
        // Reset button state
        submitBtn.disabled = false;
        btnText.textContent = 'Check URL';
        spinner.classList.add('hidden');
    }
});

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
