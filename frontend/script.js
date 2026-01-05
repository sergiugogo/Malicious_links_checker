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

            if (vt.error) {
                detailsHtml += `<li class="service-error">VirusTotal: ${escapeHtml(vt.error)}</li>`;
            } else {
                const vtStatus = vt.is_malicious ? 'Flagged' : 'Clean';
                detailsHtml += `<li class="${vt.is_malicious ? 'flagged' : 'clean'}">
                    VirusTotal: ${vtStatus} 
                    ${vt.malicious_count !== undefined ? `(${vt.malicious_count}/${vt.total_engines} engines)` : ''}
                </li>`;
            }

            resultDiv.innerHTML = `
                <div class="result-card ${statusClass}">
                    <p class="status">${statusText}</p>
                    <p class="url"><strong>URL:</strong> ${escapeHtml(data.url)}</p>
                    <div class="details">
                        <p><strong>Scan Results:</strong></p>
                        <ul>${detailsHtml}</ul>
                    </div>
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
