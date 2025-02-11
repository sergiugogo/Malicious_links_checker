document.getElementById('url-form').addEventListener('submit', async function (e) {
    e.preventDefault();

    const urlInput = document.getElementById('url-input').value;
    const resultDiv = document.getElementById('result');

    try {
        // Send POST request to the backend
        const response = await fetch('http://127.0.0.1:5000/check_url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });

        const data = await response.json();

        if (data.error) {
            resultDiv.textContent = `Error: ${data.error}`;
        } else {
            resultDiv.innerHTML = `
                <p><strong>URL:</strong> ${data.url}</p>
                <p><strong>Malicious:</strong> ${data.is_malicious ? "Yes" : "No"}</p>
                <p><strong>Details:</strong></p>
                <ul>
                    ${Object.entries(data.detailed_results).map(([service, result]) => 
                        `<li>${service}: ${result ? "Malicious" : "Safe"}</li>`).join('')}
                </ul>
            `;
        }
    } catch (error) {
        resultDiv.textContent = `Error: ${error.message}`;
    }
});
