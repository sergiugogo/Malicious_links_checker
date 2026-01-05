import requests
import time
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)
load_dotenv()


def is_valid_url(url):
    """Validate URL format."""
    try:
        result = urlparse(url)
        # Must have scheme (http/https) and netloc (domain)
        if result.scheme not in ('http', 'https'):
            return False
        if not result.netloc:
            return False
        # Basic domain validation
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        # Extract domain without port
        domain = result.netloc.split(':')[0]
        return bool(domain_pattern.match(domain))
    except Exception:
        return False


def check_virustotal(api_key, url):
    """Checks the URL using VirusTotal API with polling for results."""
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}

    try:
        # Submit the URL to VirusTotal
        response = requests.post(vt_url, headers=headers, data={"url": url}, timeout=10)

        if response.status_code == 200:
            # Get the analysis ID
            analysis_id = response.json()["data"]["id"]

            # Poll for analysis completion (max 30 seconds)
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(6):  # Try 6 times with 5 second intervals
                time.sleep(5)
                result_response = requests.get(analysis_url, headers=headers, timeout=10)

                if result_response.status_code == 200:
                    result = result_response.json()
                    status = result["data"]["attributes"]["status"]

                    if status == "completed":
                        stats = result["data"]["attributes"]["stats"]
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        return {
                            "is_malicious": malicious > 0 or suspicious > 0,
                            "malicious_count": malicious,
                            "suspicious_count": suspicious,
                            "total_engines": sum(stats.values())
                        }
            # Timeout - return inconclusive
            return {"is_malicious": False, "error": "Analysis timeout"}
        else:
            print(f"Error submitting URL to VirusTotal: {response.status_code}")
            return {"is_malicious": False, "error": f"API error: {response.status_code}"}
    except Exception as e:
        print(f"Error in VirusTotal check: {e}")
        return {"is_malicious": False, "error": str(e)}





def check_url(url):
    """Check URL using VirusTotal API."""
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    vt_result = check_virustotal(vt_api_key, url)

    return {
        "url": url,
        "is_malicious": vt_result.get("is_malicious", False),
        "detailed_results": {
            "VirusTotal": vt_result
        }
    }


@app.route('/')
def home():
    return "Welcome to the Link Checker API! Use the `/check_url` endpoint to check if a URL is malicious."


@app.route('/favicon.ico')
def favicon():
    return '', 204


@app.route('/health')
def health():
    """Health check endpoint for Docker."""
    return jsonify({"status": "healthy"}), 200


@app.route('/check_url', methods=['GET', 'POST'])
def check_url_api():
    if request.method == 'POST':
        data = request.json
        url = data.get('url') if data else None
    else:
        url = request.args.get('url')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Validate URL format
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL format. Please provide a valid HTTP/HTTPS URL."}), 400

    # Perform URL checks
    result = check_url(url)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
