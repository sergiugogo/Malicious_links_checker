import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
import os 
from dotenv import load_dotenv

app = Flask(__name__)
CORS(app)
load_dotenv()

# 1. VirusTotal API
def check_virustotal(api_key, url):
    """Checks the URL using VirusTotal API."""
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}  # Correct header key for VirusTotal API

    try:
        # Submit the URL to VirusTotal
        response = requests.post(vt_url, headers=headers, data={"url": url})
        
        # Check for success
        if response.status_code == 200:
            # Get the analysis ID
            analysis_id = response.json()["data"]["id"]
            
            # Fetch the analysis results
            result_url = f"{vt_url}/{analysis_id}"
            result_response = requests.get(result_url, headers=headers)
            
            # Check the analysis result
            if result_response.status_code == 200:
                result = result_response.json()
                positives = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
                return positives > 0  # True if malicious
            else:
                print(f"Error fetching VirusTotal analysis: {result_response.status_code}")
        else:
            print(f"Error submitting URL to VirusTotal: {response.status_code}")
    except Exception as e:
        print(f"Error in VirusTotal check: {e}")
    return False

# 2. IPQualityScore API
def check_ipqualityscore(api_key, url):
    """Checks the URL using IPQualityScore API."""
    ipqs_url = f"https://ipqualityscore.com/api/json/url/{api_key}/{url}"
    try:
        response = requests.get(ipqs_url)
        if response.status_code == 200:
            result = response.json()
            return result.get("malicious", False)  # True if malicious
        else:
            print(f"IPQualityScore API error: {response.status_code}")
    except Exception as e:
        print(f"Error in IPQualityScore check: {e}")
    return False

# Combine all checks into a single function
def check_url(url):
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    ipqs_api_key = os.getenv("IPQUALITYSCORE_API_KEY")

    results = {
        "VirusTotal": check_virustotal(vt_api_key, url),
        "IPQualityScore": check_ipqualityscore(ipqs_api_key, url)
    }

    # Determine final result
    is_malicious = any(results.values())
    return {
        "url": url,
        "is_malicious": is_malicious,
        "detailed_results": results
    }

# Add a route for the home page
@app.route('/')
def home():
    return "Welcome to the Link Checker API! Use the `/check_url` endpoint to check if a URL is malicious."

# Handle favicon requests to avoid 404 errors
@app.route('/favicon.ico')
def favicon():
    return '', 204  # Empty response with HTTP 204 (No Content)

# Flask API endpoint for URL checking
@app.route('/check_url', methods=['GET','POST'])
def check_url_api():
    if request.method == 'POST':
        data = request.json
        url = data.get('url')
        if not url:
            return jsonify({"error": "URL is required"}), 400
    else:
        url = request.args.get('url')
        if not url:
            return jsonify({"error": "URL is required"}), 400

    # Perform URL checks
    result = check_url(url)
    return jsonify(result)

# Example usage for debugging (runs only when executed directly)
if __name__ == "__main__":
    # Start the Flask app
    app.run(debug=True)

    # Optional: Local testing of the `check_url` function
    url_to_check = "https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview#using-the-api"
    result = check_url(url_to_check)
    print(result)
