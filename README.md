Link Checker
This is a first year project I made after one of my family members was a victim of phishing. It is a simple website setup with a backend written in python and a frontend written in javascript.

The backend is using requests on VirusTotal API and IPQualityScore API for checking if the link that is sent from the frontend are malicious or not. The backend is using flask for it's server so it will have a development server. The APIs keys are not hardcoded, they are in an .env file.

The frontend is stylied using html and css. After that it is sending a POST request to the backend with the url(as a string) it got as input

Features
URL Safety Check:
Queries the VirusTotal API and IPQualityScore API to analyze URLs.
Real-Time Results:
Displays whether a URL is safe or malicious along with detailed analysis from both APIs.
User-Friendly Interface:
Clean, neon-themed design with interactive feedback.
Flask Backend:
A minimalistic server that handles POST requests to check URL safety.
Prerequisites
Python 3.x:
Ensure Python is installed. Download Python
Flask & Other Dependencies:
See Requirements.txt for a full list of Python packages.
Internet Connection:
Required to query external APIs for URL analysis.
Installation
Backend Setup
Clone the Repository:

git clone https://github.com/yourusername/link-checker.git
Navigate to the Project Directory:

cd link-checker
Create a Virtual Environment (optional but recommended):

python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
Install Dependencies:

pip install -r Requirements.txt
Configure API Keys:

Create a file named keys.env in the project root and add your API keys:

VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
IPQUALITYSCORE_API_KEY=your_ipqualityscore_api_key_here
Run the Flask Server:

python app.py
The backend will be available at http://127.0.0.1:5000.

Frontend Setup
Open the Frontend:

Open the index.html file in your web browser, or serve it via a static server.

Usage:

Enter the URL you want to check into the input field.
Click the Check URL button.
The page will display the analysis results, indicating if the URL is malicious along with detailed results from the APIs.
Project Structure
index.html:
Contains the HTML structure and user interface for the Link Checker.

style.css:
Provides the styling for the application, including a neon, glitch-like aesthetic.

script.js:
Handles user interactions, sends the URL to the backend, and updates the DOM with the results.

app.py:
The Flask backend server that processes URL checks using the VirusTotal and IPQualityScore APIs.

Requirements.txt:
Lists all required Python packages (Flask, requests, beautifulsoup4, lxml, gunicorn, python-dotenv).

keys.env:
Contains API keys. This file is ignored in version control by .gitignore.

.gitignore:
Specifies files and directories (like keys.env and Python caches) to be ignored by Git.

Usage Example
Start the Backend:
Run python app.py to launch the Flask server.

Open the Frontend:
Open index.html in your browser.

Check a URL:
Enter a URL into the input field and click Check URL. The result box will update with the URL analysis.

Future Improvements
Enhanced Error Handling:
Better feedback for network issues or invalid URLs.
User Authentication:
Restrict access to prevent abuse of the service.
Additional API Integrations:
Incorporate more security checks for a comprehensive analysis.
Improved UI/UX:
Refine the interface with more animations and responsive design.
Acknowledgments
This project was inspired by the need to protect against phishing attacks and is intended as a learning tool. Special thanks to the communities behind VirusTotal and IPQualityScore for providing accessible APIs.

License
This project is licensed under the MIT License. See the LICENSE file for more details.