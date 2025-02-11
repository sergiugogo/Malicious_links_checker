This is a first year project I made after one of my family members was a victim of phishing.
It is a simple website setup with a backend written in python and a frontend written in javascript.

The backend is using requests on VirusTotal API and IPQualityScore API for checking if the link that is sent from the frontend are malicious or not. The backend is using flask for it's server so it will have a development server. The APIs keys are not hardcoded, they are in an .env file.

The frontend is stylied using html and css. After that it is sending a POST request to the backend with the url(as a string) it got as input
