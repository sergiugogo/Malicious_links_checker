FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY backend/Requirements.txt .
RUN pip install --no-cache-dir -r Requirements.txt

# Copy backend code
COPY backend/app.py .

# Copy frontend files
COPY frontend/ ./frontend/

# Expose port (Render uses PORT env var)
EXPOSE 5000

# Run with gunicorn
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120 app:app"]
