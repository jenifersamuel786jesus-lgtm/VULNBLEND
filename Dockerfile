FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data /app/reports
EXPOSE 3000
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=3000", "--server.headless=true", "--browser.gatherUsageStats=false"]
