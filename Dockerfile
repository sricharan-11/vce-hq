FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VCE_PORT=80 \
    VCE_HOST=0.0.0.0

WORKDIR /app

# Copy the entire application
COPY . /app/

# Install the application and its dependencies
RUN pip install --no-cache-dir .

# Expose the application port
EXPOSE 80

# Run the FastAPI application
CMD ["python", "-m", "uvicorn", "vce_hq.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "80"]
