# Use Python 3.9
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy files
COPY . /app

# Install libraries
RUN pip install --no-cache-dir -r requirements.txt

# Run the app
CMD ["python", "app.py"]