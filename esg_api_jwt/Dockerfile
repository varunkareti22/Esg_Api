# Use official lightweight Python image
FROM python:3.10-slim

# Set working directory in container
WORKDIR /app

# Copy all files into the container
COPY . .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 5000 for Flask
EXPOSE 5000

# Run your main Python file
CMD ["python", "esg_api_secure_jwt.py"]
