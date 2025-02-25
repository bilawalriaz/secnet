# SecurityScan Pro

A simple yet robust cybersecurity scanning platform that allows users to perform network scans and security assessments on endpoints using tools like nmap. The system consists of a Python/FastAPI backend and uses Supabase for authentication.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [Database Schema](#database-schema)
- [Authentication](#authentication)
- [Usage Examples](#usage-examples)
- [Development](#development)
- [Deployment](#deployment)
- [License](#license)

## Features

- **User Management**: Registration, authentication, and profile management via Supabase
- **Endpoint Management**: Add, edit, and organize network endpoints into groups
- **Scanning Capabilities**:
  - Basic network scanning using nmap
  - Port scanning with service detection
  - OS fingerprinting
  - Basic vulnerability detection
- **Reporting**: Generate detailed scan reports in various formats (JSON, CSV, PDF)
- **Scheduling**: Schedule recurring scans on endpoints
- **API Access**: Secure API for integration with other tools

## Architecture

SecurityScan Pro follows a modern, modular architecture:

- **Backend**: Python/FastAPI RESTful API
- **Database**: PostgreSQL (accessed via SQLAlchemy ORM)
- **Authentication**: Supabase Auth with JWT tokens
- **Scanning Engine**: Python wrapper around nmap
- **Container Support**: Docker and Docker Compose for easy deployment

## Prerequisites

- Docker and Docker Compose
- Supabase account and project
- nmap installed on the host system (for local development)
- Python 3.9+ (for local development)

## Getting Started

### Environment Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/security-scan-pro.git
   cd security-scan-pro
   ```

2. Run the setup script to create the environment file and start the containers:
   ```bash
   chmod +x setup-script.sh
   ./setup-script.sh
   ```

3. After running the setup script for the first time, edit the `.env` file with your Supabase credentials and run the script again.

4. The API will be available at http://localhost:8000
   - API documentation is available at http://localhost:8000/docs

### Manual Setup (without Docker)

1. Set up a PostgreSQL database
2. Navigate to the backend directory:
   ```bash
   cd backend
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set environment variables (you can copy them from env-template.txt):
   ```bash
   export DATABASE_URL=postgresql://username:password@localhost:5432/securityscan
   export SUPABASE_URL=your_supabase_project_url
   export SUPABASE_KEY=your_supabase_anon_key
   export SUPABASE_JWT_SECRET=your_supabase_jwt_secret
   export ACCESS_TOKEN_EXPIRE_MINUTES=10080  # 7 days
   export CORS_ORIGINS=http://localhost:3000,http://localhost
   export NMAP_PATH=/usr/bin/nmap
   ```

5. Create Alembic versions directory if it doesn't exist:
   ```bash
   mkdir -p app/alembic/versions
   ```

6. Run database migrations:
   ```bash
   python -m alembic.config -c ./app/alembic/ini.txt upgrade head
   ```

7. Start the FastAPI server:
   ```bash
   uvicorn app.main:app --reload
   ```

## API Documentation

The complete OpenAPI documentation is available at the `/docs` endpoint when the server is running. Below is a summary of the main API endpoints:

### Authentication

- `POST /api/v1/auth/signup`: Register a new user
- `POST /api/v1/auth/login`: Authenticate a user and get JWT token
- `POST /api/v1/auth/logout`: Log out a user
- `POST /api/v1/auth/reset-password`: Request password reset
- `POST /api/v1/auth/update-password`: Update password with reset token

### Endpoints Management

- `GET /api/v1/endpoints`: List all endpoints
- `POST /api/v1/endpoints`: Create a new endpoint
- `GET /api/v1/endpoints/{id}`: Get endpoint details
- `PUT /api/v1/endpoints/{id}`: Update an endpoint
- `DELETE /api/v1/endpoints/{id}`: Delete an endpoint

### Endpoint Groups

- `GET /api/v1/endpoint-groups`: List all endpoint groups
- `POST /api/v1/endpoint-groups`: Create a new endpoint group
- `GET /api/v1/endpoint-groups/{id}`: Get group details
- `PUT /api/v1/endpoint-groups/{id}`: Update a group
- `DELETE /api/v1/endpoint-groups/{id}`: Delete a group

### Scans

- `GET /api/v1/scans`: List all scans
- `POST /api/v1/scans`: Create and start a new scan
- `GET /api/v1/scans/{id}`: Get scan details
- `DELETE /api/v1/scans/{id}`: Delete a scan
- `POST /api/v1/scans/{id}/stop`: Stop a running scan

### Scheduled Scans

- `GET /api/v1/scans/scheduled`: List all scheduled scans
- `POST /api/v1/scans/scheduled`: Create a new scheduled scan
- `GET /api/v1/scans/scheduled/{id}`: Get scheduled scan details
- `PUT /api/v1/scans/scheduled/{id}`: Update a scheduled scan
- `DELETE /api/v1/scans/scheduled/{id}`: Delete a scheduled scan

### Reports

- `GET /api/v1/reports/{scan_id}`: Get a report for a scan
- `GET /api/v1/reports/scan/{scan_id}/summary`: Get a summary of scan results
- `GET /api/v1/reports/comparison`: Compare results of two scans

## Database Schema

SecurityScan Pro uses a relational database with the following main tables:

- `users`: User accounts and authentication details
- `endpoints`: Network endpoints to be scanned
- `endpoint_groups`: Logical groups for organizing endpoints
- `scans`: Scan jobs and their status
- `scan_targets`: Many-to-many relationship between scans and endpoints
- `scan_results`: Results of completed scans
- `scheduled_scans`: Configuration for recurring scans
- `api_keys`: API keys for programmatic access

## Authentication

The system uses Supabase for authentication with JWT tokens. All API endpoints (except registration and login) require authentication via the Authorization header:

```
Authorization: Bearer YOUR_JWT_TOKEN
```

## Usage Examples

Here are some examples of how to use the API with curl:

### Register a new user

```bash
curl -X POST http://localhost:8000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword",
    "full_name": "John Doe"
  }'
```

### Login

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword"
  }'
```

This will return a JWT token that you should use for subsequent requests:

```json
{
  "access_token": "your_jwt_token",
  "token_type": "bearer"
}
```

### Create an endpoint group

```bash
curl -X POST http://localhost:8000/api/v1/endpoint-groups \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_jwt_token" \
  -d '{
    "name": "Production Servers",
    "description": "All production web servers"
  }'
```

### Create an endpoint

```bash
curl -X POST http://localhost:8000/api/v1/endpoints \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_jwt_token" \
  -d '{
    "name": "Main Web Server",
    "address": "192.168.1.100",
    "type": "ip",
    "description": "Primary web server",
    "group_id": "group_uuid_from_previous_response"
  }'
```

### Start a port scan

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_jwt_token" \
  -d '{
    "name": "Weekly Port Scan",
    "type": "port-scan",
    "parameters": {
      "ports": "1-1000",
      "speed": "normal"
    },
    "target_endpoints": ["endpoint_uuid_from_previous_response"]
  }'
```

### Get scan results

```bash
curl -X GET http://localhost:8000/api/v1/scans/scan_uuid_from_previous_response \
  -H "Authorization: Bearer your_jwt_token"
```

### Generate a PDF report

```bash
curl -X GET "http://localhost:8000/api/v1/reports/scan_uuid?format=pdf" \
  -H "Authorization: Bearer your_jwt_token" \
  --output scan_report.pdf
```

## Development

### Project Structure

```
security-scan-pro/
├── backend/
│   ├── app/
│   │   ├── alembic/      # Database migration configuration
│   │   ├── auth/         # Authentication components
│   │   ├── core/         # Core utilities and security
│   │   ├── database/     # Database models and session
│   │   ├── endpoints/    # Endpoint management
│   │   ├── groups/       # Endpoint groups
│   │   ├── reports/      # Report generation
│   │   ├── scans/        # Scanning functionality
│   │   ├── config.py     # Configuration
│   │   └── main.py       # Application entry point
│   ├── docs/             # Documentation
│   ├── Dockerfile        # Docker configuration
│   ├── docker-compose.yaml # Docker Compose configuration
│   ├── env-template.txt  # Template for environment variables
│   └── requirements.txt  # Python dependencies
├── setup-script.sh       # Setup script for easy deployment
└── test-api.py           # API testing script
```

### Running Tests

```bash
cd backend
pytest
```

### Code Style

This project follows the PEP 8 style guide. You can check your code using:

```bash
flake8 app
```

## Deployment

### Docker Deployment (Recommended)

The easiest way to deploy SecurityScan Pro is using the provided setup script:

```bash
chmod +x setup-script.sh
./setup-script.sh
```

Alternatively, you can use Docker Compose directly:

```bash
docker-compose -f backend/docker-compose.yaml up -d
```

### Manual Deployment

For production deployments, consider using a WSGI server like Gunicorn:

```bash
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app
```

### Environment Variables for Production

In production, make sure to set these environment variables in your `.env` file:

- `DATABASE_URL`: Connection string for your PostgreSQL database
- `SUPABASE_URL`: URL of your Supabase project
- `SUPABASE_KEY`: Anon key for your Supabase project
- `SUPABASE_JWT_SECRET`: JWT secret for your Supabase project
- `ACCESS_TOKEN_EXPIRE_MINUTES`: JWT token expiration time (default: 10080 - 7 days)
- `CORS_ORIGINS`: Comma-separated list of allowed origins
- `NMAP_PATH`: Path to the nmap binary (default: /usr/bin/nmap)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
