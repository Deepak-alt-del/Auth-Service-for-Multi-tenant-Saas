# Auth Service for Multi-tenant SaaS


This repository contains the backend implementation of an authentication service for a multi-tenant SaaS application. It includes APIs for user management, organization management, role management, and various statistics endpoints.

## Technologies Used
* Python Django Rest Framework
* PostgreSQL / SQLite (database)
* JWT (for authentication tokens)
* Resend (for Email API)

## Docker Support
This repository includes a Dockerfile and docker-compose.yml file for running the application in a containerized environment.

### Build and Run with Docker Compose
To build and start the application using Docker Compose, run the following command:
```bash
docker-compose up -d --build
```
# Testing
* Import the provided Postman collection (Auth_Service.postman_collection.json) into Postman for testing the APIs.
* Ensure all scenarios (successful and error cases) are thoroughly tested.

