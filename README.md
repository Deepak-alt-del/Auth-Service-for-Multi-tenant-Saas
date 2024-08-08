#Auth Service for Multi-tenant SaaS
This repository contains the backend implementation of an authentication service for a multi-tenant SaaS application. It includes APIs for user management, organization management, role management, and various statistics endpoints.

Technologies Used
Python Django Rest Framework
PostgreSQL / SQLite (database)
JWT (for authentication tokens)
Resend (for Email API)
Docker Support
This repository includes a Dockerfile and docker-compose.yml file for running the application in a containerized environment.

Build and Run with Docker Compose
To build and start the application using Docker Compose, run the following command:
docker-compose up -d --build
This command will build the Docker images if they don't exist and start the containers in detached mode (-d).
