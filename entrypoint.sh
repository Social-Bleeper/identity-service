#!/bin/sh
set -e  # Exit immediately if a command exits with a non-zero status

# Any other setup commands can go here (if needed)

# Run Maven command to start the Spring Boot application
sh ./mvnw spring-boot:run
