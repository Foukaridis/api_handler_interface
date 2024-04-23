# Start from a specific version of the Golang base image
FROM golang:1.22

# Set the working directory inside the container
WORKDIR /app

# Copy the local code to the container's workspace
COPY . .

# Assuming your Go application's main package is in the "api" directory
WORKDIR /app/api

# Build your application on the specified directory
RUN go build -o porcupine-api

# Change permissions to make the app executable
RUN chmod +x porcupine-api

# Command to run the executable
CMD ["./porcupine-api"]