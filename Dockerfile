# Use the official Golang image:    or?: FROM golang:1.22.5
FROM golang:latest

# Set the Current Working Directory inside the container:
WORKDIR /app

# Copy everything from the current directory to the PWD (Present Working Directory) inside the container:    or?: COPY . /app
COPY . .

# Install SQLite and related dependencies:
RUN apt-get update && apt-get install -y sqlite3 libsqlite3-dev

# Download all dependencies. Go modules will be cached (to speed up build times) if the go.mod and go.sum files haven't not changed:
RUN go mod download

# Build the Go app:                 or?: RUN go build -o main
RUN go build -o forum main.go

# Ensure the built executable has the correct permissions and is always ready to run:
RUN chmod +x /app/forum

# Expose the application port:
EXPOSE 8080

# Command to run the executable:    or?: CMD ["/app/main"]
CMD ["/app/forum"]