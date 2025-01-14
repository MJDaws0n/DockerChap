# Use an official Node.js runtime as the base image
FROM node:22.13.0

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the remaining application files (useful for static builds)
COPY . .

# Default command
CMD ["npm", "start"]
