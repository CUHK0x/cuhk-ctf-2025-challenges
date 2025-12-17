FROM node:lts-alpine

# Download Chrome
RUN apk update && apk add chromium-chromedriver

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json to the working directory
# A wildcard is used to ensure both package.json AND package-lock.json are copied
COPY package.json yarn.lock ./

# Install app dependencies
RUN yarn install --immutable --production

# If you are building for production, consider using `npm ci --only=production`
# RUN npm ci --only=production

# Bundle app source
COPY . .

# Expose the port your Express app listens on (e.g., 3000 or 8080)
EXPOSE 3000

# Define the command to run your application
ENTRYPOINT [ "./entrypoint.sh" ]