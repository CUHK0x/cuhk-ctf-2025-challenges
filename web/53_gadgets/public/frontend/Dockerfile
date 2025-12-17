FROM node:20-alpine AS development-dependencies-env
COPY ./package.json yarn.lock /app/
WORKDIR /app
RUN yarn install --immutable
COPY . /app

FROM node:20-alpine AS production-dependencies-env
COPY ./package.json yarn.lock /app/
WORKDIR /app
RUN yarn install --immutable --production

FROM node:20-alpine AS build-env
COPY . /app/
COPY --from=development-dependencies-env /app/node_modules /app/node_modules
WORKDIR /app
RUN yarn run build

FROM node:20-alpine
COPY ./package.json yarn.lock /app/
COPY --from=production-dependencies-env /app/node_modules /app/node_modules
COPY --from=build-env /app/build /app/build
WORKDIR /app
CMD ["yarn", "run", "start"]