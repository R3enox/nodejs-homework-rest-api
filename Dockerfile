FROM node

WORKDIR /app

COPY . /app

RUN yarn

EXPOSE 3000

CMD ["node", "server"]