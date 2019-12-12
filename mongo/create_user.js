db = db.getSiblingDB('mongo');
db.createUser(
  {
    user: "mongo",
    pwd: "cj9ka0f6ie1mq1akqsb1iy10wp1yfz5b",
    roles: [
       { role: "readWrite", db: "mongo" }
    ]
  }
);