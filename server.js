const fs = require("fs");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const express = require("express")

const server = jsonServer.create();
const router = jsonServer.router("./database.json");
const userdb = JSON.parse(fs.readFileSync("./users.json", "UTF-8"));

server.use(express.urlencoded({ extended: true }));
server.use(express.json());
server.use(jsonServer.defaults());

const SECRET_KEY = "123456789";

const expiresIn = "1h";

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) =>
    decode !== undefined ? decode : err
  );
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  return (
    userdb.users.findIndex(
      (user) => user.email === email && user.password === password
    ) !== -1
  );
}

function isAuthenticatedByUserId({ userId, password }) {
  return (
    userdb.users.findIndex(
      (user) => user.userId === userId && user.password === password
    ) !== -1
  );
}

// Register New User
server.post("/signup", (req, res) => {
  console.log("register endpoint called; request body:");
  console.log(req.body);
  const { email, userId, password } = req.body;

  if (
    isAuthenticated({ email, password }) === true ||
    isAuthenticatedByUserId({ userId, password }) === true
  ) {
    const status = 401;
    const message = "User already exist.";
    res.status(status).json({ status, message });
    return;
  }

  fs.readFile("./users.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    // Get current users data
    var data = JSON.parse(data.toString());

    // Get the id of last user
    var last_item_id = data.users[data.users.length - 1].id;

    //Add new user
    data.users.push({ id: last_item_id + 1, email: email, password: password }); //add some data
    var writeData = fs.writeFile(
      "./users.json",
      JSON.stringify(data),
      (err, result) => {
        // WRITE
        if (err) {
          const status = 401;
          const message = err;
          res.status(status).json({ status, message });
          return;
        }
      }
    );
  });

  // Create token for new user
  const token = createToken({ email, password });
  console.log("Access Token:" + token);
  res.status(200).json({ token });
});

// Login to one of the users from ./users.json
server.post("/login", (req, res) => {
  console.log("login endpoint called; request body:");
  console.log(req.body);
  const { email, userId, password } = req.body;
  if (
    isAuthenticated({ email, password }) === false &&
    isAuthenticatedByUserId({ userId, password }) === false
  ) {
    const status = 401;
    const message = "Incorrect email or password";
    res.status(status).json({ status, message });
    return;
  }
  const token = createToken({ email, password });
  console.log("Access Token:" + token);
  res.status(200).json({ token });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.token === undefined
  ) {
    const status = 401;
    const message = "Error in authorization format";
    res.status(status).json({ status, message });
    return;
  }
  try {
    let verifyTokenResult;
    verifyTokenResult = verifyToken(req.headers.token);

    if (verifyTokenResult instanceof Error) {
      const status = 401;
      const message = "Access token not provided";
      res.status(status).json({ status, message });
      return;
    }
    next();
  } catch (err) {
    const status = 401;
    const message = "Error access_token is revoked";
    res.status(status).json({ status, message });
  }
});

server.use(router);

server.listen(8000, () => {
  console.log("Run Auth API Server");
});
