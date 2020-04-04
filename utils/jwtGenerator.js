const jwt = require("jsonwebtoken");
require("dotenv").config(); // allows us to get access to all our env variables;

function jwtGenerator(user_id) {
  const payload = {
    user: user_id,
  };
  return jwt.sign(payload, process.env.jwtSecret, { expiresIn: "1hr" });
}

module.exports = jwtGenerator;
