//CHECKS IF THE JWT TOKEN === VALID
const jwt = require("jsonwebtoken");
require("dotenv").config(); //so i can acc env vars

module.exports = async (req, res, next) => {
  try {
    //destructure token
    const jwtToken = req.header("token");

    if (!jwtToken) {
      res.status(403).json("not authorizZz");
    }

    const payload = jwt.verify(jwtToken, process.env.jwtSecret);
    req.user = payload.user;
  } catch (err) {
    console.error(err.message);
    res.status(403).json("not authorized");
  }
  next();
};
