const router = require("express").Router();
const pool = require("../db");
const authorization = require("../middleware/authorization");

router.get("/", authorization, async (req, res) => {
  try {
    //req.use has the payload,
    //pt ca ai asta in authorization.js:
    //    req.user = payload.user;
    // res.json(req.user); // sends the user id

    const user = await pool.query(
      "select user_name from users where user_id = $1",
      [req.user]
    );
    res.json(user.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json("server err");
  }
});

module.exports = router;
