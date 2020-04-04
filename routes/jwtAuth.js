//use routers to make your routes more modular
const router = require("express").Router();
const pool = require("../db");
const bcrypt = require("bcrypt");
const jwtGenerator = require("../utils/jwtGenerator");

//register
//postman: http://localhost:5000/auth/register
router.post("/register", async (req, res) => {
  try {
    //1: destructure req.body (ce vine din post/front)
    const { name, email, password } = req.body;

    //2: check user exists (if exists => err; )
    const user = await pool.query("select * from users where user_email = $1", [
      email,
    ]);
    //if true => user already exists
    if (user.rows.length !== 0) {
      return res.status(401).send("user already exists");
    }

    //3 bcrypt the user pass
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);

    const bcryptPassword = await bcrypt.hash(password, salt);

    //4 enter new user in db
    const newUser = await pool.query(
      "insert into users (user_name, user_email, user_password) VALUES ($1, $2, $3) returning *  ",
      [name, email, bcryptPassword]
    );

    // res.json(user.rows[0]); //daca pui asta aici nu iti mai genereaza token

    //5 generate jwt token
    const token = jwtGenerator(newUser.rows[0].user_id);
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("server err");
  }
});

module.exports = router;
