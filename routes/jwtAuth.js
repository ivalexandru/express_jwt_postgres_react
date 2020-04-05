//use routers to make your routes more modular
const router = require("express").Router();
const pool = require("../db");
const bcrypt = require("bcrypt");
const jwtGenerator = require("../utils/jwtGenerator");
const validInfo = require("../middleware/validInfo");
const authorization = require("../middleware/authorization");

//register
//postman: http://localhost:5000/auth/register
//USE MIDDEWARE IN THERE (validInfo)
//iar daca nu introduci nume, sau mail sau parola, validInfo te impiedica sa inregistrezi user.
router.post("/register", validInfo, async (req, res) => {
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
    // err: Cannot set headers after they are sent to the client

    //5 generate jwt token
    const token = jwtGenerator(newUser.rows[0].user_id);
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("server err");
  }
});

//login route
router.post("/login", validInfo, async (req, res) => {
  try {
    //1 destructure req.body
    const { email, password } = req.body;

    //2 check if user exists, if not err
    const user = await pool.query("select * from users where user_email =$1", [
      email,
    ]);

    if (user.rows.length === 0) {
      return res.status(401).json("user does not exist");
    }

    //3 check if posted pass matches with db pass
    //user.rows[0].user_password is the pass stored in the db
    const validPassword = await bcrypt.compare(
      password,
      user.rows[0].user_password
    );
    // console.log(validPassword); // true

    if (!validPassword) {
      return res.status(401).json("passwd or mail incorrect");
    }

    //4 give usr jwt token
    const token = jwtGenerator(user.rows[0].user_id);
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("server err");
  }
});

router.get("/is-verified", authorization, async (req, res) => {
  try {
    //if token is valid (conf authorization middleware used here )
    res.json(true);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("server err");
  }
});

module.exports = router;
