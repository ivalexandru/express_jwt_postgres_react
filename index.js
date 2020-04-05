const express = require("express");
const app = express();
const cors = require("cors");

//mid
app.use(express.json()); //acc req.body
app.use(cors());

//routes
app.use("/auth", require("./routes/jwtAuth"));

//dashboard route
app.use("/dashboard", require("./routes/dashboard"));

app.listen(5000, () => {
  console.log("srv r on p 5k");
});
