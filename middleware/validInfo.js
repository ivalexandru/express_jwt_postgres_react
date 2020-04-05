//you can use expres validator for this

module.exports = (req, res, next) => {
  const { email, name, password } = req.body;

  function validEmail(userEmail) {
    return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(userEmail);
  }

  if (req.path === "/register") {
    console.log(!email.length);
    //check if empty
    if (![email, name, password].every(Boolean)) {
      return res.status(401).json("need email, name and passwd");
    } else if (!validEmail(email)) {
      return res.status(401).json("Invalid Email");
    }
  } else if (req.path === "/login") {
    if (![email, password].every(Boolean)) {
      return res.status(401).json("need email, name and passwd");
    } else if (!validEmail(email)) {
      return res.status(401).json("Invalid Email");
    }
  }
  //if all above is k, continue on with the route
  next();
};
