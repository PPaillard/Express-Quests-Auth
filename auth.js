const argon2 = require("argon2");

const hashPassword = (req, res, next) => {
  // hash the password using argon2 then call next()
  argon2
    .hash(req.body.password)
    .then((hashedPassword) => {
      // for security reason, we clear the plain password
      delete req.body.password;
      // fill the req.body so we can access the hashedpassword
      //in next middlewares
      req.body.hashedPassword = hashedPassword;
      next();
    })
    .catch((err) => {
      console.error(err);
      res.sendStatus(400);
    });
};

module.exports = {
  hashPassword,
};
