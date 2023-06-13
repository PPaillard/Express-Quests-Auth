const argon2 = require("argon2");
const jwt = require("jsonwebtoken");

const secret = process.env.JWT_SECRET;
const expDelay = process.env.EXP_DELAY;

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

const verifyPassword = (req, res) => {
  // hash the password using argon2 then call next()
  argon2
    .verify(req.user.hashedPassword, req.body.password)
    .then((isVerified) => {
      if (!isVerified) return res.sendStatus(401);

      // le password est verifié
      const token = jwt.sign({ sub: req.user.id }, secret, {
        expiresIn: expDelay,
      });
      res.send(token);
    })
    .catch((err) => {
      console.error(err);
      res.sendStatus(400);
    });
};

const verifyToken = (req, res, next) => {
  try {
    //next();
    const authorizationHeader = req.get("Authorization");
    // si ya pas d'authorization dans le header
    if (!authorizationHeader) throw new Error("Authorization required");

    const [tokenType, token] = authorizationHeader.split(" ");

    if (tokenType !== "Bearer") throw new Error("Wrong token type");

    req.payload = jwt.verify(token, secret);
    next();
  } catch (err) {
    console.error(err);
    res.sendStatus(401);
  }
};

module.exports = {
  hashPassword,
  verifyPassword,
  verifyToken,
};
