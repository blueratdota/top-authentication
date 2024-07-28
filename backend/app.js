const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const pool = new Pool({
  user: process.env.DB_USER, // AWS MASTER USERNAME
  password: process.env.DB_PASSWORD, // AWM MASTER PASSWORD
  host: process.env.DB_HOSTNAME,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: false
  }
});
// const pgPool = new Pool({
//   user: process.env.DB_USER, // AWS MASTER USERNAME
//   password: process.env.DB_PASSWORD, // AWM MASTER PASSWORD
//   host: process.env.DB_HOSTNAME,
//   port: process.env.DB_PORT,
//   database: process.env.DB_SESSION,
//   ssl: {
//     rejectUnauthorized: false
//   }
// });

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(
  session({
    secret: "cats",
    resave: false,
    saveUninitialized: true,
    store: new pgSession({
      pool: pool, // Connection pool
      tableName: "session" // Use another table-name than the default "session" one
    }),
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
  })
);
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});
app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.get("/log-in", (req, res) => res.render("log-in"));
app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/sign-up", async (req, res, next) => {
  try {
    // console.log(req.body);

    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) {
        return alert("xxx");
      }
      await pool.query(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        [req.body.username, hashedPassword]
      );
    });
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  })
);

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );

      console.log(rows);
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passwords do not match!
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.listen(3000, () => console.log("app listening on port 3000!"));
