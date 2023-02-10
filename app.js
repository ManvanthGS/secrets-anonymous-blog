require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const encrypt = require("mongoose-encryption");

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(
  session({
    secret: "This is a secret.",
    resave: true,
    saveUninitialized: true,
    // cookie: { secure: true }         set this to true only if you are using https server or else req.isAuthenticated() always returns false
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/usersDB");

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//mongoose encryption

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });


//creating local strategy to register users
const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

//use these below 2 lines to serialize users for only local strategies
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//use these lines for general strategies
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
        // console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
//   if (req.isAuthenticated()) {
//     res.render("secrets");
//   } else {
//     res.redirect("/login");
//   }
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if(err){
            console.log(err);
        } else {
            res.render("secrets", {usersWithSecrets: foundUsers});
        }
    })

});

app.get("/submit", function(req, res){
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    }
  });
  res.redirect("/");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

//using bcrypt hashing to save and authenticate passowrds

/*

app.post("/register", function(req, res){

    bcrypt.hash(req.body.password, 5, function(err, hash) {
        // Store hash in your password DB.
        const newUser = new User({
            username: req.body.username,
            password: hash
            // password: md5(req.body.password)
        });
        newUser.save(function(err){
            if(err){
                console.log(err);
            }else{
                res.render("secrets");
            }
        });
    });
});

app.post("/login", function(req, res){
    const userName = req.body.username;
    const password = req.body.password;
    // const password = md5(req.body.password);

    const findUser = User.findOne({email:userName}, function(err, foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                bcrypt.compare(password, foundUser.password, function(err, result) {
                    if(result === true){
                        res.render("secrets");
                    }else{
                        res.send("You have entered an incorrect password please try again");
                    }
                });
            }else{
                res.send("You have not registered to the website please register first and then try again.");
            }
        }
    });
});

*/

//using passport(node module) authentication

app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );

  // User.register({username: req.body.username, email: req.body.username}, req.body.password, function(err, user) {
  //     if (err) {
  //         console.log(err);
  //         res.redirect("/register");
  //     } else {
  //         const authenticate = User.authenticate();
  //         authenticate(req.body.username, req.body.password, function(err, result) {
  //             if (err) {
  //                 console.log(err);
  //                 res.redirect("/register");
  //             } else {
  //                 res.redirect("/secrets");
  //             }
  //         });
  //     }
  // });
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
      res.redirect("/login");
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    // console.log(req.user);
    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        } else {
            foundUser.secret = submittedSecret;
            foundUser.save(function(err){
                if(err){
                    console.log(err);
                } else {
                    res.redirect("/secrets");
                }
            });
        }
    });
});

app.listen(3000, () => console.log("server is listening on port 3000"));
