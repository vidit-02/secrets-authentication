//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const app= express();
const pg = require("pg");
const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
const Strategy = require("passport-local");
const env = require("dotenv");
const Googlestrategy = require("passport-google-oauth2");
env.config();
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie:{
    maxAge: 1000 * 60 * 60 * 24, //indicate the life of cookie right now it is one day
  },
})
);
app.use(passport.initialize());
app.use(passport.session());
//the order pf above three lines should be maintained

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended:true
}));
const saltRounds = 10;

const db = new pg.Client({
  user:process.env.PG_USER,
  host:process.env.PG_HOST,
  database:process.env.PG_DATABASE,
  password:process.env.PG_PASSWORD,
  port:process.env.PG_PORT,
})
db.connect();

app.get('/',function(req,res){
  res.render("home");
})

app.get('/login',function(req,res){
  res.render("login");
})

app.get('/register',function(req,res){
  res.render("register");
})

app.get('/secrets',function(req,res){
  console.log(req.user);
  if(req.isAuthenticated()){
    res.render("secrets.ejs");
  }else{
    res.redirect("/login");
  }
})

app.get('/auth/google',passport.authenticate("google",{
  scope: ["profile","email"],
}))
app.get('/auth/google/secrets',passport.authenticate("google",{
  successRedirect: "/secrets",
  failureRedirect: "/login"
}))
app.get('/logout',function(req,res){
  req.logout((err)=>{
    if(err) console.log(err);
    res.redirect("/");
  })
})
app.post('/login',passport.authenticate("local",{
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

app.post('/register', async (req,res)=>{
  const email = req.body.username;
  const password = req.body.password;
  try{
    const checkEmail = await db.query("SELECT * FROM users WHERE email = $1",[email]);
    if(checkEmail.rows.length > 0){
      res.send("email already exist");
    } else {
      bcrypt.hash(password,saltRounds,async (err,hash)=>{
        if(err){
          console.log("error hashing ",err);
        } else{
          const result = await db.query("INSERT INTO users (email,password) VALUES ($1,$2) RETURNING *",[email,hash]);
          //console.log(result);
          const user = result.rows[0];
          // res.render("secrets.ejs");
          req.login(user, (err)=>{
            console.log(err);
            res.redirect("/secrets");
          })
        }

      })

    }
  } catch(err){
    console.log(err);
  }

})
passport.use("local",new Strategy(async function verify(username,password,cb){
  
  try{
    const checkEmail= await db.query("SELECT * FROM users WHERE email = $1",[username]);
    if(checkEmail.rows.length == 0){
      //alert("Kindly register");
      //res.render("register.ejs");
      return cb("User not Found");
    }
    else {
      bcrypt.compare(password,checkEmail.rows[0].password,(err,result)=>{
      if(err){
        return cb(err);
      }else{
        if(result){
          return cb(null, checkEmail.rows[0]);
        } else{
          return cb(null,false);
        }
      }
      })

      //console.log(checkEmail);
    }
  }catch(err){
    return cb(err);
  }
}))

passport.use("google", new Googlestrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:"http://localhost:3000/auth/google/secrets",
  userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo",
}, async (accessTOken, refreshToken, profile, cb)=>{
  console.log(profile);
  try{
    const result= await db.query("SELECT * FROM users WHERE email = $1",[profile.email]);
    if(result.rows.length === 0){
      const newUser = await db.query("INSERT INTO users (email,password) VALUES ($1,$2)",[profile.email, "google"])
      cb(null,newUser);
    }
    else{
      //existing user
      cb(null,result.rows[0]);
    }
  }catch{
    cb(err);

  }
}))
passport.serializeUser((user, cb)=>{
  cb(null,user);
})
passport.deserializeUser((user,cb)=>{
  cb(null,user);
})
app.listen(3000,function(){
  console.log("server started on port 3000");
});
