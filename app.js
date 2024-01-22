//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const app= express();
const pg = require("pg");
const bcrypt = require("bcrypt");


app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended:true
}));
const saltRounds = 10;

const db = new pg.Client({
  user:"postgres",
  host:"localhost",
  database:"Secrets",
  password:"vidit06",
  port: 5432,
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

app.post('/login', async (req,res)=>{
  const email = req.body.username;
  const password = req.body.password;
  try{
    const checkEmail= await db.query("SELECT * FROM users WHERE email = $1",[email]);
    if(checkEmail.rows.length == 0){
      //alert("Kindly register");
      res.render("register.ejs");
    }
    else {
      bcrypt.compare(password,checkEmail.rows[0].password,(err,result)=>{
      if(err){
        console.log(error);
      }else{
        if(result){
          res.render("secrets.ejs");
        } else{
          res.send("wrong password");
        }
      }
      })

      //console.log(checkEmail);
    }
  }catch(err){
    console.log(err);
  }

})

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
          const result = await db.query("INSERT INTO users (email,password) VALUES ($1,$2)",[email,hash]);
          console.log(result);
          res.render("secrets.ejs");
        }

      })

    }
  } catch(err){
    console.log(err);
  }

})

app.listen(3000,function(){
  console.log("server started on port 3000");
});
