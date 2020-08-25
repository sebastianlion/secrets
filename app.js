//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
//const encrypt = require("mongoose-encryption"); esto es para el userSchema.plugin
//const md5 = require("md5");
//const bcrypt = require("bcrypt"); //es para encriptar con hash salt(Agregar numeros aleatorios) y saltrounds
//const saltRounds = 10; //Es para definir cuantas rondas de salt osea de agregar numeros al hash vamos a hacer
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

const findOrCreate = require('mongoose-findorcreate');

const app = express();


app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    appId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate); //para que la funcion de la linea 63 funcione, esta fue tomada desde passport para la estrategia de google 

//const secret = process.env.SECRET;
 //Se usara esta palabra para encriptar, ahora esta en el .env
//userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"]}); //todo lo creado con "userSchema" sera encriptado por la variable secret de arriba
//con encryptedFields se selecciona que campos se desea encriptar

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//passport.serializeUser(User.serializeUser()); //Es para colocarle las cookies al usuario
//passport.deserializeUser(User.deserializeUser()); //Es para abrir las cookies y saber que hay dentro

passport.serializeUser(function(user, done){
    done(null, user.id);
});

passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,   
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ appId: profile.id }, function(err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_PASSWORD,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    //profileFields: ['id', 'displayName', 'photos', 'email']
},
    function(accessToken, refreshToken, profile, cb){
        console.log(profile);
        User.findOrCreate({ appId: profile.id}, function(err, user){
            return cb(err, user);
        });
    }
));

app.get("/", function(req, res){
    res.render("home");
});

app.get("/auth/google", 
    passport.authenticate("google", { scope: ["profile"]})
    );

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login"}),
    function(req, res){
        res.redirect("/secrets");
    });

app.get("/auth/facebook",
    passport.authenticate("facebook", { scope: ["profile"]})
    );

app.get("/auth/facebook/secrets",
    passport.authenticate("facebook", { failureRedirect: "/login"}),
    function(req, res){
        res.redirect("/secrets");
    });
    

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){

    User.find({"secret": {$ne:null}}, function(err, foundUsers){ //esta linea dice que busque el campo llamado "secret" y de ese campo $ne:null que significa no equal to null osea que sean diferentes a null
        if(err){
            console.log(err);
        } else {
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
/*     if(req.isAuthenticated()){
        res.render("secrets");
    } else {
        res.redirect("/login");
    } */
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;

    console.log(req.user.id);

    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        } else {
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.get("/logout", function(req, res){
    req.logout(); //Para eliminar las cookies y cerrar las sesiones
    res.redirect("/");
});



app.post("/register", function(req, res){

    User.register({username: req.body.username}, req.body.password, function(err, user){ //Este metodo viene de passport-local-mongoose
        if(err){
            console.log(err);
            res.redirect("/register");
        } else {
             passport.authenticate("local")(req, res, function(){ //Para crear las cookies y abrir sesion
                 res.redirect("/secrets");
             });
        }
    }); 

/*     bcrypt.hash(req.body.password, saltRounds, function(err, hash){ //Con esta funcion podemos encriptar el primer parametro(la contraseña) con la cantidad de saltRounds que son el segundo parametro

        const newUser = new User({
            email: req.body.username,
            password: hash
        });
    
        newUser.save(function(err){
            if(err){
                console.log(err);
            } else {
                res.render("secrets");
            }
        });

    }); */

});

app.post("/login", function(req, res){

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){ //Este metodo viene de passport
        if(err){
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){ //Para crear las cookies y abrir sesion
                res.redirect("/secrets");
            });
        }
    });
/*     const username = req.body.username;
    const password = req.body.password

    User.findOne({email: username}, function(err, foundUser){
        if(err){
            console.log(err);
        } else {
            if(foundUser){
                bcrypt.compare(password, foundUser.password, function(err, result){
                    if(result === true){
                        res.render("secrets");
                    }
                });
            }
        }
    }); */
});





app.listen(3000, function(){
    console.log("Server started on port 3000.");
});