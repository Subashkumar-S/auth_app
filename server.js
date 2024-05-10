const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const {Schema}  = mongoose;
const app = express();
const router = express.Router();
const passport = require('passport');
const session = require('express-session');
const LocalStrategy = require('passport-local').Strategy;
const port = 8080;
require("dotenv").config();
// const methodOverride = require('method-override');
const bodyParser = require('body-parser');



const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: true
    },
    userName: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true
    }
})

const User = mongoose.model('User', userSchema);

mongoose.connect(process.env.MONGO_URL);
const connection = mongoose.connection;
connection.on( 'open' , () => { console.log("Database connected")});

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(router);
// app.use(methodOverride('_method'))





passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    console.log('Authenticating user called: ' + email);
    try {
        const user = await User.findOne({ email });
        console.log('User retrieved from database:', user);

        if (!user) {
            console.log('User not found:', email);
            return done(null, false);
        }
         console.log("Entered password: " + password);

        console.log("Retrieved password from database:", user.password);
        const hashedPassword = await user.password;
        console.log("Hashed password from database:", hashedPassword);

        console.log("Password for comparing "+ password);
        console.log("Hashed password for comparing " + hashedPassword);
        const passwordMatch = await bcrypt.compare(password, hashedPassword);
        console.log("password match :" + passwordMatch);
        if (!passwordMatch) {
            console.log('Incorrect password for user:', email);
            return done(null, false);
        }
        console.log('User authenticated:', email);
        return done(null, user);
    } catch (err) {
        console.error('Error finding user:', err);
        return done(err);
    }
}));



passport.serializeUser((user, done) =>{
    done(null, user.id);
});
passport.deserializeUser((id, done) =>{
    console.log("---------> Deserialize Id");
    console.log(id);
    User.findById(id)
        .then(user => {
            done(null, user);
        })
        .catch(err => {
            done(err, null);
        });
    // done(id, user);
})




router.get('/', (req, res) => {
    res.render('home');
  })

router.get('/signup', checkNotAuthenticated, (req, res) => {
    res.render('signup');
})

router.post('/signup', checkNotAuthenticated, async (req, res) => {
   try{
    let user = await User.findOne({'email': req.body.email});
    if(user){
        res.status(400).send("User already exists. Please login");
    } else {
        const password = await
        bcrypt.hash(req.body.password, 10)
        .then(console.log("password hashed successfully"))
        .catch(err => { console.log(err);});

        const user = new User({
            fullName: req.body.fullName,
            userName: req.body.userName,
            email: req.body.email,
            password: password
        })
        user.save()
            .then(user => { console.log("user saved successfully", user)})
            .catch(err => {console.log("error saving user", err)});
            res.redirect("/login");
    }

   } catch (err){
    return res.status(400).json({message: err.message});
   }
})

router.get('/dashboard', checkAuthenticated, (req, res) => {
    console.log("request to dashboard" +req.user);
    const userName = req.user.fullName;
    res.render('dashboard', { name: userName });
})

router.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login');
})

app.post('/login', checkNotAuthenticated,
    passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
}));




app.post('/logout', (req, res) => {
  req.logOut((err) => {
    if(err){
        console.error(err);
        res.status(500).send('Error during logout');
    }
  });
  res.redirect('/');
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next()
  }

  res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/dashboard');
  }
  next()
}

app.listen(port, () => {
    console.log(`Server listening on port ${port}`)
  })