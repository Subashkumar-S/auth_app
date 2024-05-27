// var atatus = require("atatus-nodejs");
// atatus.start({
//     licenseKey: "lic_apm_dbee7fd40fb84e39b8e4376563a6a850",
//     appName: "authentication_app",
//     enabled: true,
//     analytics: true,
//     analyticsCaptureOutgoing: true,
//     logBody: "all",
//     notifyHost: '10.40.30.105',
//     notifyPort: '8091',
//     useSSL: false,
//     // logLevel: "debug",
//     // proxy: "http://localhost:5000"
// });
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const {Schema}  = mongoose;
const app = express();
const router = express.Router();
const passport = require('passport');
const session = require('express-session');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
// const port = 5000;
require("dotenv").config();
// const methodOverride = require('method-override');
const bodyParser = require('body-parser');
const redis = require('redis');
const RedisStore = require('connect-redis').default;
const redisClient = redis.createClient();
const nsq = require('nsqjs');

(async() => {
    await redisClient.connect();
})();

redisClient.on('error', function(err){
    console.log("Could not establish a connection with redis"+ err);
});

redisClient.on('ready' , function(err){
    console.log("Connected to redis");
})
const redisStore = new RedisStore({
    client: redisClient
});

const writer = new nsq.Writer('127.0.0.1', 4150);
// writer.on('ready', () => {
//     console.log('NSQ Writer connected successfully');
//     // Start publishing messages here or perform other operations
// });

// // Event listener for NSQ connection errors
// writer.on('error', (err) => {
//     console.error('NSQ Writer connection error:', err);
// });

// // Event listener for connection close
// writer.on('closed', () => {
//     console.log('NSQ Writer connection closed');
// });
writer.connect();




const User = require("./models/userModel.js");

mongoose.connect(process.env.MONGO_URL);
const connection = mongoose.connection;
connection.on( 'open' , () => { console.log(" MongoDB connected")});

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
    secret: "secret",
    store:redisStore,
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(passport.authenticate('session'));
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

passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:5000/auth/google/callback",
    passReqToCallback: true
  }, async (request, accessToken, refreshToken, profile, done) => {
      try {
          let user = await User.findOne({ email: profile.email });
          console.log("user from google" + JSON.stringify(profile));
          if (user) {
              user.googleId = profile.id;
          } else {
              user = new User({
                  fullName: profile.displayName,
                  userName: profile.email,
                  email: profile.email,
                  password: await bcrypt.hash(profile.email, 10),
                  googleId: profile.id,
              });
          }

          await user.save();

          return done(null, user);
      } catch (err) {
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
    const sess = req.session;

    console.log(sess);
    console.log("request to dashboard" +req.user);
    const userName = req.user.fullName;
    res.render('dashboard', { name: userName });
})

router.get("/auth/google",checkNotAuthenticated, passport.authenticate('google', {
    scope: ['email', 'profile']
}));

router.get("/auth/google/callback",checkNotAuthenticated, passport.authenticate('google', {
    successRedirect: "/dashboard",
    failureRedirect: "/login"
}));

router.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login');
})

router.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    failureRedirect: '/login',
    failureFlash: true
}), async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            console.log("email sending function is called");
            const email = req.user.email;
            const text = 'Login successful';
            await publishEmailNotification(email, text);
            res.redirect('/dashboard');
        } else {
            res.redirect('/login');
        }
    } catch (error) {
        console.error('Error in login route:', error);
        res.redirect('/error');
    }
});




 function publishEmailNotification(email, text) {
  const message = JSON.stringify({
    email: email,
    text: text
  });

  try {
     writer.publish('login', message);
    console.log('Message published to login topic');
    if (writer) {
       writer.close();
      console.log('NSQ Writer connection closed successfully');
    }
  } catch (error) {
    console.error('Error publishing message:', error);
    if (writer) {
       writer.close();
      console.log('NSQ Writer connection closed due to error');
    }
  }
}






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

const server = app.listen(5000, () => {
    console.log(`Server listening on port 5000`);
});

server.on('error', (err) => {
    console.error('Server error:', err);
});

