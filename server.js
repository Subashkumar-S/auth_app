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

mongoose.connect("mongodb+srv://subashs2232:subash2232@cluster0.ha0obgf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0");
const connection = mongoose.connection;
connection.on( 'open' , () => { console.log("Database connected")});

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(router);
app.use(session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());

authUser = (email, password, done) => {
    console.log('Authenticating user:', email);
    User.findOne({"email": email}, function(err, user){
        if(err) {
            console.error('Error finding user:', err);
            return done(err);
        } else if(!user){
            console.log('User not found:', email);
            return done(null, false);
        } else if(!user.password){
            console.log('User has no password:', email);
            return done(null, false);
        }
        console.log("User found and authenticated:", email);
        return done(null, user);
    });
}


passport.use(new LocalStrategy( 'local' ,authUser));
passport.serializeUser((user, done) =>{

    done(null, user.id);
});
passport.deserializeUser((id, done) =>{
    User.findById(id, function(err, user) {
        done(err, user);
    });
})




router.get('/', (req, res) => {
    res.send('Home page!');
  })

router.get('/signup', (req, res) => {
    res.render('signup.ejs');
})

router.post('/signup', async (req, res) => {
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
        res.redirect("/user");
        return res.status(201).json(user);

    }

   } catch (err){
    return res.status(400).json({message: err.message});
   }
})

router.get('/user', (req, res) => {
    res.send('User page!');
})

router.get('/login', (req, res) => {
    res.render('login.ejs');
})

router.post('/login', passport.authenticate('local', {
    successRedirect: "/user",
    failureRedirect: "/login"
}))
  
app.listen(port, () => {
    console.log(`Server listening on port ${port}`)
  })