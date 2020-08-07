const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcryptjs = require('bcryptjs');
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const mongoDB = process.env.MONGODB_AUTH_BASICS;
mongoose.connect(mongoDB, { useUnifiedTopology: true, useNewUrlParser: true });

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'mongo connection error'));

const User = mongoose.model('User', new Schema({
	username: { type: String, required: true },
	password: { type: String, required: true }})
);

const app = express();
app.set('views', __dirname);
app.set('view engine', 'ejs');

app.use(session({ secret: 'cats', resave: false, saveUninitialized: true }));

/* Passport Functions */
/* Check the user and password in the database */
passport.use(
	new LocalStrategy((username, password, done) => {
		User.findOne({ username: username }, (error, user) => {
			if(error)
				return done(error);

			if(!user)
				return done(null, false, { msg: 'Incorrect username' });

			bcryptjs.compare(password, user.password, (error, response) => {
				if(response){
					// passwords match! log user in
					return done(null, user)
				}else{
					// passwords do not match!
					return done(null, false, { msg: 'Incorrect password' });
				}
			});

			return done(null, user);
		});
	})
);

/* Store the user's data in a cookie to keep them logged in */
passport.serializeUser(function(user, done){
	done(null, user.id);
});

passport.deserializeUser(function(id, done){
	User.findById(id, function(error, user){
		done(error, user);
	});
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get('/', (req, res) => { res.render('index', { user: req.user }) });
app.get('/sign-up', (req, res) => res.render('sign-up-form'));
app.post('/sign-up', (req, res, next) => {
	bcryptjs.hash(req.body.password, 10, (error, hashedPassword) => {
		if(error)
			res.redirect('/');

		/* Success */
		const user = new User({
			username: req.body.username,
			password: hashedPassword
		}).save(err => {
			if (err) {
				return next(err);
			};
			res.redirect('/');
		});
	});
});
app.get('/log-in', (req, res) => { res.render('log-in') });
app.post('/log-in', passport.authenticate('local', {
		successRedirect: '/',
		failureRedirect: '/'
	})
);
app.get('/log-out', (req, res) => {
	req.logout();
	res.redirect('/');
});


app.listen(3000, () => { console.log('App listening on port 3000!'); });
