var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require('express-session');
var passport = require('passport');
var OidcStrategy = require('passport-openidconnect').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

//configuration
app.use(session({
  secret: 'MyVoiceIsMyPassportVerifyMe',
  resave: false,
  saveUninitialized: true
}));

//Configuration that tells Express to use Passport for sessions
app.use(passport.initialize());
app.use(passport.session());

// set up passport
passport.use('google', new GoogleStrategy({
  clientID: '966852441551-vanor6vqvnomitk14qei5185tckkh330.apps.googleusercontent.com',
  clientSecret: 'NA1VNyk6lhjkhjAx79IQyjUL',
  callbackURL: 'http://localhost:3000/auth/google/callback',
  tokenURL: 'https://www.googleapis.com/oauth2/v3/token'
}, (accessToken, refreshToken, profile, done) => {
  if (profile) {
    user = profile;
    return done(null, user);
  } else {
    return done(null, false);
  }
}));

// Tells Passport.js how to serialize the user information into a session
passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});

app.use('/', indexRouter);
app.use('/users', usersRouter);

//ensure only logged in users can get to the profile page
function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect('/login')
}

// app.use('/login', passport.authenticate('google'));

app.get('/auth/google', passport.authenticate('google', { scope: ['https://www.googleapis.com/auth/plus.login'] }));


app.use('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/error' }),
  (req, res) => {
    res.redirect('/profile');
  }
);

//Profile route
app.use('/profile', ensureLoggedIn, (req, res) => {
  res.render('profile', { title: 'Express', user: req.user });
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

//Logout
app.get('/logout', (req, res) => {
  req.logout();
  req.session.destroy();
  res.redirect('/');
});

module.exports = app;
