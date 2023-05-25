const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const scryptMcf = require('scrypt-mcf')
const fs = require('fs');
const { performance } = require('perf_hooks');
const OAuth2Strategy = require('passport-oauth2');
const path = require('path');

const app = express()
const port = 3000

app.use(logger('dev')); // Logs for development
app.use(cookieParser()); // Parse cookies correctly

// Custom middleware to check if cookies are valid
const isAuthenticated = (req, res, next) => {
  // Store the decoded cookies in req.user
  if (req.cookies.session) {
    jwt.verify(req.cookies.session, jwtSecret, (err, decoded) => { if (!err) req.user = decoded.sub; })
  }

  if (req.user) next(); // User is logged in
  else res.redirect('/auth/error'); // Redirect to login route
};

/*
  Configure the local strategy for using it in Passport.
  The local strategy requires a `verify` function which receives the credentials
  (`username` and `password`) submitted by the user.  The function must verify
  that the username and password are correct and then invoke `done` with a user
  object, which will be set at `req.user` in route handlers after authentication.
*/
passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
  async (username, password, done) => {
    // Check usernames and passwords
    const usersData = fs.readFileSync('users.txt', 'utf8');
    const users = usersData.trim().split('\n').map(line => {
      const [username, hashedPass] = line.trim().split(':');
      return { username, hashedPass };
    });

    var user = null;
    for (const testUser of users) {
      if (testUser.username !== username) continue;
      const result = await scryptMcf.verify(password, testUser.hashedPass)
      if (result) {
        user = testUser;
        return done(null, user); // Return the user
      } else {
        return done(null, false) // The password is not valid
      }
    }
    return done(null, false) // The user does not exist
  })
);

// OAuth2 strategy configuration
passport.use('oauth2-github', new OAuth2Strategy(
  {
    authorizationURL: 'https://github.com/login/oauth/authorize',
    tokenURL: 'https://github.com/login/oauth/access_token',
    clientID: '468283da79286228955a',
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/github/callback'
  },
(accessToken, refreshToken, profile, done) => {
  // OAuth2 does not provide any information about the user. We only know a unique access token
  // We use that access token to identify the user
  profile = { accessToken: accessToken }
  return done(null, profile);
})
);

// Generate the session token. The identifier must be a unique string for every user.
const addSessionJWT = (res, identifier) => {
  // This is what ends up in our JWT
  const jwtClaims = {
    sub: identifier,
    iss: 'localhost:3000',
    aud: 'localhost:3000',
    exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
    role: 'user' // just to show a private JWT field
  }

  // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
  const token = jwt.sign(jwtClaims, jwtSecret)

  // Store the token in a cookie
  const options = {
    httpOnly: true,
    secure: false, // Set to true if using HTTPS (it is false to make it work with Safari https://github.com/sveltejs/kit/issues/6632)
    maxAge: 1000 * 60 * 60 * 24, // Cookie expires in 1 day
  }

  res.cookie('session', token, options);
}

app.use(express.urlencoded({ extended: true })) // Needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // We load the passport auth middleware to our express application. It should be loaded before any route.


// Routes
app.get('/', isAuthenticated, (req, res) => {
  res.send(fortune.fortune());
})

app.get('/login',
  (req, res) => {
    res.sendFile('pages/login.html', { root: __dirname })
  }
)

// Error routes
app.get('/auth/error', (req, res) => res.send('Authentication Error'));

// Logout route
app.get('/logout',
  (req, res) => {
    // Reset cookie and redirect to the login page
    res.clearCookie('session')
    res.redirect('/login')
  }
)

// Authentication routes
app.post('/login',
  passport.authenticate('username-password', { failureRedirect: '/auth/error', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => {
    addSessionJWT(res, req.user.username);
    res.redirect('/');
  }
)

app.get('/auth/github', passport.authenticate('oauth2-github', { failureRedirect: '/auth/error', session: false }));
app.get(
  '/auth/github/callback',
  passport.authenticate('oauth2-github', {
    failureRedirect: '/auth/error',
    session: false, // Disable session support 
  }),
  (req, res) => {
    addSessionJWT(res, req.user.accessToken);
    res.redirect('/');
  });

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})

