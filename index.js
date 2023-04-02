const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')

const app = express()
const port = 3000

app.use(logger('dev'))
app.use(cookieParser())

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
  function (username, password, done) {
    if (username === 'walrus' && password === 'walrus') {
      const user = { 
        username: 'walrus',
        description: 'the only user that deserves to contact the fortune teller'
      }
      return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
    }
    return done(null, false)  // in passport returning false as the user object means that the authentication process failed. 
  }
))

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.

app.get('/', (req, res) => {
  console.log(req.cookies)
  jwt.verify(req.cookies.session, jwtSecret, (err, decoded) => {
    if (err) {
      console.log('Invalid token')
      res.redirect('/login')
    } else {
      console.log('Valid token')
      console.log(decoded)
      res.send(fortune.fortune())
    }
  })
})

app.get('/login',
  (req, res) => {
    res.sendFile('pages/login.html', { root: __dirname })
  }
)

app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => { 
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
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
      secure: true, // Set to true if using HTTPS
      maxAge: 1000 * 60 * 60 * 24 // Cookie expires in 1 day
    }
    res.cookie('session', token, options)

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    //res.json(token)
    res.redirect('/');
    
    // And let us log a link to the jwt.io debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})