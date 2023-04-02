::: container
::: row
::: col-lg-4
#### Table of contents

-   [1. Preparing your project](#1-preparing-your-project)
    -   [1.1. Node.js](#11-nodejs)
    -   [1.2. Express](#12-express)
-   [2. Express Hello World](#2-express-hello-world)
-   [3. Route handlers](#3-route-handlers)
-   [4. Middleware](#4-middleware)
    -   [4.1. Example: Adding an express logger
        middleware](#41-example-adding-an-express-logger-middleware)
    -   [4.2. Handling errors](#42-handling-errors)
-   [5. Authentication tutorial using passport.js authentication
    middleware](#5-authentication-tutorial-using-passportjs-authentication-middleware)
    -   [5.1. Passport installation](#51-passport-installation)
    -   [5.2. Setting up login with username/password (passport\'s
        \'local\'
        strategy)](#52-setting-up-login-with-usernamepassword-passports-local-strategy)
        -   [5.2.1. Create the route handlers for the
            login](#521-create-the-route-handlers-for-the-login)
        -   [5.2.2. Finishing the login
            process](#522-finishing-the-login-process)
    -   [5.3. Setting up an authenticated fortune-teller endpoint
        (passport\'s JWT
        strategy)](#53-setting-up-an-authenticated-fortune-teller-endpoint-passports-jwt-strategy)
        -   [5.3.1. Creating and sending the JWT to the user agent upon
            successful
            login](#531-creating-and-sending-the-jwt-to-the-user-agent-upon-successful-login)
-   [6. Do-it-yourself exercises](#6-do-it-yourself-exercises)
    -   [6.1. \[optional\] Add TLS certificates to your
        server](#61-optional-add-tls-certificates-to-your-server)
    -   [6.2. Exchange the JWT using
        cookies](#62-exchange-the-jwt-using-cookies)
    -   [6.3. Create the fortune-teller
        endpoint](#63-create-the-fortune-teller-endpoint)
    -   [6.4. Add a logout endpoint](#64-add-a-logout-endpoint)
    -   [6.5. Add a strong key derivation function to the login
        process](#65-add-a-strong-key-derivation-function-to-the-login-process)
    -   [6.6. Add Oauth2-based login to your
        server](#66-add-oauth2-based-login-to-your-server)
    -   [6.7. Add OpenID-Connect based login to your
        server](#67-add-openid-connect-based-login-to-your-server)
    -   [6.8. Create a new \'radius\' strategy based on the Local one in
        order to check users\' credentials against your RADIUS
        server](#68-create-a-new-radius-strategy-based-on-the-local-one-in-order-to-check-users-credentials-against-your-radius-server)
:::

::: {.col-lg-8 .main}
# Express with passport

Most of the contents of this tutorial have been taken directly (often
literally copy-pasted) from the wonderful documentation at [express
website](https://expressjs.com/) and the [MDN Web
Docs](https://developer.mozilla.org/en-US/docs/Learn/Server-side/Express_Nodejs/Introduction).

## 1. Preparing your project {#1-preparing-your-project tabindex="-1"}

### 1.1. Node.js {#11-nodejs tabindex="-1"}

In order to use express we need Node.js installed and operative. Node.js
can be installed in Windows, MacOS, and Linux by just visiting the
[Node.js website](https://nodejs.org/en/), and downloading and
installing the latest long-term support (LTS) version for your operating
system.

In MacOS and Linux is usually preferable to install Node.js using
[`n`](https://github.com/tj/n), which greatly simplifies installing
different versions of Node.js, and allows for installing Node.js in the
user space (instead of admin space), which is cleaner and safer.

> If you have previously installed Node.js using other means, please
> uninstall it first. For example, if you have a version installed using
> `apt`, you could remove with:
>
> ``` hljs
> $ sudo apt purge nodejs npm
> ```

Being confident that no other Node.js version is installed, just execute
the following command, which will guide you through the process of
installing `n` and the latest LTS version of Node.js.

``` hljs
curl -L https://git.io/n-install | bash
```

You will need to close and open again the terminal for the node
executable to be available in your prompt. After that, you check that
the latest LTS version is installed and running.

``` hljs
$ node -v
v18.15.0
```

> You can get which is the latest LTS version by visiting the [Node.js
> website](https://nodejs.org/en/). When this document was revisited for
> the last time, it was 18.15.0.

Although not needed for this lab exercise, you can use `n` to later
download other versions of Node.js. For example, you could run the
following command to install the latest, not necessarily LTS, version of
Node.js:

``` hljs
n latest
```

And you could switch between node.js versions just running:

``` hljs
n
```

which shows a menu to choose among the installed Node.js versions:

``` hljs
    node/18.15.0
  ο node/19.7.0

Use up/down arrow keys to select a version, return key to install, d to delete, q to quit
```

If you have installed any non-LTS version for testing just switch to the
LTS one.

### 1.2. Express {#12-express tabindex="-1"}

Let us just start with the classic \'hello world\' example.

Assuming you've already installed Node.js, create directory
`express-app` to hold your application, and make that your working
directory.

``` hljs
mkdir express-app
cd express-app
```

Use the `npm init` command to create a `package.json` file for your
application. For more information on how `package.json` works, see
[Specifics of npm's package.json
handling](https://docs.npmjs.com/files/package.json).

``` hljs
npm init
```

This command prompts you for a number of things, such as the name and
version of your application, and the entry point. The entry point refers
to the file that is executed by default when your project is
required/imported by an external project. For now, default values are
ok, and thus our entry point will be `index.js`.

Before starting to write our code in `index.js`, let us first install
Express in our project with:

``` hljs
npm install express
```

If you open the `package.json` file now, you will see that `express` has
been automatically added to the project dependencies. The caret (`^`) at
the front of the version number indicates that when installing, `npm`
will pull in the highest version of the package it can find where only
the major version has to match. This method of versioning dependencies
(major.minor.patch) is known as semantic versioning. You can read more
about it here: [About semantic
versioning](https://docs.npmjs.com/about-semantic-versioning).

Express has been installed in local mode, that is to say, that the
package along with all its dependencies have been installed to
`express-app/node_modules`. You can also check that there is a new file
`package-lock.json` that actually declares all the exact packages with
the exact version that are installed in your project (dependencies,
dependencies of dependencies, dependencies of dependencies of
dependencies, and so on). Obviously, `npm` manages to merge
`dependencies` and optimizes the required installations.

> If you have to share code, you don\'t need to share the (usually
> heavy) `node_modules` directories that contains all the project
> dependencies. With the `package.json` and the `package-lock.json`
> files, anyone can install the dependencies and regenerate exactly the
> same `node_modules` directory just running `npm install` in the
> project directory.

When requiring a package by name, if it is not bundled with Node.js
itself, Node.js will resolve the file to load by searching the `main`
entry in the `package.json` file in all the directories in the
project\'s `node_modules`, as well as in the globally installed
`node_modules` (you could also install modules globally so that they can
be used everywhere).

> **Note** Above paragraph is an utter simplification of the Node.js
> resolve algorithm. A `package.json` could define more entrypoints and
> switch between one and another based on some environment conditions.
> If interested, take a look at [Node.js high-level resolve algorithm in
> pseudocode](https://nodejs.org/api/modules.html#modules_all_together)

Now, we can now require the `express` package with
`const express = require('express')`, although we could (NOT
RECOMMENDED) directly require the file the `express` entry point as
`const express = require('./node_modules/express/index.js')` (assuming
that we are executing the `require` from our project root directory
`express-app`)

## 2. Express Hello World {#2-express-hello-world tabindex="-1"}

Create `index.js` with the following content:

``` hljs
const express = require('express')

const app = express()
const port = 3000

app.get('/', (req, res) => {
  res.send('hello world')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
```

This app starts a server and listens on port 3000 for connections. The
app responds with "hello world" for requests to the root URL, i.e. or
route `/`. For every other path, it will respond with a 404 Not Found.

Run the example with:

``` hljs
$ node index.js
Example app listening at http://localhost:3000
```

Open your browser and point it to <http://localhost:3000>, the server
response will be string \'hello world\'

## 3. Route handlers {#3-route-handlers tabindex="-1"}

In our `hello world` Express example (see above), we defined a
(callback) route handler function for HTTP GET requests to the site root
(\'/\').

``` hljs
app.get('/', (req, res) => {
  res.send('hello world')
});
```

The callback function takes a request and a response object as
arguments. In this case, the method calls
[`send()`](https://expressjs.com/en/4x/api.html#res.send) on the
response to return the string \'hello world\'.

There are a number of other response methods for ending the
request/response cycle, for example, you could call
[`res.json()`](https://expressjs.com/en/4x/api.html#res.json) to send a
JSON response or
[`res.sendFile()`](https://expressjs.com/en/4x/api.html#res.sendFile) to
send a file.

> **JavaScript tip**: You can use any argument names you like in the
> callback functions; when the callback is invoked the first argument
> will always be the request and the second will always be the response.
> It makes sense to name them such that you can identify the object
> you\'re working with in the body of the callback.

Besides [`app.get()`](https://expressjs.com/en/4x/api.html#app.get), the
Express application object also provides methods to define route
handlers for all the other HTTP verbs, which are mostly used in exactly
the same way, including:
[`app.delete()`](https://expressjs.com/en/4x/api.html#app.delete),
[`app.post()`](https://expressjs.com/en/4x/api.html#app.post),
[`app.put()`](https://expressjs.com/en/4x/api.html#app.put).

Routes allow you to match particular patterns of characters in a URL,
and extract some values from the URL and pass them as parameters to the
route handler (as attributes of the request object passed as a
parameter).

You can add another GET route:

``` hljs
app.get('/user', (req, res) => {
  const user = {
    name: 'walrus',
    description: 'it is what it is'
  }
  res.json(user)
})
```

And if you run your server again with `node index.js` you can point your
browser to <http://localhost:3000/user> and you will get the json:

``` hljs
{
  "name": "walrus",
  "description": "it is what it is"
}
```

## 4. Middleware {#4-middleware tabindex="-1"}

Middleware is used extensively in Express apps for tasks from serving
static files to error handling to compressing HTTP responses. Whereas
route functions end the HTTP request-response cycle by returning some
response to the HTTP client, middleware functions *typically* perform
some operation on the request or response, and then call the next
function in the "stack", which might be more middleware or a route
handler. The order in which middleware is called is up to the app
developer.

> **Note**: The middleware can perform any operation, execute any code,
> make changes to the request and response object, and it can also end
> the request-response cycle. If it does not end the cycle then it must
> call `next()` to pass control to the next middleware function (or the
> request will be left hanging).

Most apps will use third-party middleware to simplify common web
development tasks like working with cookies, sessions, user
authentication, accessing request POST and JSON data, logging, etc.

Some middlewares are distributed as part of express, and others have to
be installed/created manually.

Middleware and routing functions are called in the order that they are
declared. For some middlewares the order is important (for example if
session middleware depends on cookie-parser middleware, then the
cookie-parser one must be added first). Middlewares are chained and
called (in the order they are added), making changes to the request and
response object methods, before executing the route handlers; otherwise,
route handlers will not have access to functionality added by the
middlewares.

You can write your own middleware functions, and you are likely to have
to do so (if only to create error handling code). The **only**
difference between a middleware function and a route handler callback is
that middleware functions have a third argument `next`, which middleware
functions are expected to call until completing the request cycle.

You can add a middleware function to the processing chain for all
responses with `app.use()`, or for a specific HTTP verb using the
associated method: `app.get()`, `app.post()`, etc. Routes are specified
in the same way for both cases, though the route is optional when
calling `app.use()`.

The example below shows how you can add a middleware function using both
approaches, and with/without a route. Our middleware is just logging
\'request received\' when it is invoked.

``` hljs
const express = require('express')

const app = express()
const port = 3000

// An example middleware function
let a_middleware_function = function(req, res, next) {
  console.log('request invoked')
  next() // Call next() so Express will call the next middleware function in the chain.
}

// Function added with use() for all routes and verbs
app.use(a_middleware_function)

// Function added with use() for a specific route
app.use('/someroute', a_middleware_function)

// A middleware function added for a specific HTTP verb and route
app.get('/', a_middleware_function)

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
```

> **JavaScript Tip**: Above we declare the middleware function
> separately and then set it as the callback. In our previous route
> handler function we declared the callback function when it was used.
> In JavaScript, either approach is valid.

### 4.1. Example: Adding an express logger middleware {#41-example-adding-an-express-logger-middleware tabindex="-1"}

You may have realized by now that there is no log server-side of the
clients\' connection requests, but the \'request received\' that we have
added in the section above.

We could manually add some logs at every route with e.g.
`console.log('...')` but it is usually preferable to log more
information, and do it automatically without worrying about adding code
to every route.

Morgan is a popular logger middleware for express. To install it just
execute:

``` hljs
npm install morgan
```

Then, we need to register the Morgan middleware, so that every
request-response will go through it.

``` hljs
const express = require('express')
const logger = require('morgan')

const app = express()
const port = 3000

app.use(logger('dev'))
...
```

If you rerun now your application with `node index.js` you will see that
now the logger is "logging" things. As a middleware, it is "hooking" in
every request-response cycle and logging some data. For example if you
point your browser to <http://localhost:3000> with your application
running, you will see

``` hljs
Example app listening at http://localhost:3000
GET / 304 3.552 ms - -
GET /favicon.ico 404 1.920 ms - 150
```

Obviously, the way morgan logs can be tuned. Refer to the [morgan
documentation](https://github.com/expressjs/morgan#morgan) for more
details.

### 4.2. Handling errors {#42-handling-errors tabindex="-1"}

Errors are handled by one or more special middleware functions that have
four arguments, instead of the usual three: `(err, req, res, next)`. For
example:

``` hljs
app.use(function(err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})
```

These can return any content required, but must be called after all
other `app.use()` and routes calls so that they are the last middleware
in the request handling process.

Express comes with a built-in error handler, which takes care of any
remaining errors that might be encountered in the app. This default
error-handling middleware function is added at the end of the middleware
function stack. If you do not handle an error in an error handler, it
will be handled by the built-in error handler; the error will be written
to the client with the stack trace.

When an error is written, the following information is added to the
response:

-   The `res.statusCode` is set from `err.status` (or `err.statusCode`).
    If this value is outside the 4xx or 5xx range, it will be set to
    500.
-   The `res.statusMessage` is set according to the status code.
-   The body will be the HTML of the status code message when in
    production environment, otherwise will be `err.stack`.
-   Any headers specified in an `err.headers` object.

> **Note**: The stack trace is not included in the production
> environment. To run it in production mode you need to set the
> environment variable `NODE_ENV` to \'production\'.
>
> **Note**: HTTP404 and other "error" status codes are not treated as
> errors. If you want to handle these, you can add a middleware function
> to do so.

You define error-handling middleware last, after other app.use() and
routes calls.

For more information see [Error
handling](http://expressjs.com/en/guide/error-handling.html) in the
Express docs.

## 5. Authentication tutorial using passport.js authentication middleware {#5-authentication-tutorial-using-passportjs-authentication-middleware tabindex="-1"}

In this tutorial we are going to create a simple fortune-teller server
authenticated with JWTs. The fortune-teller server will require user
agents to hold a valid JWT, and, in order to get a valid JWT, end users
should log in using a valid username and password. Using JWTs, our
server will be completely stateless and no user data will be recorded
(but the data required to log in).

We are going to use [Passport](http://www.passportjs.org/) as the
authentication middleware. Passport is the most widely used
authentication middleware in the Node.js ecosystem thanks to its
modularity and support for a plethora of different authentication
strategies, including username and password, Google, Facebook, and more.

In this tutorial we will create the following route endpoints with the
following endpoints and Passport\'s authentication strategies:

-   GET `/login`. Returns an HTML login formulary. Once filled, the
    formulary (username and password) can be POSTed to `/login` (see
    next route)
    -   Authentication strategy: none
-   POST `/login`. Parses urlencoded data POSTed from the login
    formulary and returns a cookie with a valid JWT for our
    fortune-teller server.
    -   Authentication strategy: [passport
        local](http://www.passportjs.org/packages/passport-local/),
        which verifies urlencoded username and passwords provided
        through an HTML formulary.
-   GET `/`. This is our main **fortune-teller endpoint**. If the user
    agent (end-user browser) holds a cookie with a valid JWT, the server
    will tell fortune to the user (just a random adage); otherwise, the
    user agent will be redirected to the `/login` endpoint.
    -   Authentication strategy: [passport
        JWT](http://www.passportjs.org/packages/passport-jwt/). In our
        tutorial the JWTs will be presented by the user-agent (end-user
        browser) using a cookie.

### 5.1. Passport installation {#51-passport-installation tabindex="-1"}

Let us install passport and the necessary passport strategies (\'local\'
and \'jwt\'):

``` hljs
npm install passport passport-local passport-jwt
```

### 5.2. Setting up login with username/password (passport\'s \'local\' strategy) {#52-setting-up-login-with-usernamepassword-passports-local-strategy tabindex="-1"}

As previously explained, for the login process, we are going to use the
passport\'s \'local\' strategy, which eases the task of verifying
urlencoded username and passwords provided through an HTML formulary.
Therefore, before we need to configure that strategy before it can be
used by passport to authenticate requests.

Strategies, and their configuration, are supplied via the `use()`
function. For the sake of simplicity, we will not create by now a user
database/file, and we will just check for an only hardcoded valid user
(DO NOT DO THIS IN PRODUCTION!). The chosen account is:

-   username: `walrus`
-   password: `walrus`

Now, open your `index.js`, create a new local strategy with name
\'username-password\', add it to passport, and load the passport
middleware to your express application.

``` hljs
...
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy

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
... 
```

#### 5.2.1. Create the route handlers for the login {#521-create-the-route-handlers-for-the-login tabindex="-1"}

Let us create the required route handlers for the login process, which,
as explained before, are:

-   GET `/login`. Returns an HTML login formulary. Once filled, the
    formulary (username and password) can be POSTed to `/login` (see
    next route)
    -   Authentication strategy: none
-   POST `/login`. Parses urlencoded data POSTed from the login
    formulary and returns a cookie with a valid JWT for our
    fortune-teller server.
    -   Authentication strategy: [passport
        local](http://www.passportjs.org/packages/passport-local/),
        which verifies urlencoded username and passwords provided
        through an HTML formulary.

##### 5.2.1.1. GET /login {#5211-get-login tabindex="-1"}

Let us first create a web page with a login formulary for our GET
`/login` route. Create a file `login.html` in your project\'s root
directory with the following contents:

``` hljs
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>

<body>
    <p><strong>Want to listen to the fortune-teller server?</strong></p>
    <p>Please login to proceed</p>
    <form action="/login" method="post">  <!-- when the formulary is submitted, it will be POSTed to /login-->
        <div>
            <label>Username:</label>
            <input type="text" name="username" />  <!-- the name MUST match the one defined in the local 'username-password' startegy -->
        </div>
        <div>
            <label>Password:</label>
            <input type="password" name="password" /> <!-- the name MUST match the one defined in the local 'username-password' startegy -->
        </div>
        <div>
            <input type="submit" value="Log In" />
        </div>
    </form>
</body>

</html>
```

And now let use define a route handler that sends this formulary to
anyone (no authentication) requesting it

``` hljs
...
app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
  }
)
...
```

##### 5.2.1.2. POST /login {#5212-post-login tabindex="-1"}

And now let us define the route handler for the `POST /login`. We tell
the passport middleware to authenticate this route using the
\'username-password\' strategy (which we created before). Moreover, we
will tell passport to redirect again the user to the `GET /login`
endpoint if the authentication fails.

``` hljs
app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => { 
    // we should create here the JWT for the fortune teller and send it to the user agent inside a cookie.
    // we'll do it later, right now we'll just say 'Hello ' and the name of the user that we get from the `req.user` object provided by passport
    res.send(`Hello ${req.user.username}`)
  }
)
...
```

#### 5.2.2. Finishing the login process {#522-finishing-the-login-process tabindex="-1"}

Your complete `index.js` file should now look as

``` hljs
const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy

const app = express()
const port = 3000

app.use(logger('dev'))

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
  res.send('hello world')
})

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.post('/login',
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }),
  (req, res) => { //
    // we should create here the JWT for the fortune teller and send it to the user agent inside a cookie.
    // we'll do it later, right now we'll just say 'Hello ' and the name of the user that we get from the `req.user` object provided by passport
    res.send(`Hello ${req.user.username}`)
  }
)

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
```

Run your express app now (`node index.js`) and point your browser to
<http://localhost:3000/login>. You should be able to login using
username `walrus` and password `walrus`. If you successfully
authenticate, you will receive a \'Hello walrus\' welcome message.

We are on the path, but our goal was not just to receive a welcome
message, what we want is a valid JWT (auth token) for accessing the
fortune teller that will listen at [`/`](http://localhost:3000/).

### 5.3. Setting up an authenticated fortune-teller endpoint (passport\'s JWT strategy) {#53-setting-up-an-authenticated-fortune-teller-endpoint-passports-jwt-strategy tabindex="-1"}

We are going to change the `GET /` so that a user-agent (in this case a
web browser) in only authorized if holds a cookie with a valid JWT

#### 5.3.1. Creating and sending the JWT to the user agent upon successful login {#531-creating-and-sending-the-jwt-to-the-user-agent-upon-successful-login tabindex="-1"}

We are going to install the `jsonwebtoken` package, a widely used
library for creating and verifying JWTs in Node.js.

``` hljs
npm install jsonwebtoken
```

Add the needed \'require\' in our `index.js` file:

``` hljs
...
const jwt = require('jsonwebtoken')
...
```

Our JWTs will be signed using the HMAC-SHA256 (HS256) algorithm, which
is the default, and thus we need a secret. Let us create a random one
every time we bring up our server by adding this to the top of your
`index.js` file just after the `require`\'s.

``` hljs
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 
```

And now let us code how to create a JWT. Since the JWT is created after
a user logs in using our \'username-password\' strategy, we have to edit
the `POST /login` route. Modify it to look like the following:

``` hljs
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

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    res.json(token)
    
    // And let us log a link to the jwt.io debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)
```

If you rerun your application now and log in, you should receive a valid
JWT (just check the cookies in your browser). This token will be later
needed to authenticate to access the intranet. When a user logs in, your
node.js server will log a link to the [JWT.io debugger](https://jwt.io)
that you can use to inspect the created JWT.

## 6. Do-it-yourself exercises {#6-do-it-yourself-exercises tabindex="-1"}

We were almost there\... but now you have the knowledge to continue all
by your self. You should perform the following steps:

### 6.1. \[optional\] Add TLS certificates to your server {#61-optional-add-tls-certificates-to-your-server tabindex="-1"}

If you want to test your server outside your localhost you are going to
need a valid certificate and private-key pair and add them to your
express server. You just learn how to do that in the Network Security
course.

### 6.2. Exchange the JWT using cookies {#62-exchange-the-jwt-using-cookies tabindex="-1"}

Instead of sending the JWT directly to the browser with
`res.json(token)`, write it to a cookie that the browser will then
present every time it connects to our server. After sending the cookie,
you can automatically redirect the user to the fortune teller at `/` or
just allow him/her to click on a link to it.

With security in mind, the cookie must hold the flags \'httpOnly\' and
\'secure\':

-   \'httpOnly\', which does not allow JS code to access the cookie
    (since we don\'t need it, why should we allowed it?)
-   \'secure\', that prevents exchanging the cookie outside a secure
    context. Secure context means here using a TLS-protected channel
    (https). However, localhost is considered secure also on http, so
    you should be able to test your server even before owning a valid
    certificate and private key.

Managing cookies in Passport.js is greatly simplified by the
`cookie-parser` middleware, which parses the Cookie header on the
request and expose the cookie data as the property `req.cookies` and, if
a `secret` was provided, as the property `req.signedCookies`. In any
case, we are not going to use the cookie signatures since the JWT is
already signed.

### 6.3. Create the fortune-teller endpoint {#63-create-the-fortune-teller-endpoint tabindex="-1"}

The route `/` should be changed to be our fortune teller, which just
sends a random adage to the user. The endpoint should be authenticated
using Passport\'s JWT strategy:

-   You can use the `fortune-teller` package and invoke a random adage
    with `fortune.fortune()` (assuming you required the package as
    `const fortune = require('fortune-teller')`)
-   Check the [Passport JWT
    strategy](https://www.passportjs.org/packages/passport-jwt/) to
    learn how to use it to verify a JWT in a cookie. *Tip: Pay attention
    to the `jwtFromRequest` option*

### 6.4. Add a logout endpoint {#64-add-a-logout-endpoint tabindex="-1"}

Create a new route at `/logout` that will log the user out. *Tip: just
reset the cookie*

### 6.5. Add a strong key derivation function to the login process {#65-add-a-strong-key-derivation-function-to-the-login-process tabindex="-1"}

Create a file/database of users with their hashed passwords and verify
the login data against that database/file. It is up to you to decide
whether using just a file or a database; and in the later case which
database (SQLite, MongoDB, PostgreSQL, etc.) to use.

Test your system using a strong key derivation function, such as scrypt
or Argon2, for storing password hashes. For your convenience you can use
this [scrypt with MCF
implementation](https://www.npmjs.com/package/scrypt-mcf) to generate
and verify password hashes.

> Refer to [this link](https://github.com/juanelas/scrypt-pbkdf) in
> order to better understand how to use scrypt.

### 6.6. Add Oauth2-based login to your server {#66-add-oauth2-based-login-to-your-server tabindex="-1"}

Implement a \"login with\" an identity provider using OAuth2. Examples
of identity providers are GitHub, Google, Facebook, etc. You must
register first an application with your chosen Identity Provider. Once
registered, your application will be issued a client ID and client
secret, which need to be provided to the passport strategy in use. You
will also need to configure a callback URL which matches that route in
your application.

### 6.7. Add OpenID-Connect based login to your server {#67-add-openid-connect-based-login-to-your-server tabindex="-1"}

Implement a \"login with\" an identity provider using OpenID Connect
(OIDC). Since OIDC is built upon OAuth2 the solutions should be similar
to the OAuth2 one, although now you have a standardized user-info object
and the only configuration needed for the client (relying party) to
operate with the OIDC server is the well-known-configuration endpoint.

### 6.8. Create a new \'radius\' strategy based on the Local one in order to check users\' credentials against your RADIUS server {#68-create-a-new-radius-strategy-based-on-the-local-one-in-order-to-check-users-credentials-against-your-radius-server tabindex="-1"}

Run a RADIUS server. Then, create a new strategy `local-radius` based on
the `LocalStrategy` that runs a RADIUS client that is connected with
your RADIUS server. As a result, you should be able to send credentials
received through a html login form to your RADIUS server that will check
the credentials. For such a purpose you can use a JS RADIUS client
implementation such as
[`node-radius-client`](https://www.npmjs.com/package/node-radius-client)
or [`radclient`](https://www.npmjs.com/package/radclient).
:::
:::
:::
