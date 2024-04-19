const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const passport = require('passport');
const session = require('express-session');
const Sqlite = require('better-sqlite3');
const SqliteStore = require('better-sqlite3-session-store')(session); 
require('dotenv').config();

const sessOptions = {
  secret: process.env.SECRETSESS,
  name: 'session-id',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: false, maxAge: 86400000},
  unset: 'destroy',
  store: new SqliteStore({
    client: new Sqlite('sessions.db', { verbose: console.log }),
    expired: { clear: true, intervalMs: 86400000 },
  }),
};

const indexRouter = require('./routes/index');

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(sessOptions.secret));
app.use(express.static(path.join(__dirname, 'public')));
app.use(passport.initialize({ userProperty: 'currentUser' }));
app.use(session(sessOptions));

app.use('/', indexRouter);
app.use('/bw', express.static(__dirname + '/node_modules/bootswatch/dist'))

app.use(function(req, res, next) {
  next(createError(404));
});

app.use(function(err, req, res, next) {
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
