const express = require('express');
const router = express.Router();
const GoogleStrategy = require('passport-google-oidc').Strategy;
const passport = require('passport');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const LocalStrategy = require('passport-local');
const onlyMsgErrorFormatter = ({ msg }) => { return msg; };
require('dotenv').config();

/**
 Takes our message and encodes it with the private key, based on the algorithm, sets the inputted expiry
 */
const encodeJWT = (payload, expiry) => {
    const privateKey = fs.readFileSync('es256private.key');
    const token = jwt.sign(payload, privateKey, { algorithm: 'ES256' }, { expiresIn: expiry });
    return token;
};

/**
 * Taking our encoded message and decodes it with the public key
 */
const checkJWT = (token) => {
    const cert = fs.readFileSync('es256public.pem');
    const decoded = jwt.verify(token, cert, { algorithm: 'ES256' })
    return decoded
};

/**
 *  Contacts google and requests a profile, and redirects to the callback url, if there is a profile.id returns the profile
 */
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENTID,
    clientSecret: process.env.SECRETCLIENT,
    callbackURL: 'http://localhost:3000/login',
}, function (issuer, profile, done) {
    if (profile.id) {
        return done(null, profile);
    }
}));

/**
 * Makes it so we can access the profile that we acquired from google
 */
passport.serializeUser((user, done) => { done(null, user) });

/**
 * this checks to see if we have an email in the session, if not it renders the google login, if so redirect to encode page
 */
router.get('/', function (req, res, next) {
    if (req.session.email) { res.redirect('/encode') }
    else {
        res.render('index', {
            title: 'Google Login'
        });
    }
});

/**
 * post for the login screen, sends in the scope email, so we can grab the email from the profile
 */
router.post('/login', passport.authenticate('google', { scope: ['email'] }));

/**
 * get for the login screen, returns the requested profile with the requested email, which we assign to a session variable
 * then checks to see if we have an email in the session, if not it renders the google login, if so redirect to encode page
 */
router.get('/login', passport.authenticate('google'),
    function (req, res, next) {
        req.session.email = req.currentUser.emails[0].value;
        if (!req.session.email) {
            res.render('index', {
                title: 'Google Login',
            })
        }
        if(req.cookies.secret){ res.redirect('/decode') }
        else { res.redirect('/encode') }
    });

/**
 * get for the encode page, checks if there is a session message variable, and if not initializes it as an array
 * if there is no session email variable, redirects to the login page, else renders the encoded message page
 */
router.get('/encode', function (req, res, next) {
    if (!req.session.message) { req.session.message = []; }
    if (!req.session.email) { res.redirect('/') }
    else {
        res.render('encode', {
            title: 'Encode a Message:',
        });
    }
});

/**
 * post for the encode page,
 */
router.post('/encode', [
    //these are the validators for the messaging encoding form
    //had to add custom validator for date
    body('message').trim().notEmpty().withMessage('Message is required').bail().isLength({ min: 1, max: 150 }).withMessage('Message must be between 1 and 150 characters'),
    body('expiryDate').toDate().custom((value, { req }) => {
        if (req.body.expiryDate === null) {
            throw new Error('Expiry date must be selected');
        }
        if (req.body.expiryDate < new Date()) {
            throw new Error('Expiry ate must be in the future');
        }
        return true;
    }),
    body('email').trim().notEmpty().withMessage('Email is required').bail()
        .normalizeEmail().isEmail().withMessage('Email must be in a valid format'),
],

    /**
     * checks the validation results and then stores them as error messages only
     */
    function (req, res, next) {
        const violations = validationResult(req)
        const errorMessages = violations.formatWith(onlyMsgErrorFormatter).mapped();
        // information we received from our form plus the session email
        const payload = {
            message: req.body.message,
            emailReceiver: req.body.email,
            emailSender: req.session.email,
            expiry: req.body.expiryDate
        };
        //send in our payload with expiry into the encodeJWT function
        let secretMessage = encodeJWT(payload, payload.expiry)
        // this is our message object, which allows us to take the encoded message and split it as well as send along the full encoded message which we pushed to the session message array
        let messages =
        {
            messageShort: secretMessage.substring(secretMessage.length - 20),
            messageLong: secretMessage
        }
        // making sure violations are empty before pushing our message object to the array
        if (violations.isEmpty()) { req.session.message.push(messages) }
        // toast gives feedback for a message being encoded
        res.render('encode', {
            title: 'Encode A Message:',
            err: errorMessages,
            toast: violations.isEmpty(),
            secretMessage: secretMessage
        });
    }
);

/**
 *  get for our decode page where we will take the encoded message and decode it
 *  we check to see if the current session email = the decoded email sender or the decoded email reciever, otherwise they recieve an error
 */
router.get('/decode', function (req, res, next) {
    const cookieOptions = {
        path: req.baseUrl,
        sameSite: 'lax',
        httpOnly: true
    };
    let secretMessage = "";
    res.cookie('secret', req.query.msg, cookieOptions);
    if(req.cookies.secret){ secretMessage = req.cookies.secret }
    else { secretMessage = req.query.msg }
    let decoded = checkJWT(secretMessage);
    let decodedMessage = "";
    if (new Date(decoded.expiry + '') < Date.now()) {
        decodedMessage = "Your message has expired"
    } else {
        decodedMessage = decoded.emailSender === req.session.email ? decoded.message : decoded.emailReceiver === req.session.email ? decoded.message : "You aren't able to view this message"
    }
    if (!req.session.email) {
        res.render('index', {
            title: 'Google Login',
        })
    } else {
        res.render('decode', {
            title: 'Decoded Message:',
            msg: decodedMessage
        });
    }
});

/**
 * get for our messages page, checks to see if there are any session messages and displays them as a list
 * each message links to the decoded message page
 */
router.get('/messages', function (req, res, next) {
    if (!req.session.email) { res.redirect('/') }
    else {
        res.render('messages', {
            title: 'List of Encoded Messages:',
            message: req.session.message
        });
    }
});

/**
 * checks to see if the username/password matches the hardcoded username/password, and if so returns a currentUser boolean which is true
 */
passport.use(new LocalStrategy(
    function (username, password, done) {
        if (username === 'Jess' && password == 'Pa55w0rd') {
            return done(null, true);
        }
    }
));

/**
 * post method for the developer page, store the private and public keys and session variables, as well as the currentUser.
 * If currentUser boolean is true, renders the secret keys page and displays the public and private keys
 * also creates a cookie which stores: username that logs in
 */
router.post('/developer', passport.authenticate('local', {failureRedirect: '/developer'}),
    function (req, res) {
        req.session.privatekey = fs.readFileSync('es256private.key').toString();
        req.session.publickey = fs.readFileSync('es256public.pem').toString();
        req.session.user = req.currentUser;
        const cookieOptions = {
            path: req.baseUrl,
            sameSite: 'lax',
            httpOnly: true
        };
        res.cookie('username', req.body.username, cookieOptions);
        res.redirect('/keys');
    });

/**
 * get for the developer page, displays the username from the cookie in the userName field if the cookie exists
 */
router.get('/developer', function (req, res, next) {
    res.render('developer', {
        title: 'Developer Login',
        username: req.cookies.username
    });
});

/**
 * get for the keys page, checks to see if cookie with the username exists, and if the session.user is true, if so it renders the private and public keys, if not redirects back to the developer login
 */
router.get('/keys', function (req, res, next) {
    if (req.cookies.username !== "Jess" || req.session.user !== true) { res.redirect('/developer'); }
    else {
        res.render('keys', {
            title: 'Secret Keys',
            privatekey: req.session.privatekey,
            publickey: req.session.publickey
        });
    }
});

/**
 *  post for the keys page saves the new private and public keys file, then stores them in the session and reloads the page
 *  in order to display the new versions of the keys
 */
router.post('/keys',
    function (req, res) {
        fs.writeFileSync('es256private.key', req.body.privatekey);
        fs.writeFileSync('es256public.pem', req.body.publickey);
        req.session.privatekey = req.body.privatekey;
        req.session.publickey = req.body.publickey;
        res.redirect('/keys')
    });

module.exports = router;
