/*jshint laxcomma:true*/
/*
 * Module dependencies
 */

var passport = require('passport')
  , GoogleStrategy = require('passport-google-oauth').OAuth2Strategy
  , LocalStrategy = require('passport-local').Strategy
  , TwitterStrategy = require('passport-twitter').Strategy
  , FacebookStrategy = require('passport-facebook').Strategy
  , bcrypt = require('bcrypt');

/**
 * Expose Authentication Strategy
 */

module.exports = Strategy;

/*
 * Defines Passport authentication
 * strategies from application configs
 *
 * @param {Express} app `Express` instance.
 * @api public
 */

function Strategy (app) {
  var config = app.get('config');

  passport.serializeUser(function(user, done) {
    done(null, user);
  });

  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

  if(config.auth.google.consumerkey.length) {
    passport.use(new GoogleStrategy({
        clientID: config.auth.google.consumerkey,
        clientSecret: config.auth.google.consumersecret,
        callbackURL: config.auth.google.callback
      },
      function(token, tokenSecret, profile, done) {
        if(/@advisa.se$/.test(profile.emails[0].value)) {
          return done(null, profile);
        } else {
          return done(null, false, "Invalid domain");
        }
      }
    ));
  }

  passport.use(new LocalStrategy(function(username, password, done) {
    var queryString = "SELECT username,password_digest FROM creditor_users WHERE username = ?";
    app.get('mysqlConnection').query(queryString, [username], function(err, results) {
      if (err) { return done(err); }
      if (!results) { return done(new Error("Invalid credentials")); }
      bcrypt.compare(password, results[0].password_digest, function(err, res) {
        if (err) { return done(err); }
        if (res) {
          return done(null, {
            username: username,
            provider: 'bank'
          });
        } else {
          return done(null, false, "Invalid credentials");
        }

      });
    });
  }));

  if(config.auth.twitter.consumerkey.length) {
    passport.use(new TwitterStrategy({
        consumerKey: config.auth.twitter.consumerkey,
        consumerSecret: config.auth.twitter.consumersecret,
        callbackURL: config.auth.twitter.callback
      },
      function(token, tokenSecret, profile, done) {
        return done(null, profile);
      }
    ));
  }

  if(config.auth.facebook.clientid.length) {
    passport.use(new FacebookStrategy({
        clientID: config.auth.facebook.clientid,
        clientSecret: config.auth.facebook.clientsecret,
        callbackURL: config.auth.facebook.callback
      },
      function(accessToken, refreshToken, profile, done) {
        return done(null, profile);
      }
    ));
  }
}

