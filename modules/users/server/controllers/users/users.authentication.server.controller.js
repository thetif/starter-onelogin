'use strict';

/**
 * Module dependencies
 */
var path = require('path'),
  errorHandler = require(path.resolve('./modules/core/server/controllers/errors.server.controller')),
  mongoose = require('mongoose'),
  passport = require('passport'),
  OAuth2Strategy = require('passport-oauth2'),
  User = mongoose.model('User'),
  config = require(path.resolve('./config/config')),
  request = require('request');

// URLs for which user can't be redirected on signin
var noReturnUrls = [
  '/authentication/signin',
  '/authentication/signup'
];

/**
 * Signup
 */
exports.signup = function (req, res) {
  // For security measurement we remove the roles from the req.body object
  delete req.body.roles;

  // Init user and add missing fields
  var user = new User(req.body);
  user.provider = 'local';
  user.displayName = user.firstName + ' ' + user.lastName;

  // Then save the user
  user.save(function (err) {
    if (err) {
      return res.status(400).send({
        message: errorHandler.getErrorMessage(err)
      });
    } else {
      // Remove sensitive data before login
      user.password = undefined;
      user.salt = undefined;

      req.login(user, function (err) {
        if (err) {
          res.status(400).send(err);
        } else {
          res.json(user);
        }
      });
    }
  });
};

/**
 * Signin after passport authentication
 */
exports.signin = function (req, res, next) {
  // passport.authenticate('local', function (err, user, info) {
  //   if (err || !user) {
  //     res.status(400).send(info);
  //   } else {
  //     // Remove sensitive data before login
  //     user.password = undefined;
  //     user.salt = undefined;
  //
  //     req.login(user, function (err) {
  //       if (err) {
  //         res.status(400).send(err);
  //       } else {
  //         res.json(user);
  //       }
  //     });
  //   }
  // })(req, res, next);
  request.post({
    url: 'https://api.us.onelogin.com/auth/oauth2/token',
    headers: {
      'content-type': 'application/json',
      'Authorization': 'client_id: ' + config.onelogin.clientID +
        ', client_secret: ' + config.onelogin.clientSecret
    },
    body: '{ "grant_type": "client_credentials" }'
  },
  function (error, response, body) {
    if (!error && response.statusCode === 200) {
      var json = JSON.parse(body);
      var access_token = json.data[0].access_token;
      var authBody = '{ "username_or_email":"' + req.body.username + '","password":"' +
        req.body.password + '", "subdomain": "fearless"}';

      request.post({
        url: 'https://api.us.onelogin.com/api/1/login/auth',
        headers: {
          'content-type': 'application/json',
          'Authorization': 'bearer:' + access_token
        },
        body: authBody
      },
      function (error, response, body) {
        if (error) {
          console.log('error', error);
          return res.status(400).send({
            message: errorHandler.getErrorMessage(error)
          });
        } else {
          if (response.statusCode === 200) {
            var userJson = JSON.parse(body);
            console.log('user', userJson.data[0].user);
            var profile = userJson.data[0].user;
            var providerUserProfile = {
              firstName: profile.firstname,
              lastName: profile.lastname,
              displayName: profile.firstname + ' ' + profile.lastname,
              email: profile.email,
              username: profile.username,
              provider: 'onelogin',
              providerIdentifierField: 'id',
              providerData: profile
            };

            if (!profile) {
              return res.status(400).send({
                message: 'Invalid username or password'
              });
            } else {
              User.findOne({ 'username': profile.username }).exec(function(err, user) {
                if (err) {
                  return res.status(400).send({
                    message: 'Invalid username or password'
                  });
                } else if (!user) {
                  user = new User(providerUserProfile);
                  user.save(function (err) {
                    if (err) {
                      return res.status(400).send({
                        message: 'Invalid username or password'
                      });
                    } else {
                      req.login(user, function (err) {
                        if (err) {
                          res.status(400).send(err);
                        } else {
                          res.json(user);
                        }
                      });
                    }
                  });
                } else {
                  req.login(user, function (err) {
                    if (err) {
                      res.status(400).send(err);
                    } else {
                      res.json(user);
                    }
                  });
                }
              });
            }
          } else {
            console.log('body', body);
            return res.status(400).send({
              message: 'Invalid username or password'
            });
          }
        }
      });
    } else {
      return res.status(400).send({
        message: 'Error logging in'
      });
    }
  });
};

/**
 * Signout
 */
exports.signout = function (req, res) {
  req.logout();
  res.redirect('/');
};

/**
 * OAuth provider call
 */
exports.oauthCall = function (strategy, scope) {
  return function (req, res, next) {
    // Set redirection path on session.
    // Do not redirect to a signin or signup page
    if (noReturnUrls.indexOf(req.query.redirect_to) === -1) {
      req.session.redirect_to = req.query.redirect_to;
    }
    // Authenticate
    passport.authenticate(strategy, scope)(req, res, next);
  };
};

/**
 * OAuth callback
 */
exports.oauthCallback = function (strategy) {
  return function (req, res, next) {
    // Pop redirect URL from session
    var sessionRedirectURL = req.session.redirect_to;
    delete req.session.redirect_to;

    passport.authenticate(strategy, function (err, user, redirectURL) {
      if (err) {
        return res.redirect('/authentication/signin?err=' + encodeURIComponent(errorHandler.getErrorMessage(err)));
      }
      if (!user) {
        return res.redirect('/authentication/signin');
      }
      req.login(user, function (err) {
        if (err) {
          return res.redirect('/authentication/signin');
        }

        return res.redirect(redirectURL || sessionRedirectURL || '/');
      });
    })(req, res, next);
  };
};

/**
 * Helper function to save or update a OAuth user profile
 */
exports.saveOAuthUserProfile = function (req, providerUserProfile, done) {
  if (!req.user) {
    // Define a search query fields
    var searchMainProviderIdentifierField = 'providerData.' + providerUserProfile.providerIdentifierField;
    var searchAdditionalProviderIdentifierField = 'additionalProvidersData.' + providerUserProfile.provider + '.' + providerUserProfile.providerIdentifierField;

    // Define main provider search query
    var mainProviderSearchQuery = {};
    mainProviderSearchQuery.provider = providerUserProfile.provider;
    mainProviderSearchQuery[searchMainProviderIdentifierField] = providerUserProfile.providerData[providerUserProfile.providerIdentifierField];

    // Define additional provider search query
    var additionalProviderSearchQuery = {};
    additionalProviderSearchQuery[searchAdditionalProviderIdentifierField] = providerUserProfile.providerData[providerUserProfile.providerIdentifierField];

    // Define a search query to find existing user with current provider profile
    var searchQuery = {
      $or: [mainProviderSearchQuery, additionalProviderSearchQuery]
    };

    User.findOne(searchQuery, function (err, user) {
      if (err) {
        return done(err);
      } else {
        if (!user) {
          var possibleUsername = providerUserProfile.username || ((providerUserProfile.email) ? providerUserProfile.email.split('@')[0] : '');

          User.findUniqueUsername(possibleUsername, null, function (availableUsername) {
            user = new User({
              firstName: providerUserProfile.firstName,
              lastName: providerUserProfile.lastName,
              username: availableUsername,
              displayName: providerUserProfile.displayName,
              email: providerUserProfile.email,
              profileImageURL: providerUserProfile.profileImageURL,
              provider: providerUserProfile.provider,
              providerData: providerUserProfile.providerData
            });

            // And save the user
            user.save(function (err) {
              return done(err, user);
            });
          });
        } else {
          return done(err, user);
        }
      }
    });
  } else {
    // User is already logged in, join the provider data to the existing user
    var user = req.user;

    // Check if user exists, is not signed in using this provider, and doesn't have that provider data already configured
    if (user.provider !== providerUserProfile.provider && (!user.additionalProvidersData || !user.additionalProvidersData[providerUserProfile.provider])) {
      // Add the provider data to the additional provider data field
      if (!user.additionalProvidersData) {
        user.additionalProvidersData = {};
      }

      user.additionalProvidersData[providerUserProfile.provider] = providerUserProfile.providerData;

      // Then tell mongoose that we've updated the additionalProvidersData field
      user.markModified('additionalProvidersData');

      // And save the user
      user.save(function (err) {
        return done(err, user, '/settings/accounts');
      });
    } else {
      return done(new Error('User is already connected using this provider'), user);
    }
  }
};

/**
 * Remove OAuth provider
 */
exports.removeOAuthProvider = function (req, res, next) {
  var user = req.user;
  var provider = req.query.provider;

  if (!user) {
    return res.status(401).json({
      message: 'User is not authenticated'
    });
  } else if (!provider) {
    return res.status(400).send();
  }

  // Delete the additional provider
  if (user.additionalProvidersData[provider]) {
    delete user.additionalProvidersData[provider];

    // Then tell mongoose that we've updated the additionalProvidersData field
    user.markModified('additionalProvidersData');
  }

  user.save(function (err) {
    if (err) {
      return res.status(400).send({
        message: errorHandler.getErrorMessage(err)
      });
    } else {
      req.login(user, function (err) {
        if (err) {
          return res.status(400).send(err);
        } else {
          return res.json(user);
        }
      });
    }
  });
};
