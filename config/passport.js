const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const passport = require('passport')
const Provider = require('../model/Provider')
const User = require('../model/User')
const options = {}
options.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken()
options.secretOrKey = process.env.ACCESS_TOKEN

passport.use(new JwtStrategy(options, function(jwt_payload, done) {
    if(jwt_payload.type === 'User'){
        User.findOne({_id: jwt_payload._id}, function(err, user) {
            if (err) {
                return done(err, false);
            }
            if (user) {
                return done(null, user);
            } else {
                //user not found
                return done(null, false);
            }
        });
    }
    else if (jwt_payload.type === 'Provider'){
        Provider.findOne({_id: jwt_payload._id}, function(err, user) {
            if (err) {
                return done(err, false);
            }
            if (user) {
                return done(null, user);
            } else {
                //user not found
                return done(null, false);
            }
        });
    }
    
}));