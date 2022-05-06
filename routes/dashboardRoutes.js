const router = require('express').Router()
const passport  = require('passport')
require('../config/passport')


router.get('/', passport.authenticate('jwt', {session: false}), (req,res) => {
    res.json({
        title: 'my first post',
        id: req.user._id,
        name: req.user.name,
        role: req.user.type
    })
})


module.exports = router