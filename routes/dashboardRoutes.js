const router = require('express').Router()
const {authenticateToken} = require('./webTokens')
const User = require('../model/User')


router.get('/', authenticateToken, (req,res) => {
    res.json({
        title: 'my first post',
        id: req.user
    })
})


module.exports = router