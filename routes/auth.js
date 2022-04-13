const router = require('express').Router()
const User = require('../model/User')
const Provider = require('../model/Provider')
const Manager = require('../model/Manager')
const Token = require('../model/Token')
const {regUserValid, regProviderValid} = require('../validation')
const crypto = require('crypto')
const sendEmail = require('../email')

router.post('/register', async (req, res) => {
    //if the sign up is a user
    if(req.body.type === 'User'){
        //check if email already exists
        const emailExists = await User.findOne({email:req.body.email})
        if (emailExists) return res.status(400).send('Email already in use')

        //validation
        const {error} = regUserValid.validate(req.body)
        if(error) return res.status(400).send(error.details[0].message)
        const user = new User({
            email: req.body.email,
            name: req.body.name,
            dateOfBirth: req.body.dateOfBirth,
            phoneNumber: req.body.phoneNumber,
            password: req.body.password,
            address: req.body.address,
            city: req.body.city,
            zipCode: req.body.zipCode,
        })

        //save user in db
        try {
            await user.save()
        }catch(err){
            res.status(500).send(err)
        }

        //generate token for email validation
        const token = new Token({
            _userId: user._id,
            token: crypto.randomBytes(16).toString('hex')
        })
        //save token
        try {
            await token.save()
        }catch(err){
            res.status(500).send(err)
        }

        //send email
        const message = `Hello ${req.body.name}, please verify your email by clicking on the following link: ${process.env.URL}/user/verify/${user._id}/${token.token}`
        await sendEmail(user.email, "WYO Email Verification", message)
        res.send('email sent for verification')
    }

    //if the sign up is a provider
    else if(req.body.type === 'Provider'){
        //check if email already exists
        const emailExists = await Provider.findOne({email:req.body.email})
        if (emailExists) return res.status(400).send('Email already in use')

        //validation
        const {error} = regProviderValid.validate(req.body)
        if(error) return res.status(400).send(error.details[0].message)
        const user = new Provider({
            email: req.body.email,
            name: req.body.name,
            dateOfBirth: req.body.dateOfBirth,
            phoneNumber: req.body.phoneNumber,
            password: req.body.password,
            address: req.body.address,
            biography: req.body.biography,
            city: req.body.city,
            zipCode: req.body.zipCode,
        })

        //save user in db
        try {
            await user.save()
        }catch(err){
            res.status(500).send(err)
        }

        //generate token for email validation
        const token = new Token({
            _userId: user._id,
            token: crypto.randomBytes(16).toString('hex')
        })
        //save token
        try {
            await token.save()
        }catch(err){
            res.status(500).send(err)
        }

        //send email
        const message = `Hello ${req.body.name}, please verify your email by clicking on the following link: ${process.env.URL}/user/verify/${user._id}/${token.token}`
        await sendEmail(user.email, "WYO Email Verification", message)
        res.send('email sent for verification')
    }
    //if the user is a manager
    else{
        const user = new Manager({
            username: req.body.username,
            password: req.body.password,
        })

        //save in db
        try {
            await user.save()
        }catch(err){
            res.status(500).send(err)
        }
    }
})


//email verification route
router.get('/verify/:id/:token', async(req, res) => {
    const user = await User.findOne({_id: req.params.id})
    if(!user) return res.status(400).send('invalid link')

    const token = await Token.findOne({_userId: user._id, token: req.params.token})
    if(!token) return res.status(400).send('invalid link')

    await User.updateOne({
        _id: user.id,
        verificationStatus: true
    })
    await Token.findByIdAndRemove(token.id)

    res.send('email has been verified!')
})

module.exports = router;