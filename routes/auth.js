const router = require('express').Router()
const User = require('../model/User')
const Provider = require('../model/Provider')
const Manager = require('../model/Manager')
const Token = require('../model/Token')
const {regUserValid, regProviderValid, loginValidation} = require('../validation')
const crypto = require('crypto')
const sendEmail = require('../email')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const {generateAccessToken} = require('./webTokens')
const RefreshToken = require('../model/RefreshToken')

//REGISTRATION
router.post('/register', async (req, res) => {
    //USER SIGN UP
    if(req.body.type === 'User'){
        //check if email already exists
        const emailExists = await User.findOne({email:req.body.email})
        if (emailExists) return res.status(400).send('Email already in use')

        //validation
        const {error} = regUserValid.validate(req.body)
        if(error) return res.status(400).send(error.details[0].message)

        //hash password
        const salt = await bcrypt.genSalt(10)
        const hashedPass = await bcrypt.hash(req.body.password, salt)

        //create new user
        const user = new User({
            email: req.body.email,
            name: req.body.name,
            dateOfBirth: req.body.dateOfBirth,
            phoneNumber: req.body.phoneNumber,
            password: hashedPass,
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

    //PROVIDER SIGN UP
    else if(req.body.type === 'Provider'){
        //check if email already exists
        const emailExists = await Provider.findOne({email:req.body.email})
        if (emailExists) return res.status(400).send('Email already in use')

        //validation
        const {error} = regProviderValid.validate(req.body)
        if(error) return res.status(400).send(error.details[0].message)

        //hash password
        const salt = await bcrypt.genSalt(10)
        const hashedPass = await bcrypt.hash(req.body.password, salt)

        //create new provider
        const user = new Provider({
            email: req.body.email,
            name: req.body.name,
            dateOfBirth: req.body.dateOfBirth,
            phoneNumber: req.body.phoneNumber,
            password: hashedPass,
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

    //MANAGER SIGN UP
    else{
        //hash password
        const salt = await bcrypt.genSalt(10)
        const hashedPass = await bcrypt.hash(req.body.password, salt)

        const user = new Manager({
            username: req.body.username,
            password: hashedPass,
        })

        //save in db
        try {
            await user.save()
        }catch(err){
            res.status(500).send(err)
        }
    }
})

//LOGIN
router.post('/login', async (req,res) => {
    //validation
    const {error} = loginValidation.validate(req.body)
    if(error) return res.status(400).send(error.details[0].message)

    //check if user exists
    const user = await User.findOne({email: req.body.email})
    if(!user) return res.status(400).send("Email or password is incorrect")

    //checking password
    const validPassword = await bcrypt.compare(req.body.password, user.password)
    if(!validPassword) return res.status(400).send("Email or password is incorrect")

    //checking if verified
    if(user.verificationStatus === false){
        const oldToken = await Token.findOne({_userId: user._id})
        //if old token doesnt exists make a new one
        if(!oldToken){
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
            //resend verification email
            const message = `Hello ${req.body.name}, please verify your email by clicking on the following link: ${process.env.URL}/user/verify/${user._id}/${token.token}`
            await sendEmail(user.email, "WYO Email Verification", message)
            return res.send("You must verify your email before you can login. A new verification email was sent")
        }
        //if old token exists update it with a new token
        else{
            let id = oldToken._userId
            const token = crypto.randomBytes(16).toString('hex')
            await Token.updateOne({
                _userId: user.id,
                token: token
            })
            //resend verification email
            const message = `Hello ${req.body.name}, please verify your email by clicking on the following link: ${process.env.URL}/user/verify/${user._id}/${token}`
            await sendEmail(user.email, "WYO Email Verification", message)
            return res.send("You must verify your email before you can login. A new verification email was sent")
        }
        
    }

    //create access and refresh token for successful login
    const accessToken = generateAccessToken({user: user._id})
    const refreshToken = jwt.sign({id: user._id}, process.env.REFRESH_TOKEN)    

    //save refresh token in db
    const token = new RefreshToken({
        token: refreshToken 
    })
    try {
        await token.save()
    }catch(err){
        res.status(500).send(err)
    }

    res.json({accessToken: accessToken, refreshToken: refreshToken})
})


//GET ANOTHER TOKEN
router.post('/token', async (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.status('401').send('No refresh token found')

    const foundToken = await RefreshToken.findOne({token: refreshToken})
    if(!foundToken) return res.status('403').send('Invalid token must log back in')

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
        if(err) return res.status(403).send('Authentication failure')
        const accessToken = generateAccessToken({user: user._id})
        res.send('new token is: ' + accessToken)
    })
})

//EMAIL VERIFICATION
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