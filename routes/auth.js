const router = require('express').Router()
//models
const User = require('../model/User')
const Provider = require('../model/Provider')
const Manager = require('../model/Manager')
const {regUserValid, regProviderValid} = require('../validation')

router.post('/register', async (req,res) => {
    let user
    //if the sign up is a user
    if(req.body.type === 'User'){
        //validation
        const {error} = regUserValid.validate(req.body)
        if(error) return res.status(400).send(error.details[0].message)
        user = new User({
            email: req.body.email,
            name: req.body.name,
            dateOfBirth: req.body.dateOfBirth,
            phoneNumber: req.body.phoneNumber,
            password: req.body.password,
            address: req.body.address,
            city: req.body.city,
            zipCode: req.body.zipCode,
        })
    }
    //if the sign up is a provider
    else if(req.body.type === 'Provider'){
        //validation
        const {error} = regProviderValid.validate(req.body)
        if(error) return res.status(400).send(error.details[0].message)
        user = new Provider({
            email: req.body.email,
            name: req.body.name,
            dateOfBirth: req.body.dateOfBirth,
            phoneNumber: req.body.phoneNumber,
            password: req.body.password,
            address: req.body.address,
            biography: req.body.biography,
            pictureURL: req.body.pictureURL,
            city: req.body.city,
            zipCode: req.body.zipCode,
        })
    }
    //if the user is a manager
    else{
        user = new Manager({
            username: req.body.username,
            password: req.body.password,
        })
    }

    res.send('registered')

    // try {
    //     const savedUser = await user.save()
    //     res.send(savedUser)
    // }catch(err){
    //     res.status(400).send(err)
    // }
})

module.exports = router;