const RefreshToken = require('./model/RefreshToken')
const jwt = require('jsonwebtoken')

const generateAccessToken = (user) => {
    //create access and refresh token for successful login
    const accessToken = jwt.sign({
        _id: user._id,
    }, process.env.ACCESS_TOKEN, {
        expiresIn: process.env.ACCESS_TOKEN_EXP
    })

    return accessToken
}

const generateRefreshToken = async(user) => {
    //if a refresh token already exists for the user remove it before creating a new one
    await RefreshToken.findByIdAndRemove({_id: user._id})
    
    const refreshToken = jwt.sign({_id: user._id}, process.env.REFRESH_TOKEN, {expiresIn: process.env.REFRESH_TOKEN_EXP})    
    
    //save refresh token in db
    const token = new RefreshToken({
        _id: user._id,
        token: refreshToken 
    })
    try {
        await token.save()
    }catch(err){
        return err
    }

    return refreshToken
}

module.exports.generateAccessToken = generateAccessToken
module.exports.generateRefreshToken = generateRefreshToken