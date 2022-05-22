const mongoose = require('mongoose')

const tokenSchema = new mongoose.Schema({
    _userId:{
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    token:{
        type: String,
        required: true
    },
    expiresAt:{
        type: Date,
        default: Date.now,
        expires: 3600
    }
})

module.exports = mongoose.model('ForgotPassword', tokenSchema)