const mongoose = require('mongoose')

const tokenSchema = new mongoose.Schema({
    _id:{
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
        expires: 2574000
    }
})

module.exports = mongoose.model('RefreshToken', tokenSchema)