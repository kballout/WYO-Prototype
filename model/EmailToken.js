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
        index: {
            expires: 86400000
        }
    }
})

module.exports = mongoose.model('EmailToken', tokenSchema)