const mongoose = require('mongoose')

const tokenSchema = new mongoose.Schema({
    _userId:{
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'Users'
    },
    token:{
        type: String,
        required: true
    },
    expires:{
        type: Date,
        default: Date.now,
        index: {
            expires: 86400000
        }
    }
})

module.exports = mongoose.model('Token', tokenSchema)