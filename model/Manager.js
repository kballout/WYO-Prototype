const mongoose = require('mongoose')

//userSchema
const userSchema = new mongoose.Schema({
    username:{
        type: String,
        required: true,
        max: 255
    },
    type:{
        type: String,
        default: 'Manager'
    },
    password:{
        type: String,
        required: true,
        max: 1024,
        min: 6
    },
    date:{
        type: Date,
        default: Date.now
    }
})

//WYOSchema

module.exports = mongoose.model('Manager', userSchema)