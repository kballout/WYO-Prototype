const mongoose = require('mongoose')

//userSchema
const userSchema = new mongoose.Schema({
    employeeID:{
        type: String,
        default: '-1'
    },
    email:{
        type: String,
        required: true,
        maxlength: 255,
        minlength: 6
    },
    name:{
        type: String,
        required: true,
        maxlength: 255
    },
    type:{
        type: String,
        default: 'Provider'
    },
    dateOfBirth:{
        type: Date,
        required: true,
    },
    phoneNumber:{
        type: String,
        required: true,
        minlength: 10,
        maxlength: 10
    },
    password:{
        type: String,
        required: true,
        maxlength: 1024,
        minlength: 6
    },
    address:{
        type: String,
        required: true,
        maxlength: 50
    },
    biography:{
        type: String,
        required: true,
        maxlength: 3000,
    },
    pictureURL:{
        type: String,
        maxlength: 1024,
    },
    city:{
        type: String,
        required: true,
        maxlength: 25
    },
    zipCode:{
        type: String,
        required: true,
        minlength: 5,
        maxlength: 5
    },
    currentJobs:{
        type: Array,
        default: []
    },
    jobHistory:{
        type: Array,
        default: []
    },
    verificationStatus:{
        type: Boolean,
        default: false
    },
    backgroundCheckStatus:{
        type: Boolean,
        default: false
    },
    dateCreated:{
        type: Date,
        default: Date.now
    }
})

module.exports = mongoose.model('Provider', userSchema)