//Validation
const Joi = require('joi');

//Register User Validation
const regUserValid = Joi.object({
        type: Joi.string()
            .default('User'),
        email: Joi.string()
            .max(255)
            .min(6)
            .required()
            .email(),
        name: Joi.string()
            .max(255)
            .required(),
        dateOfBirth: Joi.date()
            .required(),
        phoneNumber: Joi.string()
            .min(10)
            .max(10)
            .required(),
        password: Joi.string()
            .min(6)
            .max(1024)
            .required(),
        address: Joi.string()
            .max(50)
            .required(),
        city: Joi.string()
            .max(25)
            .required(),
        zipCode: Joi.string()
            .min(5)
            .max(5)
            .required()
    
});

//Register Provider Validation
const regProviderValid = Joi.object({
    type: Joi.string()
        .default('User'),
    employeeID: Joi.string()
        .default('-1'),
    biography: Joi.string()
        .max(3000)
        .required(),
    pictureURL: Joi.string()
        .max(1024)
        .uri()
        .required(),
    email: Joi.string()
        .max(255)
        .min(6)
        .required()
        .email(),
    name: Joi.string()
        .max(255)
        .required(),
    dateOfBirth: Joi.date()
        .required(),
    phoneNumber: Joi.string()
        .min(10)
        .max(10)
        .required(),
    password: Joi.string()
        .min(6)
        .max(1024)
        .required(),
    address: Joi.string()
        .max(50)
        .required(),
    city: Joi.string()
        .max(25)
        .required(),
    zipCode: Joi.string()
        .min(5)
        .max(5)
        .required()

});

module.exports.regUserValid = regUserValid
module.exports.regProviderValid = regProviderValid