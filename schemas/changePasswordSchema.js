const Joi = require('joi');

const changePasswordSchema = Joi.object({
    currentPassword: Joi.string()
        .required()
        .max(25)
        .pattern(/[^\w\s]/) 
        .messages({
            'any.required': 'Aktualne hasło jest wymagane',
            'any.max': 'Aktualne hasło nie może być dłuższe niż 25 znaków'
        }),
    
    newPassword: Joi.string()
        .required()
        .max(25)
        .pattern(/[^\w\s]/) 
        .messages({
            'any.required': 'Nowe hasło jest wymagane',
            'any.max': 'Nowe hasło nie może być dłuższe niż 25 znaków'
        }),

    repeatNewPassword: Joi.string()
        .required()
        .max(25)
        .pattern(/[^\w\s]/) 
        .messages({
            'any.required': 'Powtórka hasła jest wymagana',
            'any.max': 'Powtórka hasła nie może być dłuższa niż 25 znaków'
        }),
});

module.exports = {
    changePasswordSchema
};