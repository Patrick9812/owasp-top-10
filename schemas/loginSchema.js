const Joi = require('joi');

const loginSchema = Joi.object({
    user: Joi.string()
        .required()
        .max(25)
        .messages({
            'any.required': 'Nazwa użytkownika jest wymagana.'
        }),
    
    password: Joi.string()
        .required()
        .max(25)
        .messages({
            'any.required': 'Hasło jest wymagane.'
        }),

    'g-recaptcha-response': Joi.string()
        .required()
        .messages({
            'any.required': 'Weryfikacja CAPTCHA jest wymagana.'
        })
});

module.exports = {
    loginSchema
};