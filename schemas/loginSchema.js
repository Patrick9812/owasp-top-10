const Joi = require('joi');

const loginSchema = Joi.object({
    user: Joi.string()
        .required()
        .messages({
            'any.required': 'Nazwa użytkownika jest wymagana.'
        }),
    
    password: Joi.string()
        .required()
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