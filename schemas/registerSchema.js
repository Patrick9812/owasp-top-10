const Joi = require('joi');

const registerSchema = Joi.object({
    user: Joi.string()
        .min(6)
        .max(25)
        .pattern(/[a-zA-Z]/)
        .pattern(/[0-9]/) 
        .required()
        .messages({
            'any.required': 'Nazwa użytkownika (login) jest wymagana.',
            'string.min': 'Login musi mieć minimum 6 znaków.',
            'string.pattern.base': 'Login musi zawierać zarówno litery, jak i cyfry.',
            'string.max': 'Login musi mieć maximum 25 znaków.',
        }),

    password: Joi.string()
        .min(8)
        .max(25)
        .pattern(/[^\w\s]/) 
        .required()
        .messages({
            'any.required': 'Hasło jest wymagane.',
            'string.min': 'Hasło musi mieć minimum 8 znaków.',
            'string.pattern.base': 'Hasło musi zawierać co najmniej jeden znak specjalny.',
            'string.max': 'Login musi mieć maximum 25 znaków.',
        }),

    name: Joi.string()
        .min(3)
        .max(25)
        .pattern(/^[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ]+$/)
        .required()
        .messages({
            'any.required': 'Imię jest wymagane.',
            'string.min': 'Imię musi mieć minimum 3 znaki.',
            'string.pattern.base': 'Imię może zawierać tylko litery.',
            'string.max': 'Login musi mieć maximum 25 znaków.',
        }),
        
    surname: Joi.string()
        .min(3)
        .max(35)
        .pattern(/^[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ]+$/)
        .required()
        .messages({
            'any.required': 'Nazwisko jest wymagane.',
            'string.min': 'Nazwisko musi mieć minimum 3 znaki.',
            'string.pattern.base': 'Nazwisko może zawierać tylko litery.',
            'string.max': 'Login musi mieć maximum 35 znaków.',
        }),

    'g-recaptcha-response': Joi.string()
        .required()
        .messages({
            'any.required': 'Weryfikacja CAPTCHA jest wymagana.'
        })
    });
    
module.exports = {
    registerSchema
};