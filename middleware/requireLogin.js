const requireLogin = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login-secure');
    }
    next();
};

module.exports = {
    requireLogin
};