// Middleware to verify the JWT Token
const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    console.log('Verifying token');
    const token = req.headers.authorization && req.headers.authorization.split(' ')[1]; // Get the token from the Authorization header
    if(!token) return res.status(401).send('Access Denied');

    try {
        const verified = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = verified;
        console.log('Token Verified');
        next();
    }
    catch (error) {
        console.log('Token verification failed');
        res.status(400).send('Invalid Token');
    }
};

//Middleware for role checking
const permit = (...permittedRoles) => {
    return (req, res, next) => {
        const { user } = req;

        // Check if user has one of the permitted roles
        if(user && permittedRoles.includes(user.role)) {
            next();
        } else {
            res.status(403).send('Forbidden: You do not have the required role');
        }
    }
}

module.exports = {
    verifyToken,
    permit
}