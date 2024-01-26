const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { verifyToken, permit } = require('../middleware/middleware');



// Register User
router.post('/register', async (req, res) => {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    // Create new user
    const user = new User({
        username: req.body.username,
        password: hashedPassword
    });
    try {
        const savedUser = await user.save();
        res.send({ user: user._id });
    }
    catch (error) {
        res.status(400).send(error);
    }
});

// Login User
router.post('/login', async (req, res) => {
    // Check if user exists
    const user = await User.findOne({
        username: req.body.username
    });
    if(!user) return res.status(400).send('Username or password is wrong');

    // Check if password is correct
    const validPass = bcrypt.compare(req.body.password, user.password);
    if(!validPass) return res.status(400).send('Invalid Password');

    // Create and assign a token
    // const token = jwt.sign(
    //     { _id: user._id, role: user.role },
    //     process.env.TOKEN_SECRET,
    //     { expiresIn: '1m' }
    // );
    // res.header('auth-token', token).send(token);

    // Create and assign tokens
    const accessToken = jwt.sign(
        { _id: user._id, role: user.role },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '1m' } // Access token expires in 1 minutes
    );

    const refreshToken = jwt.sign(
        { _id: user._id, role: user.role },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '4m' } // Refresh token expires in 4 minutes
    );

    res.header('auth-token', accessToken).send({ accessToken, refreshToken });

});

router.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    if(!refreshToken) return res.status(401).send('Access Denied');

    // Verify the refresh token
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (error, user) => {
        if(error) return res.status(403).send('Invalid Refresh Token');

        const accessToken = jwt.sign(
            { _id: user._id, role: user.role },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '2m' } // Access token expires in 2 minutes
        );

        res.send({ accessToken });
    });
});


// Route accessible by both user and admin
router.get('/user', verifyToken, permit('user', 'admin', 'supervisor'), (req, res) => {
    res.send('Welcome, user!');
});

// Route accessible by admin only
router.get('/admin', verifyToken, permit('admin'), (req, res) => {
    res.send('Welcome, admin!');
})


module.exports = router;