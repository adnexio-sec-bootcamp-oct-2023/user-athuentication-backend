require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const port = process.env.PORT;


// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
        .then(() => console.log('MongoDB Connected'))
        .catch((err) => console.log(err));

// Middle
app.use(express.json());

// Enable CORS for frontend origin
app.use(cors({
    origin: 'http://localhost:3000' // Allow only this to get api endpoint
}));

//Routes
const authRouter = require('./routes/auth');
app.use('/api/user', authRouter);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});