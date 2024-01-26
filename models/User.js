const mongoose = require('mongoose');

// Create/define our schema
const Schema = mongoose.Schema;

const userSchema = new Schema({
    username: { type: String, require: true, unique: true }, 
    password: { type: String, required: true },
    role: {type: String, default: 'user'}
});

module.exports = mongoose.model('User', userSchema);