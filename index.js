const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/database',)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// Secret key and token expiration time
const JWT_SECRET = 'key';
const JWT_EXPIRES_IN = '1h';

// User schema and model
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access Denied' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid Token' });
        req.user = user;
        next();
    });
};

// Public Route: Homepage
app.get('/homepage', (req, res) => {
    res.send('Welcome to the homepage');
});

// Protected Routes: Register and Login
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ username: user.username, id: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    res.json({ token });
});

// Protected CRUD Routes for Todos (Example)
const TodoSchema = new mongoose.Schema({
    text: String,
    completed: Boolean,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});
const Todo = mongoose.model('Todo', TodoSchema);

app.get('/todos', authenticateToken, async (req, res) => {
    const todos = await Todo.find({ userId: req.user.id });
    res.json(todos);
});

app.post('/todos', authenticateToken, async (req, res) => {
    const todo = new Todo({
        text: req.body.text,
        completed: req.body.completed || false,
        userId: req.user.id
    });
    await todo.save();
    res.status(201).json(todo);
});

app.put('/todos/:id', authenticateToken, async (req, res) => {
    const updatedTodo = await Todo.findOneAndUpdate(
        { _id: req.params.id, userId: req.user.id },
        req.body,
        { new: true }
    );
    if (!updatedTodo) return res.status(404).json({ message: 'Todo not found' });
    res.json(updatedTodo);
});

app.delete('/todos/:id', authenticateToken, async (req, res) => {
    const deletedTodo = await Todo.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!deletedTodo) return res.status(404).json({ message: 'Todo not found' });
    res.json({ message: 'Todo deleted' });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
