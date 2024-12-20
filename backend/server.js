// Import required libraries and modules
const express = require('express'); // For creating the server and handling HTTP requests
const mongoose = require('mongoose'); // For interacting with MongoDB
const bcrypt = require('bcryptjs'); // For hashing passwords
const jwt = require('jsonwebtoken'); // For generating and verifying JWTs
const { v4: uuidv4 } = require('uuid'); // For generating unique identifiers
const dotenv = require('dotenv'); // For managing environment variables
const Joi = require('joi'); // For validating user input

// Configure environment variables from the .env file
dotenv.config();

// Initialize the Express application
const app = express();
const port = process.env.PORT || 3005; // Use the PORT from the environment or default to 3005
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key'; // Secret for JWT signing and verification

// Middleware to log request details for debugging
app.use((req, res, next) => {
    console.log(`Request Method: ${req.method}, Request URL: ${req.url}`);
    next();
});

// Middleware to parse incoming JSON requests
app.use(express.json());

// Connect to MongoDB using Mongoose
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Define the Mongoose schema for users
const userSchema = new mongoose.Schema({ 
  user_id: { type: String, unique: true }, // Unique identifier for the user
  username: { type: String, required: true }, // Username (required)
  email: { type: String, required: true, unique: true }, // Email (required, unique)
  password: { type: String, required: true }, // Hashed password
  created_at: { type: Date, default: Date.now }, // Creation timestamp
  role: { type: String, default: "USER" }, // Role of the user (default is "USER")
});

// Define the Mongoose schema for todos
const todosSchema = new mongoose.Schema({
  taskId: { type: String, unique: true }, // Unique identifier for the task
  title: String, // Task title
  description: String, // Task description
  user_id: String, // ID of the user who owns the task
  priority: String, // Task priority (e.g., LOW, MEDIUM, HIGH)
  status: String, // Task status (e.g., TODO, IN_PROGRESS, DONE)
  created_at: { type: Date, default: Date.now }, // Creation timestamp
});


mongoose.set('bufferTimeoutMS', 30000); // 30 seconds


// Create models from schemas for interacting with MongoDB
const UserModel = mongoose.model('users', userSchema);
const TodosModel = mongoose.model('todos', todosSchema);

// Define validation schemas using Joi for input validation
const userValidationSchema = Joi.object({
  username: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  role: Joi.string().valid('USER', 'ADMIN'),
});

const todoValidationSchema = Joi.object({
  title: Joi.string().required(),
  description: Joi.string().required(),
  priority: Joi.string().valid('LOW', 'MEDIUM', 'HIGH').default('LOW'),
  status: Joi.string().valid('TODO', 'IN_PROGRESS', 'DONE').default('TODO'),
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Invalid or expired token." });
      }
      req.userId = decoded.userId;
      req.role = decoded.role;
      next();
    });
  } else {
    return res.status(401).json({ message: "Authorization token required." });
  }
};

const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.role !== role) {
      return res.status(403).json({ message: "Access denied." });
    }
    next();
  };
};

// Routes
app.get('/', (req, res) => {
  res.send('Application is working. Go to different routes. Thank you!');
});

// Signup Route
app.post('/signup', async (req, res) => {
  const { username, email, password, role } = req.body;

  // Validate input
  const { error } = userValidationSchema.validate({ username, email, password, role });
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  try {
    const existingUser = await UserModel.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: "Username or email already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new UserModel({
      user_id: uuidv4(),
      username,
      email,
      password: hashedPassword,
      role: role || "USER",
    });

    await newUser.save();
    res.status(201).json({ message: "User created successfully." });
  } catch (error) {
    console.error("Error during signup:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required." });
    }


    // console.log(username,password,'login route called');
    

  try {
    
    const user = await UserModel.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials." });
    }

    const token = jwt.sign({ username: user.username, userId: user.user_id, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({ message: "Login successful", jwtToken: token });
  } catch (error) {
    console.error("Error during login:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Middleware to validate request data for creating/updating todos
const validateTodoData = (req, res, next) => {
  const { error } = todoValidationSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }
  next();
};

// Task Routes
app.get('/tasks/', authenticateToken, async (req, res) => {
    // console.log('tasks route called to get all tasks');
    
  try {
    const todos = await TodosModel.find({ user_id: req.userId });
    if (todos.length === 0) {
      return res.status(404).json({ message: "No tasks found. Create new tasks!" });
    }
    res.status(200).json(todos);
  } catch (error) {
    console.error("Error retrieving todos:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.post('/tasks/', authenticateToken, validateTodoData, async (req, res) => {
    // console.log('tasks route to add new task');
    
  try {
    const { title, description, priority, status } = req.body;
    const newTodo = new TodosModel({
      user_id: req.userId,
      taskId: uuidv4(),
      title,
      description,
      priority,
      status,
    });
    await newTodo.save();
    res.status(201).json({ message: "Todo created successfully.", newTodo });
  } catch (error) {
    console.error("Error creating todo:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.put('/tasks/:taskId', authenticateToken, validateTodoData, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { title, description, status, priority } = req.body;

    const todo = await TodosModel.findOne({ taskId, user_id: req.userId });
    if (!todo) {
      return res.status(404).json({ message: "Todo not found." });
    }

    const updatedTodo = await TodosModel.findOneAndUpdate(
      { taskId, user_id: req.userId },
      { $set: { title, description, status, priority } },
      { new: true }
    );

    res.status(200).json({ message: "Todo updated successfully.", updatedTodo });
  } catch (error) {
    console.error("Error updating todo:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.delete('/tasks/:taskId', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const result = await TodosModel.findOneAndDelete({ taskId, user_id: req.userId });

    if (result) {
      res.status(200).json({ message: "Todo deleted successfully." });
    } else {
      res.status(404).json({ message: "Todo not found." });
    }
  } catch (error) {
    console.error("Error deleting todo:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Profile Routes
app.get('/profile/', authenticateToken, async (req, res) => {
  try {
    const profile = await UserModel.findOne({ user_id: req.userId });
    if (!profile) {
      return res.status(404).json({ message: "Profile not found." });
    }
    res.status(200).json(profile);
  } catch (error) {
    console.error("Error retrieving profile:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.put('/profile/', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;
    if (updates.password) {
      updates.password = await bcrypt.hash(updates.password, 10);
    }

    const updatedProfile = await UserModel.findOneAndUpdate(
      { user_id: req.userId },
      { $set: updates },
      { new: true }
    );

    res.status(200).json({ message: "Profile updated successfully.", updatedProfile });
  } catch (error) {
    console.error("Error updating profile:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.delete('/profile/', authenticateToken, async (req, res) => {
  try {
    const result = await UserModel.findOneAndDelete({ user_id: req.userId });
    if (result) {
      res.status(200).json({ message: "Profile deleted successfully." });
    } else {
      res.status(404).json({ message: "Profile not found." });
    }
  } catch (error) {
    console.error("Error deleting profile:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Admin-only Route
app.get('/users/', authenticateToken, authorizeRole('ADMIN'), async (req, res) => {
  try {
    const users = await UserModel.find();
    res.status(200).json(users);
  } catch (error) {
    console.error("Error retrieving users:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});


