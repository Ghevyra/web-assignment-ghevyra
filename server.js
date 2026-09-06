const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'uin-sgd-if-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 day
}));

// Multer Storage Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'public', 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // limit 5MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|pdf|doc|docx|zip/;
        const extName = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        if (extName) {
            return cb(null, true);
        }
        cb(new Error('Hanya file dokumen, gambar, atau zip yang diizinkan!'));
    }
});

// Helper Functions for JSON DB
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const ASSIGNMENTS_FILE = path.join(__dirname, 'data', 'assignments.json');

function readData(filePath) {
    if (!fs.existsSync(filePath)) return [];
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        return [];
    }
}

function writeData(filePath, data) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }
    res.status(401).json({ success: false, message: 'Unauthorized. Silakan login terlebih dahulu.' });
}

// Routes - Views
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'register.html'));
});
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});
app.get('/tambah-tugas', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'add-assignment.html'));
});
app.get('/edit-assignment', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'edit-assignment.html'));
});

// API - Auth
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Username dan password wajib diisi!' });
        }
        const users = readData(USERS_FILE);
        const existing = users.find(u => u.username === username);
        if (existing) {
            return res.status(400).json({ success: false, message: 'Username sudah terdaftar!' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: users.length > 0 ? users[users.length - 1].id + 1 : 1,
            username,
            password: hashedPassword
        };
        users.push(newUser);
        writeData(USERS_FILE, users);
        res.json({ success: true, message: 'Registrasi berhasil! Silakan login.' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const users = readData(USERS_FILE);
        const user = users.find(u => u.username === username);
        if (!user) {
            return res.status(400).json({ success: false, message: 'Username atau password salah!' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Username atau password salah!' });
        }
        req.session.user = { id: user.id, username: user.username };
        res.json({ success: true, message: 'Login berhasil!', user: req.session.user });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/check-session', (req, res) => {
    if (req.session && req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ success: false, message: 'Gagal logout' });
        res.clearCookie('connect.sid');
        res.json({ success: true, message: 'Logout berhasil' });
    });
});

// API - Assignments (Protected & User Isolated)
app.get('/api/assignments', isAuthenticated, (req, res) => {
    const assignments = readData(ASSIGNMENTS_FILE);
    const userAssignments = assignments.filter(a => a.userId === req.session.user.id);
    res.json({ success: true, data: userAssignments });
});

app.get('/api/assignments/:id', isAuthenticated, (req, res) => {
    const assignments = readData(ASSIGNMENTS_FILE);
    const assignment = assignments.find(a => a.id === parseInt(req.params.id) && a.userId === req.session.user.id);
    if (!assignment) {
        return res.status(404).json({ success: false, message: 'Tugas tidak ditemukan' });
    }
    res.json({ success: true, data: assignment });
});

app.post('/api/assignments', isAuthenticated, upload.single('file'), (req, res) => {
    try {
        const { title, course, deadline, status, description } = req.body;
        if (!title || !course || !deadline) {
            return res.status(400).json({ success: false, message: 'Judul, Mata Kuliah, dan Deadline wajib diisi!' });
        }
        const assignments = readData(ASSIGNMENTS_FILE);
        const newAssignment = {
            id: assignments.length > 0 ? assignments[assignments.length - 1].id + 1 : 1,
            userId: req.session.user.id,
            title,
            course,
            deadline,
            status: status || 'Belum Selesai',
            description: description || '',
            filename: req.file ? req.file.filename : ''
        };
        assignments.push(newAssignment);
        writeData(ASSIGNMENTS_FILE, assignments);
        res.json({ success: true, message: 'Tugas berhasil ditambahkan!', data: newAssignment });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/assignments/:id', isAuthenticated, upload.single('file'), (req, res) => {
    try {
        const assignments = readData(ASSIGNMENTS_FILE);
        const index = assignments.findIndex(a => a.id === parseInt(req.params.id) && a.userId === req.session.user.id);
        if (index === -1) {
            return res.status(404).json({ success: false, message: 'Tugas tidak ditemukan' });
        }
        const { title, course, deadline, status, description } = req.body;
        const existing = assignments[index];

        assignments[index] = {
            id: existing.id,
            userId: existing.userId,
            title: title || existing.title,
            course: course || existing.course,
            deadline: deadline || existing.deadline,
            status: status || existing.status,
            description: description !== undefined ? description : existing.description,
            filename: req.file ? req.file.filename : existing.filename
        };

        writeData(ASSIGNMENTS_FILE, assignments);
        res.json({ success: true, message: 'Tugas berhasil diperbarui!', data: assignments[index] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.delete('/api/assignments/:id', isAuthenticated, (req, res) => {
    try {
        let assignments = readData(ASSIGNMENTS_FILE);
        const index = assignments.findIndex(a => a.id === parseInt(req.params.id) && a.userId === req.session.user.id);
        if (index === -1) {
            return res.status(404).json({ success: false, message: 'Tugas tidak ditemukan' });
        }
        const assignment = assignments[index];
        if (assignment.filename) {
            const filePath = path.join(__dirname, 'public', 'uploads', assignment.filename);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }
        assignments.splice(index, 1);
        writeData(ASSIGNMENTS_FILE, assignments);
        res.json({ success: true, message: 'Tugas berhasil dihapus!' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server berjalan mulus di http://localhost:${PORT}`);
});