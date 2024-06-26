const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

// Configuração do banco de dados
const dbConfig = {
  host: 'localhost',
  user: 'weuler',
  password: 'Deusefiel@2002',
  database: 'mydb',
  port: 3306
};

// Chave secreta para JWT
const secretKey = 'yourSecretKey';

// Função para conectar ao banco de dados
let connection;
async function connectToDatabase() {
  try {
    connection = await mysql.createConnection(dbConfig);
    console.log('Connected to the database');
  } catch (err) {
    console.error('Error connecting to the database', err);
  }
}

connectToDatabase();

// Configuração do multer para upload de arquivos
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  let pathname = decodeURIComponent(parsedUrl.pathname);

  // Configurar headers para CORS e JSON
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (pathname.startsWith('/uploads/')) {
    // Servir arquivos da pasta uploads
    const filePath = path.join(__dirname, pathname);
    console.log(`Tentando servir o arquivo: ${filePath}`);
    fs.readFile(filePath, (err, content) => {
      if (err) {
        console.error(`Erro ao ler o arquivo ${filePath}:`, err);
        res.writeHead(404);
        res.end(JSON.stringify({ message: 'File Not Found' }));
      } else {
        res.writeHead(200, { 'Content-Type': getContentType(filePath) });
        res.end(content);
      }
    });
    return;
  }

  // Roteamento para endpoints da API
  if (pathname === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', async () => {
      const { username, password } = JSON.parse(body);

      try {
        const [rows] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);

        if (rows.length > 0 && bcrypt.compareSync(password, rows[0].password)) {
          const token = jwt.sign({ username: rows[0].username, role: rows[0].role }, secretKey, { expiresIn: '1h' });
          console.log('Login successful:', username);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'Login successful', token }));
        } else {
          console.log('Login failed: Invalid credentials');
          res.writeHead(401);
          res.end(JSON.stringify({ message: 'Invalid credentials' }));
        }
      } catch (err) {
        console.error('Database error:', err);
        res.writeHead(500);
        res.end(JSON.stringify({ message: 'Internal Server Error' }));
      }
    });

  } else if (pathname === '/userinfo' && req.method === 'GET') {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
      res.writeHead(401);
      res.end(JSON.stringify({ message: 'Unauthorized' }));
      return;
    }

    try {
      const decoded = jwt.verify(token, secretKey);
      const [rows] = await connection.execute('SELECT username, role FROM users WHERE username = ?', [decoded.username]);
      if (rows.length > 0) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(rows[0]));
      } else {
        res.writeHead(404);
        res.end(JSON.stringify({ message: 'User not found' }));
      }
    } catch (err) {
      console.error('JWT error:', err);
      res.writeHead(401);
      res.end(JSON.stringify({ message: 'Invalid token' }));
    }

  } else if (pathname === '/add-student' && req.method === 'POST') {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
      res.writeHead(401);
      res.end(JSON.stringify({ message: 'Unauthorized' }));
      return;
    }

    try {
      const decoded = jwt.verify(token, secretKey);
      if (decoded.role !== 'admin') {
        res.writeHead(403);
        res.end(JSON.stringify({ message: 'Forbidden' }));
        return;
      }

      upload.single('photo')(req, res, async function (err) {
        if (err) {
          console.error('Upload error:', err);
          res.writeHead(500);
          res.end(JSON.stringify({ message: 'Erro ao fazer upload da foto' }));
          return;
        }

        const { studentName } = req.body;
        const photoPath = path.join('uploads', req.file.filename).replace(/\\/g, '/');  // Normaliza o caminho da foto
        console.log(`Foto salva em: ${photoPath}`);

        try {
          const [existingStudent] = await connection.execute(
            'SELECT * FROM students WHERE name = ?',
            [studentName]
          );

          if (existingStudent.length > 0) {
            res.writeHead(409);
            res.end(JSON.stringify({ message: 'Aluno já existe' }));
            return;
          }

          const [result] = await connection.execute(
            'INSERT INTO students (name, photo) VALUES (?, ?)',
            [studentName, photoPath]
          );
          console.log('Aluno adicionado:', result.insertId);
          res.writeHead(201);
          res.end(JSON.stringify({ message: 'Aluno adicionado com sucesso' }));
        } catch (err) {
          console.error('Erro ao adicionar aluno:', err);
          res.writeHead(500);
          res.end(JSON.stringify({ message: 'Erro interno do servidor' }));
        }
      });

    } catch (err) {
      console.error('JWT error:', err);
      res.writeHead(401);
      res.end(JSON.stringify({ message: 'Invalid token' }));
    }

  } else if (pathname === '/students' && req.method === 'GET') {
    try {
      const [rows] = await connection.execute('SELECT * FROM students');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(rows));
    } catch (err) {
      console.error('Database error:', err);
      res.writeHead(500);
      res.end(JSON.stringify({ message: 'Internal Server Error' }));
    }
  } else if (pathname === '/delete-student' && req.method === 'DELETE') {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
      res.writeHead(401);
      res.end(JSON.stringify({ message: 'Unauthorized' }));
      return;
    }

    try {
      const decoded = jwt.verify(token, secretKey);
      if (decoded.role !== 'admin') {
        res.writeHead(403);
        res.end(JSON.stringify({ message: 'Forbidden' }));
        return;
      }

      const studentId = parsedUrl.query.id;
      console.log(`Tentando deletar aluno com ID: ${studentId}`);
      if (!studentId) {
        res.writeHead(400);
        res.end(JSON.stringify({ message: 'Missing student ID' }));
        return;
      }

      const [result] = await connection.execute('DELETE FROM students WHERE id = ?', [studentId]);
      if (result.affectedRows > 0) {
        console.log('Aluno deletado com sucesso');
        res.writeHead(200);
        res.end(JSON.stringify({ message: 'Student deleted successfully' }));
      } else {
        console.log('Aluno não encontrado');
        res.writeHead(404);
        res.end(JSON.stringify({ message: 'Student not found' }));
      }
    } catch (err) {
      console.error('Erro ao deletar aluno:', err);
      res.writeHead(500);
      res.end(JSON.stringify({ message: 'Internal Server Error' }));
    }
  } else if (pathname === '/edit-student' && req.method === 'PUT') {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
      res.writeHead(401);
      res.end(JSON.stringify({ message: 'Unauthorized' }));
      return;
    }

    try {
      const decoded = jwt.verify(token, secretKey);
      if (decoded.role !== 'admin') {
        res.writeHead(403);
        res.end(JSON.stringify({ message: 'Forbidden' }));
        return;
      }

      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });

      req.on('end', async () => {
        const { id, studentName, photoPath } = JSON.parse(body);
        console.log(`Tentando editar aluno com ID: ${id}, Nome: ${studentName}, Foto: ${photoPath}`);
        if (!id || !studentName || !photoPath) {
          res.writeHead(400);
          res.end(JSON.stringify({ message: 'Missing required fields' }));
          return;
        }

        const [result] = await connection.execute(
          'UPDATE students SET name = ?, photo = ? WHERE id = ?',
          [studentName, photoPath, id]
        );
        if (result.affectedRows > 0) {
          console.log('Aluno editado com sucesso');
          res.writeHead(200);
          res.end(JSON.stringify({ message: 'Student updated successfully' }));
        } else {
          console.log('Aluno não encontrado');
          res.writeHead(404);
          res.end(JSON.stringify({ message: 'Student not found' }));
        }
      });
    } catch (err) {
      console.error('Erro ao editar aluno:', err);
      res.writeHead(500);
      res.end(JSON.stringify({ message: 'Internal Server Error' }));
    }
  } else if (pathname === '/cadastro' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', async () => {
      const formData = new URLSearchParams(body);

      const username = formData.get('username');
      const email = formData.get('email');
      const password = formData.get('password');
      const confirm_password = formData.get('confirm_password');
      const role = formData.get('role');

      // Verifica se as senhas coincidem
      if (password !== confirm_password) {
        res.writeHead(400);
        res.end(JSON.stringify({ message: 'As senhas não coincidem' }));
        return;
      }

      try {
        // Verifica se o usuário já existe
        const [existingUsers] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (existingUsers.length > 0) {
          res.writeHead(400);
          res.end(JSON.stringify({ message: 'Este nome de usuário já está em uso' }));
          return;
        }

        // Hash da senha
        const hashedPassword = bcrypt.hashSync(password, 10);

        // Insere o novo usuário no banco de dados
        const [result] = await connection.execute(
          'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
          [username, email, hashedPassword, role]
        );

        console.log('Novo usuário cadastrado:', result.insertId);

        res.writeHead(201);
        res.end(JSON.stringify({ message: 'Usuário cadastrado com sucesso' }));
      } catch (err) {
        console.error('Erro ao cadastrar usuário:', err);
        res.writeHead(500);
        res.end(JSON.stringify({ message: 'Erro interno do servidor' }));
      }
    });
  } else if (pathname === '/add-gallery-photo' && req.method === 'POST') {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
      res.writeHead(401);
      res.end(JSON.stringify({ message: 'Unauthorized' }));
      return;
    }

    try {
      const decoded = jwt.verify(token, secretKey);
      if (decoded.role !== 'admin' && decoded.role !== 'student') {
        res.writeHead(403);
        res.end(JSON.stringify({ message: 'Forbidden' }));
        return;
      }

      upload.single('photo')(req, res, async function (err) {
        if (err) {
          console.error('Upload error:', err);
          res.writeHead(500);
          res.end(JSON.stringify({ message: 'Erro ao fazer upload da foto' }));
          return;
        }

        const photoPath = path.join('uploads', req.file.filename).replace(/\\/g, '/');  // Normaliza o caminho da foto
        console.log(`Foto da galeria salva em: ${photoPath}`);

        try {
          const [result] = await connection.execute(
            'INSERT INTO gallery (filename, filepath) VALUES (?, ?)',
            [req.file.originalname, photoPath]
          );
          console.log('Foto da galeria adicionada:', result.insertId);
          res.writeHead(201);
          res.end(JSON.stringify({ message: 'Foto da galeria adicionada com sucesso', photoPath }));
        } catch (err) {
          console.error('Erro ao adicionar foto na galeria:', err);
          res.writeHead(500);
          res.end(JSON.stringify({ message: 'Erro interno do servidor' }));
        }
      });

    } catch (err) {
      console.error('JWT error:', err);
      res.writeHead(401);
      res.end(JSON.stringify({ message: 'Invalid token' }));
    }

  } else if (pathname === '/gallery-photos' && req.method === 'GET') {
    try {
      const [rows] = await connection.execute('SELECT * FROM gallery');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(rows));
    } catch (err) {
      console.error('Database error:', err);
      res.writeHead(500);
      res.end(JSON.stringify({ message: 'Internal Server Error' }));
    }
  } else {
    if (pathname === '/' || pathname === '') {
      pathname = '/index.html';
    }

    const filePath = path.join(__dirname, 'public', pathname);
    fs.readFile(filePath, (err, content) => {
      if (err) {
        if (err.code === 'ENOENT') {
          res.writeHead(404);
          res.end(JSON.stringify({ message: 'File Not Found' }));
        } else {
          res.writeHead(500);
          res.end(JSON.stringify({ message: 'Internal Server Error' }));
        }
      } else {
        res.writeHead(200, { 'Content-Type': getContentType(filePath) });
        res.end(content);
      }
    });
  }
});

function getContentType(filePath) {
  const extname = path.extname(filePath);
  switch (extname) {
    case '.html':
      return 'text/html';
    case '.css':
      return 'text/css';
    case '.js':
      return 'text/javascript';
    case '.json':
      return 'application/json';
    case '.png':
      return 'image/png';
    case '.jpg':
      return 'image/jpg';
    default:
      return 'application/octet-stream';
  }
}

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
