import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { createClient } from '@libsql/client';

// Подключение к Turso через переменные окружения
const db = createClient({ 
  url: process.env.TURSO_URL, 
  authToken: process.env.TURSO_TOKEN 
});

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static('public')); // Папка, где лежат ваши HTML файлы

// Промежуточный слой (middleware) для проверки авторизации
async function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid) return res.status(401).json({ error: 'Log in first' });

  const r = await db.execute({
    sql: 'SELECT username FROM sessions WHERE id = ? AND expiresAt > ?',
    args: [sid, Date.now()]
  });

  if (!r.rows.length) return res.status(401).json({ error: 'Session expired or invalid' });
  
  req.user = r.rows[0].username;
  next();
}

// Эндпоинт для входа (логина)
app.post('/api/login', async (req, res) => {
  const { id, password } = req.body;
  if (!id || !password) return res.status(400).json({ error: 'Fill in all fields' });

  // Ищем пользователя по username или email
  const r = await db.execute({
    sql: 'SELECT * FROM users WHERE username = ? OR lower(email) = lower(?)', 
    args: [id, id] 
  });
  
  const u = r.rows[0];
  let ok = false;

  if (u) {
    if (u.passwordHash) {
      // Проверка через безопасный хэш
      ok = await bcrypt.compare(password, u.passwordHash);
    } else if (u.password && u.password === password) {
      // Старый пароль в открытом виде: разрешаем вход и автоматически обновляем на хэш
      ok = true;
      const hashed = await bcrypt.hash(password, 12);
      await db.execute({ 
        sql: 'UPDATE users SET passwordHash = ?, password = NULL WHERE username = ?',
        args: [hashed, u.username] 
      });
    }
  }

  if (!ok) return res.status(401).json({ error: 'Wrong username or password' });

  // Создаем сессию
  const sid = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 30 * 86400000; // 30 дней

  await db.execute({ 
    sql: 'INSERT INTO sessions (id, username, expiresAt) VALUES (?,?,?)',
    args: [sid, u.username, expiresAt] 
  });

  // Отправляем защищенную cookie
  res.cookie('sid', sid, { 
    httpOnly: true, 
    secure: true, // true для HTTPS (на продакшене)
    sameSite: 'lax', 
    maxAge: 30 * 86400000 
  });

  res.json({ username: u.username });
});

// Простой пример защищенного эндпоинта (проверка, кто вошел)
app.get('/api/me', auth, (req, res) => {
  res.json({ username: req.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
