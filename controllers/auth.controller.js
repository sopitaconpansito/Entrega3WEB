import sql from '../db.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs'; // corregir typo en 'bycrypt'

const clave = 'INSAAAID'; // clave para firmar el JWT

export const authController = {
  // registro de usuario
  register: async (req, res) => {
    const { name, email, password } = req.body;
    try {
      // verifica si el email ya esta registrado
      const existingUser = await sql('SELECT * FROM users WHERE email = $1', [email]);
      if (existingUser.length > 0) {
        return res.status(400).json({ message: 'El correo electrónico ya está registrado.' });
      }

      // hashea la contraseña
      const hashedPassword = await bcrypt.hash(password, 10);

      // crear nuevo usuario
      const newUser = await sql(
        'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
        [name, email, hashedPassword]
      );

      // obtiene el usuario recién creado
      const createdUser = newUser[0];

      const payload = {
        id: createdUser.id, // corregir id de loggedUser a createdUser
        role: createdUser.admin || 'user', // asegurar un valor por defecto
      };

      // genera el token JWT
      const token = jwt.sign(payload, clave);

      // establece cookie con el token
      res.cookie('token', token, {
        httpOnly: true,
        secure: false, // cambiar a true en producción si usas HTTPS
        sameSite: 'lax',
      });

      return res.status(200).json({
        ok: true,
        message: 'Usuario registrado con éxito',
        token,
      });
    } catch (error) {
      console.error('Error al registrar usuario:', error);
      res.status(500).json({ message: 'Error del servidor' });
    }
  },

  // login de usuario
  login: async (req, res) => {
    const { email, password } = req.body;
    try {
      // busca el usuario en la base de datos
      const user = await sql('SELECT * FROM users WHERE email = $1', [email]);

      // verifica si el usuario existe
      if (!user.length) {
        return res.status(401).json({ message: 'Credenciales inválidas' });
      }

      // toma el primer usuario
      const loggedUser = user[0];

      // verifica la contraseña
      const validPassword = await bcrypt.compare(password, loggedUser.password);
      if (!validPassword) {
        return res.status(401).json({ message: 'Credenciales inválidas' });
      }

      const payload = {
        id: loggedUser.id,
        role: loggedUser.admin || 'user', // asegurar un valor por defecto
      };

      // genera el token JWT
      const token = jwt.sign(payload, clave);

      // establece cookie con el token
      res.cookie('token', token, {
        httpOnly: true,
        secure: false, // cambiar a true en producción si usas HTTPS
        sameSite: 'lax',
      });

      return res.status(200).json({
        message: 'Login exitoso',
        token,
      });
    } catch (error) {
      console.error('Error al iniciar sesión:', error);
      res.status(500).json({ message: 'Error del servidor' });
    }
  },
};
