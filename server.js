require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'secreto_fallback';

app.use(cors());
app.use(express.json());

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(async () => {
    console.log('Conectado exitosamente a MongoDB');
    await inicializarUsuarios();
  })
  .catch(err => console.error('Error de conexión a MongoDB:', err.message));

// Esquemas
const usuarioSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  rol: { type: String, enum: ['admin', 'empleado'], default: 'empleado' }
});
const Usuario = mongoose.model('Usuario', usuarioSchema);

const productoSchema = new mongoose.Schema({
  codigo: { type: String, required: true, unique: true, uppercase: true },
  categoria: { type: String, required: true, enum: ['Maquillaje', 'Accesorios', 'Perfumería'] },
  nombre: { type: String, required: true },
  marca: { type: String, default: '' },
  precio: { type: Number, required: true, min: 0 },
  stock: { type: Number, required: true, min: 0 },
  minimo: { type: Number, default: 5 }
}, { timestamps: true });
const Producto = mongoose.model('Producto', productoSchema);

async function inicializarUsuarios() {
  const adminExiste = await Usuario.findOne({ username: 'admin' });
  if (!adminExiste) {
    const hash = await bcrypt.hash('admin123', 10);
    await Usuario.create({ username: 'admin', password: hash, rol: 'admin' });
    console.log('Usuario admin creado: admin / admin123');
  }

  const empExiste = await Usuario.findOne({ username: 'empleado' });
  if (!empExiste) {
    const hash = await bcrypt.hash('empleado123', 10);
    await Usuario.create({ username: 'empleado', password: hash, rol: 'empleado' });
    console.log('Usuario empleado creado: empleado / empleado123');
  }
}

// Middlewares
function verificarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ mensaje: 'Token no proporcionado' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ mensaje: 'Token inválido o expirado' });
    req.usuario = decoded;
    next();
  });
}

function soloAdmin(req, res, next) {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ mensaje: 'Acción permitida únicamente para administradores' });
  }
  next();
}

// Rutas
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await Usuario.findOne({ username });
  if (!user) return res.status(400).json({ mensaje: 'Credenciales inválidas' });

  const coinciden = await bcrypt.compare(password, user.password);
  if (!coinciden) return res.status(400).json({ mensaje: 'Credenciales inválidas' });

  const token = jwt.sign({ id: user._id, rol: user.rol, username: user.username }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, rol: user.rol, username: user.username });
});

app.get('/api/productos', verificarToken, async (req, res) => {
  try {
    const lista = await Producto.find().sort({ createdAt: -1 });
    res.json(lista);
  } catch (error) {
    res.status(500).json({ mensaje: 'Error al obtener productos' });
  }
});

app.post('/api/productos', verificarToken, async (req, res) => {
  try {
    const nuevo = new Producto(req.body);
    await nuevo.save();
    res.status(201).json(nuevo);
  } catch (error) {
    res.status(400).json({ mensaje: 'Error al guardar producto', detalle: error.message });
  }
});

app.put('/api/productos/:id', verificarToken, soloAdmin, async (req, res) => {
  try {
    const editado = await Producto.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!editado) return res.status(404).json({ mensaje: 'Producto no encontrado' });
    res.json(editado);
  } catch (error) {
    res.status(400).json({ mensaje: 'Error al actualizar producto' });
  }
});

app.patch('/api/productos/:id/stock', verificarToken, soloAdmin, async (req, res) => {
  try {
    const { delta } = req.body;
    const producto = await Producto.findById(req.params.id);
    if (!producto) return res.status(404).json({ mensaje: 'Producto no encontrado' });
    if (producto.stock + delta < 0) return res.status(400).json({ mensaje: 'No puede haber stock negativo' });

    producto.stock += delta;
    await producto.save();
    res.json(producto);
  } catch (error) {
    res.status(400).json({ mensaje: 'Error al ajustar existencias' });
  }
});

app.delete('/api/productos/:id', verificarToken, soloAdmin, async (req, res) => {
  try {
    const eliminado = await Producto.findByIdAndDelete(req.params.id);
    if (!eliminado) return res.status(404).json({ mensaje: 'Producto no encontrado' });
    res.json({ mensaje: 'Producto eliminado con éxito' });
  } catch (error) {
    res.status(500).json({ mensaje: 'Error al eliminar' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en el puerto ${PORT}`);
});

const path = require('path');

// Servir archivos estáticos (incluye index.html)
app.use(express.static(path.join(__dirname)));

// Servir index.html para cualquier ruta no capturada previamente
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
