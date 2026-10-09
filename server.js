require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'secreto_fallback';

app.use(cors());
app.use(express.json());

// Servir archivos estáticos del frontend
app.use(express.static(path.join(__dirname)));

// Conexión a MongoDB Atlas
mongoose.connect(process.env.MONGO_URI)
  .then(async () => {
    console.log('Conectado exitosamente a MongoDB');
    await inicializarUsuarios();
  })
  .catch(err => console.error('Error de conexión a MongoDB:', err.message));

// Esquemas y Modelos
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
  referencia: { type: String, default: '' },
  fechaVencimiento: { type: Date, default: null },
  precio: { type: Number, required: true, min: 0 },
  stock: { type: Number, required: true, min: 0 },
  minimo: { type: Number, default: 5 }
}, { timestamps: true });
const Producto = mongoose.model('Producto', productoSchema);

const salidaSchema = new mongoose.Schema({
  productoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Producto', required: true },
  nombreProducto: { type: String, required: true },
  codigoProducto: { type: String, required: true },
  cantidad: { type: Number, required: true, min: 1 },
  precioUnitario: { type: Number, default: 0 },
  motivo: { type: String, enum: ['Venta', 'Uso en salón', 'Dañado/Vencido'], default: 'Venta' },
  usuario: { type: String, required: true }
}, { timestamps: true });
const Salida = mongoose.model('Salida', salidaSchema);

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

// --- Autenticación ---
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await Usuario.findOne({ username });
  if (!user) return res.status(400).json({ mensaje: 'Credenciales inválidas' });

  const coinciden = await bcrypt.compare(password, user.password);
  if (!coinciden) return res.status(400).json({ mensaje: 'Credenciales inválidas' });

  const token = jwt.sign({ id: user._id, rol: user.rol, username: user.username }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, rol: user.rol, username: user.username });
});

// --- Inventario de Productos ---
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
    const productoEliminado = await Producto.findByIdAndDelete(req.params.id);
    if (!productoEliminado) return res.status(404).json({ mensaje: 'Producto no encontrado' });

    const resultadoSalidas = await Salida.deleteMany({ productoId: req.params.id });

    res.json({
      mensaje: `Producto "${productoEliminado.nombre}" eliminado exitosamente junto con ${resultadoSalidas.deletedCount} registro(s) de salidas asociados.`,
      salidasEliminadas: resultadoSalidas.deletedCount
    });
  } catch (error) {
    res.status(500).json({ mensaje: 'Error al eliminar el producto', detalle: error.message });
  }
});

// --- Registro de Salidas ---
app.get('/api/salidas', verificarToken, async (req, res) => {
  try {
    const salidas = await Salida.find().sort({ createdAt: -1 });
    res.json(salidas);
  } catch (error) {
    res.status(500).json({ mensaje: 'Error al obtener historial de salidas' });
  }
});

app.post('/api/salidas', verificarToken, async (req, res) => {
  try {
    const { productoId, cantidad, motivo } = req.body;
    const cant = parseInt(cantidad, 10);

    const producto = await Producto.findById(productoId);
    if (!producto) return res.status(404).json({ mensaje: 'Producto no encontrado' });

    if (producto.stock < cant) {
      return res.status(400).json({ mensaje: `Stock insuficiente. Disponibles: ${producto.stock}` });
    }

    producto.stock -= cant;
    await producto.save();

    const nuevaSalida = new Salida({
      productoId: producto._id,
      nombreProducto: producto.nombre,
      codigoProducto: producto.codigo,
      cantidad: cant,
      precioUnitario: producto.precio || 0,
      motivo: motivo || 'Venta',
      usuario: req.usuario.username
    });
    await nuevaSalida.save();

    res.status(201).json({ mensaje: 'Salida registrada correctamente', salida: nuevaSalida, stockActual: producto.stock });
  } catch (error) {
    res.status(400).json({ mensaje: 'Error al registrar salida', detalle: error.message });
  }
});

app.delete('/api/salidas/:id', verificarToken, soloAdmin, async (req, res) => {
  try {
    const salida = await Salida.findById(req.params.id);
    if (!salida) return res.status(404).json({ mensaje: 'Registro de salida no encontrado' });

    if (salida.productoId) {
      const producto = await Producto.findById(salida.productoId);
      if (producto) {
        producto.stock += salida.cantidad;
        await producto.save();
      }
    }

    await Salida.findByIdAndDelete(req.params.id);
    res.json({ mensaje: 'Registro de salida eliminado y stock restituido exitosamente' });
  } catch (error) {
    res.status(500).json({ mensaje: 'Error al eliminar el registro de salida', detalle: error.message });
  }
});

// --- Endpoint de Alertas de Vencimiento y Rotación ---
app.get('/api/reportes/alertas-inventario', verificarToken, async (req, res) => {
  try {
    const productos = await Producto.find();
    const hoy = new Date();
    hoy.setHours(0, 0, 0, 0);

    const limite30Dias = new Date(hoy);
    limite30Dias.setDate(hoy.getDate() + 30);

    const productosPorVencer = [];

    productos.forEach(p => {
      if (p.fechaVencimiento && p.stock > 0) {
        const fechaVenc = new Date(p.fechaVencimiento);
        fechaVenc.setHours(0, 0, 0, 0);

        if (fechaVenc <= limite30Dias) {
          const diferenciaTiempo = fechaVenc.getTime() - hoy.getTime();
          const diasRestantes = Math.ceil(diferenciaTiempo / (1000 * 60 * 60 * 24));
          
          productosPorVencer.push({
            _id: p._id,
            codigo: p.codigo,
            nombre: p.nombre,
            marca: p.marca || 'N/A',
            referencia: p.referencia || 'N/A',
            categoria: p.categoria,
            stock: p.stock,
            precio: p.precio,
            fechaVencimiento: p.fechaVencimiento,
            diasRestantes: diasRestantes,
            estado: diasRestantes < 0 ? 'VENCIDO' : (diasRestantes === 0 ? 'VENCE HOY' : `Vence en ${diasRestantes} días`)
          });
        }
      }
    });

    // Ordenar: primero los más urgentes (vencidos primero, luego los que vencen antes)
    productosPorVencer.sort((a, b) => a.diasRestantes - b.diasRestantes);

    res.json({ porVencer: productosPorVencer });
  } catch (error) {
    res.status(500).json({ mensaje: 'Error al obtener alertas', detalle: error.message });
  }
});

// --- Reportes de Ventas por Fechas y Categoría ---
app.get('/api/reportes/ventas', verificarToken, async (req, res) => {
  try {
    const { inicio, fin, categoria } = req.query;
    let filtro = { motivo: 'Venta' };

    if (inicio && fin) {
      const fechaInicio = new Date(inicio);
      fechaInicio.setHours(0, 0, 0, 0);

      const fechaFin = new Date(fin);
      fechaFin.setHours(23, 59, 59, 999);

      filtro.createdAt = { $gte: fechaInicio, $lte: fechaFin };
    }

    let ventas = await Salida.find(filtro).populate('productoId', 'categoria marca referencia').sort({ createdAt: -1 });

    if (categoria && categoria !== 'TODAS') {
      ventas = ventas.filter(v => v.productoId && v.productoId.categoria && v.productoId.categoria.toLowerCase() === categoria.toLowerCase());
    }

    const totalIngresos = ventas.reduce((acc, v) => acc + (v.cantidad * (v.precioUnitario || 0)), 0);
    const totalUnidadesVendidas = ventas.reduce((acc, v) => acc + v.cantidad, 0);

    const porDia = {};
    const porSemana = {};
    const porQuincena = {};

    ventas.forEach(v => {
      const fecha = new Date(v.createdAt);
      const subtotal = (v.cantidad || 0) * (v.precioUnitario || 0);

      const diaKey = fecha.toISOString().split('T')[0];
      if (!porDia[diaKey]) porDia[diaKey] = { fecha: diaKey, total: 0, unidades: 0, operaciones: 0 };
      porDia[diaKey].total += subtotal;
      porDia[diaKey].unidades += v.cantidad;
      porDia[diaKey].operaciones += 1;

      const primerDiaAnio = new Date(fecha.getFullYear(), 0, 1);
      const dias = Math.floor((fecha - primerDiaAnio) / (24 * 60 * 60 * 1000));
      const semanaNum = Math.ceil((fecha.getDay() + 1 + dias) / 7);
      const semanaKey = `Semana ${semanaNum} (${fecha.getFullYear()})`;
      if (!porSemana[semanaKey]) porSemana[semanaKey] = { periodo: semanaKey, total: 0, unidades: 0, operaciones: 0 };
      porSemana[semanaKey].total += subtotal;
      porSemana[semanaKey].unidades += v.cantidad;
      porSemana[semanaKey].operaciones += 1;

      const mesNombre = fecha.toLocaleString('es-ES', { month: 'short' });
      const quincenaNum = fecha.getDate() <= 15 ? '1ra Quincena' : '2da Quincena';
      const quincenaKey = `${quincenaNum} ${mesNombre} ${fecha.getFullYear()}`;
      if (!porQuincena[quincenaKey]) porQuincena[quincenaKey] = { periodo: quincenaKey, total: 0, unidades: 0, operaciones: 0 };
      porQuincena[quincenaKey].total += subtotal;
      porQuincena[quincenaKey].unidades += v.cantidad;
      porQuincena[quincenaKey].operaciones += 1;
    });

    res.json({
      totalIngresos,
      totalUnidadesVendidas,
      conteoVentas: ventas.length,
      detalles: ventas,
      resumenPorDia: Object.values(porDia),
      resumenPorSemana: Object.values(porSemana),
      resumenPorQuincena: Object.values(porQuincena)
    });
  } catch (error) {
    res.status(500).json({ mensaje: 'Error al generar reporte de ventas', detalle: error.message });
  }
});

// Middleware universal para SPA
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en el puerto ${PORT}`);
});