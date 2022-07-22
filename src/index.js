const express = require('express');
const cors = require("cors");

const app = express();
app.use(cors());

app.use(express.json());

// Referenciando o controle de autenticação e passando o "app" do express pro auth (Step A):
require('./app/controllers/authController')(app);
require('./app/controllers/projectController')(app);

// require('./app/controllers/index.js')(app);







app.get('/', (req, res) => {
    res.send('Ok!')

})

console.log('Servidor rodando!!')





app.listen(3000);























// // importar as rotas
// const moviesRoutes = require("./routes/moviesRoutes");

// // 1. definir rota raiz do projeto
// app.use("/movies", moviesRoutes);

// module.exports = app;