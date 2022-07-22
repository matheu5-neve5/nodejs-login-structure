const path = require('path');
const nodemailer = require('nodemailer');
const hbs = require('nodemailer-express-handlebars');






// Importando os dados do mailtrap em outro arquivo através da desestruturação:
const { host, port, user, pass } = require('../config/mail.json');

var transport = nodemailer.createTransport({
    host,
    port,
    auth: { user, pass },
  });





// Configurando nodemailer-express-handlebars pra gerar nomes no html ("Olá, fulano!"):
transport.use('compile', hbs({
  viewEngine: {
    defaultLayout: undefined,
    partialsDir: path.resolve('./src/resources/mail/')
  },
    viewPath: path.resolve('./src/resources/mail'),
    extName: '.html',
}))



  module.exports = transport;