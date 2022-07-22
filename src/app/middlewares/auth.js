// Configurando o middleware para interceptar os requisitos de autenticação necessários para alcançar o "next", onde o usuário poderá passar pro próximo passo
// Importante saber que estamos configurando uma forma de conferir a validação do token para usuários que já estão logados!

const jwt = require('jsonwebtoken');
const authConfig = require('../../config/auth.json');


module.exports = (req, res, next) => {

    const authHeader = req.headers.authorization;

    // Verificar se o token foi informado:

    if(!authHeader)
        return res.status(401).send({ error: 'No token provided' })

    // Verificando se o token está no formato correto (Bearer + hash):

            // Separando em 2 partes:
            const parts = authHeader.split(' ');

            if (!parts.length === 2)
            return res.status(401).send({ error: 'Token error '})

            // Fazendo a desestruturação do token nas 2 partes:
            const [ scheme, token ] = parts;

            // Verificando se o scheme (parte 1) contém 'Bearer':
            if (!/^Bearer$/i.test(scheme))
            return res.status(401).send({ error: 'Token malformatted' })

    // Verificando se o token informado bate com o usuário que está pedindo a requisição:

    jwt.verify(token, authConfig.secret, (err, decoded) => {
        if (err) return res.status(401).send({ error: 'Token invalid' });

        req.userId = decoded.id;
        return next();
    });
}