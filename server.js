/*en caso de  hacer uso con el directorio controlador se 
debe importar como se observa en la siguiente linea, con el nombre del archivo js
que contiene la logica */
//const controller = require('./controller/nombredelcontrollador.js');
const express = require('express');
const db = require('./models');
const secret = require('./secret/config')
const app = express();
const bodyParser = require('body-parser');
const  bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});


app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }));

// API ENDPOINTS
/*se debe contar un una ruta por medio de método post para el inicio de sesión de la siguiente manera:
'/api/auth/signin'
*/
app.get('/', function(req, res) {
    console.log("Estructura base del proyecto backend");
    res.send("Estructura base del proyecto backend");
});

app.post('/api/auth/signup', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body
    if(name.trim() === '' || email.trim()  === '' || password.trim()  === '' || confirmPassword.trim()  === '') {
        return res.status(401).send('Los Datos no pueden estar vacios')
    }
    const user = await db.User.findOne({where: {email: email}})
    if(user !== null) {
        if(user.get() !== null) {
            return res.status(401).send('Este email ya está en uso')
        }
    }
    if(password !== confirmPassword) {
        return res.status(401).send('Las contraseñas deben ser iguales')
    }
    const encryptPassword = await bcrypt.hash(password, 10)
    const newUser = await db.User.build({
        name,
        email,
        password: encryptPassword
    })
    const resp = await newUser.save();
    res.status(201).json(resp)
});

app.post('/api/auth/signin', async (req, res) => {
    const { name, password } = req.body
    if(name.trim() === '' || password.trim()  === '') {
        return res.status(401).send('Los Datos no pueden estar vacios')
    }
    const user = await db.User.findOne({where: {name: name}})
    if(user === null) {
        return res.status(404).send('User Not Found.');
    }
    const resp = await bcrypt.compare(password, user.password)
    if(!resp) {
        return res.status(401).send({ auth: false, accessToken: null, reason: "Invalid Password!" });
    }
    token = jwt.sign({ id: user.id, name: user.name, email: user.email }, secret.secret, {
        expiresIn: 86400
    });
    return res.status(200).send({ accessToken: token });
});

app.get('/api/auth/validate', async (req, res) => {
    const token = req.headers.accesstoken;
    const userToken = jwt.decode(token);
    const user = await db.User.findOne({where: {email: userToken.email}, attributes: ['name', 'email']})
    if(user === null) {
        return res.status(404).send('User Not Found.');
    }
    return res.status(200).json(user)
})

const port = 3000
app.listen(port, () => {
    console.log(`Running on http://localhost:${port}`)
})

module.exports = app;