const express = require('express')
const Sequelize = require('sequelize')
const JWT = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const JwtConfig = require('./config/jwt-config')
const JwtMiddleware = require('./config/jwt-middleware')


const app = express()

app.use(express.json()); // Used to parse JSON bodies

const PORT = 8091;

const sequelize = new Sequelize('orm_jwt', 'root', 'Mysql@123', {
    host: 'localhost',
    dialect: 'mysql'
})

sequelize.authenticate().then((data) => {
    console.log("DB Connected")
}).catch(err => {
    console.log(err)
})

//Define a Model

const User = sequelize.define('tbl_users', {
    id: {
        allowNull: false,
        primaryKey: true,
        autoIncrement: true,
        type: Sequelize.INTEGER
    },
    name: {
        type: Sequelize.STRING(50),
        allowNull: false
    },
    email: {
        type: Sequelize.STRING(50),
        allowNull: false
    },
    password: {
        type: Sequelize.STRING(150),
        allowNull: false
    },
    status: {
        type: Sequelize.INTEGER,
        defaultValue: 1
    }
}, {
    timestamps:false,
    modelName: "User"
})

User.sync()

app.post('/profile', JwtMiddleware.checkToken , (req, res) => {
    res.status(200).json({
        status: 1,
        userData: req.user,
        message: "Token value parsed"
    })
})

// Validate Token Api:
app.post("/validate", (req, res) => {
    // console.log(req.headers, 'checking the headers')
    let userToken = req.headers['authorization'];
    if (userToken) {
        // we haven token
        JWT.verify(userToken, JwtConfig.secret, (err, decoded) => {
            if (err) {
                // console.log(err)
                res.status(500).json({
                    status: 0,
                    message: "Invalid Users",
                    data: err
                })
            } else {
                res.status(200).json({
                    status: 1,
                    message: "Token is Valid",
                    data: decoded
                })
            }
        })
    } else {
        res.status(500).json({
            status: 0,
            message: "Please provide authenticated token value"
        })
    }
})

// Login user Api:
app.post('/login', (req, res) => {
    User.findOne({
        where: {
            email: req.body.email
        }
    }).then((user) => {
        if(user) {
            if (bcrypt.compareSync(req.body.password, user.password)) {
                //password match
                let userToken = JWT.sign({
                    email: user.email,
                    id: user.id,
                }, JwtConfig.secret, {
                    expiresIn: JwtConfig.expiresIn, //this will be in millisecond 10min is the expiration time
                    notBefore: JwtConfig.notBefore, // after 1min we are able to use this token value
                    audience: JwtConfig.audience,
                    issuer: JwtConfig.issuer,
                    algorithm: JwtConfig.algorithm
                })
                res.status(200).json({
                    status: 1,
                    message: 'User Logged In Successfully',
                    token: userToken
                })
            } else {
                //password not match
                res.status(500).json({
                    status: 0,
                    message: "Password didn't match"
                })
            }
        } else {
           res.status(500).json({
            status: 0,
            message: "User Not exist with email address"
           }) 
        }
    }).catch(err => {
        console.log(err)
    })
})

// Register User Api:
app.post('/user', (req, res) => {
    const { name, email, status } = req.body
    const password = bcrypt.hashSync(req.body.password, 10)

    User.findOne({
        where: {
            email: email
        }
    }).then((user) => {
        if (user) {
            res.status(200).json({
                status: 0,
                message: 'User already Found'
            })
        } else {
            User.create({
                name,
                email,
                password,
                status
            }).then((response) => {
                res.status(200).json({
                    status: 1,
                    message: "User has been Registered successfully"
                })
            }).catch(err => {
                res.status(500).json({
                    status: 0,
                    data: err
                })
            })
        }
    }).catch(err => {
        console.log(err)
    })
    
})

app.get("/", (req, res) => {
    res.status(200).json({
        status: 1,
        message: "Welcome To Home Page"
    })
})

app.listen(PORT, function() {
    console.log('Application is Running'+PORT)
})