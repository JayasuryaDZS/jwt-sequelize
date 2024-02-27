const JwtConfig = require('./jwt-config')
const JWT = require('jsonwebtoken');

let checkToken = (req, res, next) => {
    let userToken = req.headers['authorization'];

    if (userToken) {
        // Token Value
        JWT.verify(userToken, JwtConfig.secret, {
            algorithms: JwtConfig.algorithm
        }, (err, data) => {
            if (err) {
                return res.status(500).json({
                    status: 0,
                    data: err,
                    message: "Token is not valid"
                })
            } else {
                req.user = data;
                next();
            }
        })
    } else {
        res.status(500).json({
            status: 0,
            message: "Please Provide authentication token Value"
        })
    }
}

module.exports = {
    checkToken
}