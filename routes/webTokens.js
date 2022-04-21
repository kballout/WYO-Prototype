const jwt = require('jsonwebtoken')

function authenticateToken (req, res, next) {
    const authHeader = req.headers['auth']
    const accessToken = authHeader && authHeader.split(' ')[1]
    if(!accessToken) return res.status(401).send('Access Denied')
    
    jwt.verify(accessToken, process.env.ACCESS_TOKEN, (err, user) => {
        if(err) return res.status('403').send('Access Denied')
        req.user = user
        next()
    })
    
    
}

function generateAccessToken(user){
    return jwt.sign(user, process.env.ACCESS_TOKEN, {expiresIn: '1m'})
}

module.exports.generateAccessToken = generateAccessToken
module.exports.authenticateToken = authenticateToken