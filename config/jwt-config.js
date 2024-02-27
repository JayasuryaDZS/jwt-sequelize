module.exports = {
    secret: "jayasuryaKey",
    expiresIn: 120, // Valida for 2min
    notBefore: 2, // By default notBefore/expiresIn in seconds 
    audience: 'site-users',
    issuer: "Jayasurya",
    algorithm: "HS256"
}