// Fixture INTENCIONALMENTE vulneravel para testes do VION. Nao use em producao.
const express = require('express')
const mysql = require('mysql')
const crypto = require('crypto')
const app = express()
const db = mysql.createConnection({ host: 'localhost', user: 'root' })

const password = "Sup3rS3cretPassw0rd2024"

app.get('/api/orders/:id', async (req, res) => {
  const order = await db.query('SELECT * FROM orders WHERE id = ' + req.params.id)
  res.json(order)
})

app.get('/search', (req, res) => {
  res.send('<h1>' + req.query.q + '</h1>')
})

app.post('/login', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
  res.json({ hash })
})

app.listen(3000)
