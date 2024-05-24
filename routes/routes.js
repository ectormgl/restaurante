const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db/db.js');
const router = express.Router();
const cookieParser = require('cookie-parser')
const moment = require('moment');
const secretKey = 'fen*$fne28$b2';
router.use(cookieParser());
var tkn = false
router.get("/", (req, res) => {
    if(tkn){
        res.render("index", {tkn: true});
    }else {
        
            res.render("index");
    
    }
});


router.get("/loginreq", (req, res)=>{
    res.render("login-required")
})

router.get("/views/register", (req, res) => {
    res.render("register");
});

router.get("/views/login", (req, res) => {
    res.render("login");
});

router.get("/views/interest", (req, res) => {
    res.render("ipoint");
});

router.get("/views/pontos-turistico", (req, res) => {
    res.render("pturis");
});

router.get("/views/about", (req, res) => {
    res.render("about");
});

router.post("/auth/register", (req, res) => {
    const { username, password } = req.body;
    let erros = [];

    if (!username || typeof username === undefined || username === null) {
        erros.push({ text: "Username inválido!" });
    } else if (!password || typeof password === undefined || password === null) {
        erros.push({ text: "Senha inválida" });
    } else {
        db.query('SELECT username FROM users WHERE username = ?', [username], async (error, results) => {
            if (error) {
                console.log(error);
                res.status(500).json({ message: 'Erro ao verificar usuário', success: false });
            }

            if (results.length > 0) {
                return res.render('register', { message: "Usuário já existe", success: false });
            } else {
                const hashedPassword = await bcrypt.hash(password, 8);
                db.query('INSERT INTO users SET ?', { username: username, password: hashedPassword }, (error, result) => {
                    if (error) {
                        console.log(error);
                        res.status(500).json({ message: 'Erro ao registrar usuário', success: false });
                    } else {
                        return res.render('register', { message: "Usuário registrado com sucesso", success: true });
                    }
                });
            }
        });
    }

    if (erros.length > 0) {
        res.render('register', { erros });
    }
});

router.post("/auth/login", (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], async (error, results) => {
        if (error) {
            console.log(error);
            res.status(500).json({ message: 'Erro ao verificar usuário', success: false });
        }

        if (results.length === 0 || !results) {
            return res.render('login', { message: "Usuário não encontrado", success: false });
        }

        const user = results[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            const token = jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true });
            tkn= true;
            return res.render('private', {tkn: true});
        } else {
            return res.render('login', { message: "Senha incorreta", success: false, tkn: false});
        }
    });
});

function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.render('negative');

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.status(403).send('Token inválido');
        req.user = user;
        next();
    });
}

router.get('/profile', authenticateToken, (req, res) => {
    db.query('SELECT * FROM users WHERE id = ?', [req.user.id], (err, results) => {
        if (err) return res.status(500).send('Erro no servidor');
        if (results.length === 0 || !results ) return res.status(404).send('Usuário não encontrado');

        const user = results[0];
        res.render('private', {
            id: user.id,
            username: user.username
        });
    });
});
router.post('/logout', (req, res) => {
    res.clearCookie('token'); 
    res.redirect('/'); 
    tkn = false;
});



////////////////////////////
router.get('/reserva', authenticateToken, (req, res) =>{
    res.render('reserva')
})



router.post('/reservar', authenticateToken, (req, res) => {
    const { data, qtd} = req.body;
    const userId = req.user.id; // Obtém o ID do usuário autenticado
    if (!moment(data, 'YYYY-MM-DD').isValid()) {
        return res.render('reserva', { message: "Você precisa selecionar uma data válida", success: false });
    }
    db.query('SELECT * FROM reservation WHERE datas = ? AND user_id = ?', [data, userId], (err, results) => {
        
        if (err) return  res.render('reserva', {message: "Tente novamente", success: false});

        
        //console.log(data, "==============", results)
        if (results.length > 0) {
            return res.render('reserva', {message: "Você já fez uma reserva para essa data", success: false});
        }
        if (!qtd || typeof qtd === undefined || qtd === null ) {
            return res.render('reserva', {message: "Você precisa selecionar o tipo de mesa", success: false})};
            // Horário está disponível, faça a reserva
        db.query('INSERT INTO reservation (user_id, datas, ttype) VALUES (?, ?, ?)', [userId, data, qtd], (err, result) => {
                if (err) return res.status(500).send('Erro ao realizar reserva.' + err);

                res.render('reserva', {message: "Reserva feita com sucesso", success: true});
            });
        
    });
});


////////////////////////////




router.use((req, res) => {
    res.status(404).render('notFound'); // Renderiza a página de erro 404
});
module.exports = router;
