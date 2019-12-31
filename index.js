const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const hbs = require('express-handlebars');
const router = express.Router();
const bodyParser = require('body-parser');
const db = require(path.join(__dirname, 'util', 'database'));
const session = require('express-session');
const MySQLSession = require('express-mysql-session')(session);
const bcrypt = require('bcryptjs');
const csrf = require('csurf');
const crypto = require('crypto');
const { check, validationResult, body } = require('express-validator');
console.log(check);
const csrfProt = csrf();
//const mysql2=require('mysql2');
const store = new MySQLSession({}, db);
var app = express();
app.engine('hbs', hbs({ layoutsDir: 'views/layouts/', defaultLayout: 'main-layout', extname: 'hbs' }));
app.set('view engine', 'hbs');
app.set('views', 'views');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

let sess = session({ secret: 'my secret', resave: false, saveUninitialized: false, store: store });
app.use(sess);
app.use(csrfProt);
app.use((req, res, next) => {
    //console.log(req);
    res.locals.csrfToken = req.csrfToken();
    next();
});
app.get('/', (req, res, next) => {
    let log = false;
    if (req.session.isLoggedIn == undefined)
        req.session.isLoggedIn = false;
    else
        log = req.session.isLoggedIn;
    db.execute('select * from students').then(([rows, fieldData]) => {
        res.status(200).render('home', { pageHead: "Student information", isLogin: log, mainPage: true, addPage: false, adminPage: false, rows });
    }).catch(err => {
        console.log(err);
    });
});
app.get('/student/:studid', (req, res, next) => {
    let log = false;
    if (req.session.isLoggedIn == undefined)
        req.session.isLoggedIn = false;
    else
        log = req.session.isLoggedIn;
    db.execute('select * from students where id=?', [req.params.studid])
        .then(([send, fieldData]) => {
            if (send.length > 0) {
                send = send[0];
                res.status(200).render('student', { pageHead: "Student information", isLogin: log, mainPage: true, addPage: false, adminPage: false, send });
            } else
                res.status(404).render('404', { pageHead: "Page Not Found", isLogin: log, mainPage: false, addPage: false, adminPage: false });
        })
        .catch(err => {
            console.log(err);
        });
})
app.get('/add-student', (req, res, next) => {
    let log = false;
    if (req.session.isLoggedIn == undefined)
        req.session.isLoggedIn = false;
    else
        log = req.session.isLoggedIn;
    res.status(200).render('add_student', { pageHead: "Add Student", isLogin: log, mainPage: false, addPage: true, adminPage: false });
});
app.get('/admin', (req, res, next) => {
    let log = false;
    console.log(req.session);
    if (req.session.isLoggedIn == undefined)
        req.session.isLoggedIn = false;
    else
        log = req.session.isLoggedIn;
    if (!log)
        res.redirect('/login');
    else {
        db.execute('select * from students where createdby=?', [req.session.user])
            .then(([rows, fieldData]) => {
                console.table(rows);
                res.status(200).render('admin', { pageHead: "Admin", isLogin: log, mainPage: false, addPage: false, adminPage: true, rows, csid: req.csrfToken() });
            })
            .catch(err => { console.log(err) });
    }
})
app.post('/add-student', (req, res, next) => {
    console.log('Gender=>' + req.body.gender);
    db.execute('insert into students values(?,?,?,?,?,?)', [Math.floor(1000 * Math.random()), req.body.name, req.body.age, req.body.mail, req.body.gender == '0', req.body.male ? 1 : 0])
        .then(
            () => { res.redirect('/'); }
        )
        .catch(err => {
            console.log(err);
        });
});
app.post('/del-student', (req, res, next) => {
    db.execute('delete from students where id=? and createdby=?', [req.body.id, req.session.user]);
    res.redirect('/admin');
})
app.get('/login', (req, res, next) => {
    let log = false;
    if (req.session.isLoggedIn == undefined)
        req.session.isLoggedIn = false;
    else
        log = req.session.isLoggedIn;
    res.render('login', { pageHead: "Login", mainPage: false, addPage: false, isLogin: log, adminPage: false, loginPage: true });
})
app.post('/login', (req, res, next) => {
    const mail = req.body.email;
    const pass = req.body.password;
    db.execute('select * from users where email=?', [mail])
        .then((usr, fieldData) => {
            if (!usr[0][0]) {
                console.log('USer not found');
                res.redirect('/login');
            } else {
                bcrypt.compare(pass, usr[0][0].password)
                    .then(matched => {
                        if (matched) {
                            req.session.isLoggedIn = true;
                            req.session.user = usr[0][0].email;
                            req.session.save(err => {
                                console.log(err);
                                res.redirect('/');
                            });
                        } else
                            res.redirect('/login');
                    })
                    .catch(err => {
                        console.log('Error:' + err);
                        res.redirect('/login')
                    });
            }
        })
        .catch(err => { console.log(err) });
});
app.post('/logout', (req, res, next) => {
    req.session.destroy((err) => {
        console.log(err);
        res.redirect('/');
    });
});
app.get('/signup', (req, res, next) => {
    res.render('signup', { pageHead: "SignUp", mainPage: false, addPage: false, isLogin: false, adminPage: false, loginPage: true });
});
app.post('/signup', [check('userid').isEmail().withMessage('Invalid E-mail').custom((value, { req }) => {
    if (value == 'test@test.com')
        throw new Error('This e-mail is not allowed');
})], (req, res, next) => {
    const errors = validationResult(req);
    console.log(errors);
    if (!errors.isEmpty()) {
        res.status(422).render('signup', { pageHead: "SignUp", mainPage: false, addPage: false, isLogin: false, adminPage: false, loginPage: true });
        console.log(errors.array()[0].msg);
    } else {
        db.execute('select * from users where email=?', [req.body.userid])
            .then(([rows]) => {
                if (rows.length > 0) {
                    res.redirect('/login');
                } else {
                    bcrypt.hash(req.body.password, 12)
                        .then((pass) => {
                            db.execute('insert into users(email,password) values(?,?)', [req.body.userid, pass])
                                .then(() => {
                                    console.log(pass);
                                    res.redirect('/login');
                                })
                                .catch(err => { console.log('Error:' + err) });
                        })
                        .catch(err => { console.log(err) });
                }
            })
            .catch(err => { console.log(err) });
    }
});
app.get('/reset', (req, res, next) => {
    res.render('reset', { pageHead: 'Reset Password', loginPage: true });
});

function sendMail(to, from, body) {
    console.log('From: ' + from);
    console.log('To: ' + to);
    console.log('Body: ' + body);
}
app.post('/reset', (req, res, next) => {
    crypto.randomBytes(32, (err, buffer) => {
        if (err) {
            redirect('/redirect');
            console.log(err);
        }
        const token = buffer.toString('hex');
        db.execute('select * from users where email=?', [req.body.email])
            .then(rows => {
                rows = rows[0][0];
                if (!rows) {
                    console.log('Record not found');
                    res.redirect('/reset');
                } else {
                    db.execute('update users set resetToken=?,resetTokenDate=?', [token, Date.now() + 3600000])
                        .then(row => {
                            sendMail(req.body.email, 'Srajan', 'http://localhost:2000/reset/' + token);
                            res.redirect('/login');
                        })
                        .catch(err => { console.log(err) });
                }
            })
            .catch(e => { console.log(e) });
    });
})
app.get('/reset/:token', (req, res, next) => {
    db.execute('select email,resetTokenDate from users where resetToken=?', [req.params.token])
        .then(rows => {
            rows = rows[0][0];
            if (!rows) {
                console.log('Invalid Token');
                res.redirect('/login');
            } else if (rows.resetTokenDate < Date().now) {
                console.log('Token Expired');
                res.redirect('/reset');
            } else {
                res.render('new-pass', { pageHead: 'Reset Password', loginPage: true, user: rows.email, token: req.params.token });
            }
        })
        .catch(err => { console.log(errr) });
});
app.post('/new-pass', (req, res, next) => {
    db.execute('select * from users where email=? and resetToken=? and resetTokenDate>?', [req.body.user, req.body.token, Date.now()])
        .then(rows => {
            rows = rows[0][0];
            if (!rows) {
                console.log('Invalid Token');
                res.redirect('/reset');
            } else {
                bcrypt.hash(req.body.password, 12)
                    .then(pass => {
                        db.execute('update users set password=?,resetToken=null,resetTokenDate=null where email=? ', [pass, req.body.user])
                            .then(row => {
                                res.redirect('/login');
                            })
                            .catch(err => { console.log(err) });
                    })
                    .catch(err => { console.log(err) });
            }
        })
});
app.use((req, res, next) => {
    let log = false;
    if (req.session.isLoggedIn == undefined)
        req.session.isLoggedIn = false;
    else
        log = req.session.isLoggedIn;
    res.status(404).render('404', { isLogin: log, pageHead: "Page Not Found", mainPage: false, addPage: false });
});
app.listen(2000, () => { console.log('run') });