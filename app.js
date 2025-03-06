// app.js
const express = require('express');
const path = require('path');
const app = express();
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const nodemailer = require('nodemailer');
const SESSION_SECRET = 'SereneSymphonyTundraEclipseMath2025';
const EMAIL_USER = 'safetterziev8@gmail.com';
const EMAIL_PASS = '30102006';
const ADMIN_EMAIL = 'safetterziev8@gmail.com';
const port = 4000;
app.use(express.json());

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } 
}));

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'travelwisedb'
});

connection.connect(err => {
  if (err) {
      console.error('Database connection failed: ' + err.stack);
      return;
  }
  console.log('Connected to MySQL');
});

const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/signin');
  }
};

const isAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.role === 'admin') {
    next();
  } else {
    res.status(403).send('Access denied');
  }
};

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

app.get('/register', (req, res) => {
  res.render('register');
});
app.post('/register', (req, res) => {
  const { first_name, last_name, email, password } = req.body;

  // Hash the password before saving
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.log('Error hashing password:', err);
      return res.status(500).send('Server error');
    }
  
    // Insert user data into the database
    const query = 'INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)';
    connection.query(query, [first_name, last_name, email, hashedPassword], (err, result) => {
      if (err) {
        console.log('Error inserting user into database:', err);
        return res.status(500).send('Error saving user');
      }
      console.log('User registered:', result);
      res.redirect('/signin'); // Redirect to the sign-in page after successful registration
    });
  })});

app.get('/signin', (req, res) => {
  res.render('signin'); 
});

app.get('/signin', (req, res) => {
  res.render('signin'); 
});

app.post('/signin', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  connection.query(query, [email], (err, results) => {
    if (err) {
      console.log('Error fetching user:', err);
      return res.status(500).send('Server error');
    }

    if (results.length === 0) {
      return res.status(400).send('User not found');
    }

    const user = results[0];
    // Compare password with hashed password stored in the database
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.log('Error comparing password:', err);
        return res.status(500).send('Server error');
      }

      if (!isMatch) {
        return res.status(400).send('Invalid credentials');
      }

      req.session.user = {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        role: user.role // Ensure role is set here
      };

      console.log('User signed in:', user);
      res.redirect('/');
    });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log('Error destroying session:', err);
      return res.status(500).send('Error logging out');
    }
    res.redirect('/');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log('Error destroying session:', err);
      return res.status(500).send('Error logging out');
    }
    res.redirect('/');
  });
});

app.get('/profile', isAuthenticated, (req, res) => {
  const userId = req.session.user.id;
  console.log(`Fetching profile for user ID: ${userId}`);

  // Fetch user's reservations
  const bookingsQuery = 'SELECT * FROM bookings WHERE user_id = ?';
  connection.query(bookingsQuery, [userId], (bookingsErr, bookings) => {
    if (bookingsErr) {
      console.error('Error fetching bookings:', bookingsErr);
      return res.status(500).json({ error: 'Error loading profile', details: bookingsErr.message });
    }

    console.log(`Found ${bookings.length} bookings for user ID: ${userId}`);

    // Fetch user details
    const userQuery = 'SELECT first_name, last_name, email, role FROM users WHERE id = ?';
    connection.query(userQuery, [userId], (userErr, userResults) => {
      if (userErr) {
        console.error('Error fetching user details:', userErr);
        return res.status(500).json({ error: 'Error loading profile', details: userErr.message });
      }

      if (userResults.length === 0) {
        console.error(`No user found with ID: ${userId}`);
        return res.status(404).json({ error: 'User not found' });
      }

      const userDetails = userResults[0];
      console.log(`Rendering profile for user: ${userDetails.first_name} ${userDetails.last_name}, Role: ${userDetails.role}`);

      res.render('profile', {
        user: {
          id: userId,
          firstName: userDetails.first_name,
          lastName: userDetails.last_name,
          email: userDetails.email,
          role: userDetails.role // Ensure role is passed to the template
        },
        bookings: bookings
      });
    });
  });
});

app.use((err, req, res, next) => {
  console.error('Error stack:', err.stack);
  console.error('Error message:', err.message);
  res.status(500).json({
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// Add new destination
app.post('/admin/add-destination', isAdmin, (req, res) => {
  const { name, country, description, image_url, type, price, transport, duration, start_date } = req.body;
  const numericPrice = parseFloat(price);
    
    if (isNaN(numericPrice)) {
        return res.status(400).json({ error: 'Invalid price' });
    }
  connection.query(
      'INSERT INTO destinations (name, country, description, image_url, type, price, transport, duration, start_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [name, country, description, image_url, type, price, transport, duration, start_date],
      (error, result) => {
          if (error) {
              console.error('Error adding destination:', error);
              return res.status(500).json({ error: 'Internal server error' });
          }
          res.redirect('/admin');
      }
  );
});

// Delete destination
app.delete('/admin/delete-destination/:id', isAdmin, (req, res) => {
  const { id } = req.params;
  connection.query('DELETE FROM destinations WHERE id = ?', [id], (error, result) => {
      if (error) {
          console.error('Error deleting destination:', error);
          return res.status(500).json({ success: false, error: 'Internal server error' });
      }
      if (result.affectedRows > 0) {
          res.json({ success: true });
      } else {
          res.status(404).json({ success: false, error: 'Destination not found' });
      }
  });
});

app.get('/aboutus', (req, res) => {
  res.render('aboutus');
});

app.get('/contact', (req, res) => {
  res.render('contact', { 
    user: req.session.user,
    query: req.query 
  });
});

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});

app.post('/submit-inquiry', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(403).send('Моля, влезте в профила си, за да изпратите запитване.');
    }

    const { name, email, phone, message } = req.body;

    // Validate input
    if (!name || !email || !phone || !message) {
      return res.status(400).send('Всички полета са задължителни');
    }

    const mailOptions = {
      from: `"${name}" <${email}>`,
      to: ADMIN_EMAIL,
      subject: 'Ново запитване от TravelWise',
      text: `
        Ново запитване от уебсайта на TravelWise:
        
        Име: ${name}
        Имейл: ${email}
        Телефон: ${phone}
        
        Съобщение:
        ${message}
      `,
      html: `
        <h2>Ново запитване от уебсайта на TravelWise:</h2>
        <p><strong>Име:</strong> ${name}</p>
        <p><strong>Имейл:</strong> ${email}</p>
        <p><strong>Телефон:</strong> ${phone}</p>
        <p><strong>Съобщение:</strong></p>
        <p>${message}</p>
      `
    };

    // Send email
    await transporter.sendMail(mailOptions);
    
    // Redirect with success message
    res.redirect('/contact?success=true');

  } catch (error) {
    console.error('Грешка при изпращане на имейл:', error);
    res.status(500).send('Грешка при изпращане на запитването. Моля, опитайте отново по-късно.');
  }
});

app.get('/exotic', async(req, res) => {
  const [destinations] = await connection.promise().query(
               'SELECT * FROM destinations WHERE type = "exotic"'
         );
    
           res.render('types/exotic', {
               user: req.session.user,
               destinations: destinations});
});

app.get('/admin-dashboard', isAdmin, (req, res) => {
  res.render('adminDashboard');
});

app.get('/admin/destinations', isAdmin, (req, res) => {
  connection.query('SELECT *, CAST(price AS DECIMAL(10, 2)) AS price FROM destinations', (error, results) => {
      if (error) {
          console.error('Error fetching destinations:', error);
          return res.status(500).json({ error: 'Internal server error' });
      }
      res.json(results);
  });
})

app.get('/admin/users', isAdmin, (req, res) => {
  connection.query('SELECT id, first_name, last_name, email, role FROM users WHERE role = "customer"', (error, results) => {
      if (error) {
          console.error('Error fetching users:', error);
          return res.status(500).json({ error: 'Internal server error' });
      }
      console.log('Fetched users:', results);
      res.json(results);
  });
});

//Delete user
app.delete('/admin/delete-user/:id', isAdmin, (req, res) => {
  const { id } = req.params;
  connection.query('DELETE FROM users WHERE id = ?', [id], (error, result) => {
      if (error) {
          console.error('Error deleting user:', error);
          return res.status(500).json({ success: false, error: 'Internal server error' });
      }
      if (result.affectedRows > 0) {
          res.json({ success: true });
      } else {
          res.status(404).json({ success: false, error: 'User not found' });
      }
  });
});

app.get('/destination/:id', async(req, res) => {
  const [destination] = await connection.promise().query(
      'SELECT * FROM destinations WHERE id = ?',
      [req.params.id]
  );

  if (!destination[0]) {
      return res.status(404).render('404', {
          user: req.session.user,
          message: 'Дестинацията не беше намерена'
      });
  }

  res.render('destination', {
      user: req.session.user,
      destination: destination[0]
  });

});


app.listen(port, () => {
  console.log(`TravelWise app listening at http://localhost:${port}`);
});