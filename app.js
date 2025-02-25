// app.js
const express = require('express');
const path = require('path');
const app = express();
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
//const nodemailer = require('nodemailer');
const SESSION_SECRET = 'SereneSymphonyTundraEclipseMath2025';
const ADMIN_EMAIL = 'infowisetravel@gmail.com';
const sgMail = require('@sendgrid/mail');
const dotenv = require('dotenv');
const stripe = require('stripe')("sk_test_51QwRMbFtpkraOtDeF2bVkO5DXd4v6Qui6jxN3KqVH1qTcapCS4ArrwVLE7V4KTJrFSZ7ykfD2dHx2yv2fp91PjmO00vZDojKip");
require('dotenv').config();
require('dotenv').config();
const port = 4000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const cors = require('cors');
const { default: Stripe } = require('stripe');
app.use(cors());


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
  const { destination, description, price, available_slots } = req.body;
  const query = 'INSERT INTO destinations (destination, description, price, available_slots) VALUES (?, ?, ?, ?)';
  connection.query(query, [destination, description, price, available_slots], (err, result) => {
    if (err) {
      console.log('Error adding destination:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    res.redirect('/admin-dashboard');
  });
});

// Delete destination
app.delete('/admin/delete-destination/:id', isAdmin, (req, res) => {
  const { id } = req.params;
  const query = 'DELETE FROM destinations WHERE id = ?';
  connection.query(query, [id], (err, result) => {
    if (err) {
      console.log('Error deleting destination:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    res.json({ success: true });
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

sgMail.setApiKey(process.env.SENDGRID_API_KEY);
app.post('/submit-inquiry', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(403).send('Моля, влезте в профила си, за да изпратите запитване.');
    }

    const { name, email, phone, message } = req.body;
    const userEmail = req.session.user.email;

    // Валидиране на входните данни
    if (!name || !email || !phone || !message) {
      return res.status(400).send('Всички полета са задължителни');
    }

    const msg = {
      to: process.env.ADMIN_EMAIL, 
      from: userEmail, 
      subject: 'Ново запитване от TravelWise',
      text: `
        Ново запитване от уебсайта на TravelWise:
        
        Име: ${name}
        Имейл: ${userEmail}
        Телефон: ${phone}
        
        Съобщение:
        ${message}
      `,
      html: `
        <h2>Ново запитване от уебсайта на TravelWise:</h2>
        <p><strong>Име:</strong> ${name}</p>
        <p><strong>Имейл:</strong> ${userEmail}</p>
        <p><strong>Телефон:</strong> ${phone}</p>
        <p><strong>Съобщение:</strong></p>
        <p>${message}</p>
      `
    };

    // Изпращане на имейл
    await sgMail.send(msg);
    
    // Пренасочване с успешно съобщение
    res.redirect('/contact?success=true');

  } catch (error) {
    console.error('Грешка при изпращане на имейл:', error);
    return res.redirect('/contact?error=true&message=' + encodeURIComponent(error.message));
  }
});



app.get('/admin-dashboard', isAdmin, (req, res) => {
  res.render('adminDashboard');
});

app.get('/admin/destinations', isAdmin, (req, res) => {
  const query = 'SELECT * FROM destinations';
  connection.query(query, (err, results) => {
    if (err) {
      console.log('Error fetching destinations:', err);
      return res.status(500).json({ error: 'Server error' });
    }
    res.json(results);
  });
});

app.get('/exotic', async(req, res) => {
  const [destinations] = await connection.promise().query(
               'SELECT * FROM destinations WHERE type = "exotic"'
         );
    
           res.render('types/exotic', {
               user: req.session.user,
               destinations: destinations});
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

app.post("/payment/create-checkout-session", async (req, res) => {
  try {
      const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [
              {
                  price_data: {
                      currency: "bgn", 
                      product_data: {
                          name: req.body.destinationName, // Pass the destination name dynamically
                      },
                      unit_amount: req.body.price * 100, // Stripe expects price in cents
                  },
                  quantity: 1,
              },
          ],
          mode: "payment",
          success_url:`http://localhost:4000/?payment_status=success`,
          cancel_url:`http://localhost:4000/?payment_status=cancel`,
      });

      res.json({ id: session.id });
  } catch (error) {
      console.error("Error creating Stripe session:", error);
      console.error(error);
      res.status(500).send("Internal Server Error");
  }
});


app.listen(port, () => {
  console.log(`TravelWise app listening at http://localhost:${port}`);
});