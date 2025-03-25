// app.js
const express = require('express');
const path = require('path');
const app = express();
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const nodemailer = require('nodemailer');
const sgMail = require('@sendgrid/mail');
const SESSION_SECRET = 'SereneSymphonyTundraEclipseMath2025';
const EMAIL_USER = 'safetterziev8@gmail.com';
const EMAIL_PASS = '30102006';
const ADMIN_EMAIL = 'safetterziev8@gmail.com';
const stripe  = require('stripe')('sk_test_51QwRMbFtpkraOtDeF2bVkO5DXd4v6Qui6jxN3KqVH1qTcapCS4ArrwVLE7V4KTJrFSZ7ykfD2dHx2yv2fp91PjmO00vZDojKip');
const port = 4000;
app.use(express.json());
require('dotenv').config();
// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

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

app.get('/search', (req, res) => {
  const { country, transport, start_date, type } = req.query;
  
  // Build the query dynamically based on provided parameters
  let query = 'SELECT * FROM destinations WHERE 1=1';
  const params = [];
  
  if (country && country !== '') {
      query += ' AND country = ?';
      params.push(country);
  }
  
  if (transport && transport !== '') {
      query += ' AND transport = ?';
      params.push(transport);
  }
  
  if (start_date && start_date !== '') {
      query += ' AND start_date >= ?';
      params.push(start_date);
  }
  
  if (type && type !== '') {
      query += ' AND type = ?';
      params.push(type);
  }
  
  // Execute the query
  connection.query(query, params, (error, results) => {
      if (error) {
          console.error('Error searching destinations:', error);
          return res.status(500).send('Internal server error');
      }
      
      // Render the search results page
      res.render('search-results', {
          destinations: results,
          searchParams: { country, transport, start_date, type },
          user: req.session.user
      });
  });
});

// Home route with dynamic dropdown data
app.get('/', (req, res) => {
  // Use Promise.all to run both queries in parallel
  Promise.all([
      // Query for countries
      new Promise((resolve, reject) => {
          pool.query('SELECT DISTINCT country FROM destinations WHERE country IS NOT NULL AND country != "" ORDER BY country', (error, results) => {
              if (error) {
                  console.error('Error fetching countries:', error);
                  resolve([]);
              } else {
                  console.log(`Found ${results.length} countries`);
                  resolve(results);
              }
          });
      }),
      // Query for transports
      new Promise((resolve, reject) => {
          pool.query('SELECT DISTINCT transport FROM destinations WHERE transport IS NOT NULL AND transport != "" ORDER BY transport', (error, results) => {
              if (error) {
                  console.error('Error fetching transports:', error);
                  resolve([]);
              } else {
                  console.log(`Found ${results.length} transports`);
                  resolve(results);
              }
          });
      })
  ])
  .then(([countries, transports]) => {
      // Log the data for debugging
      console.log('Countries:', JSON.stringify(countries));
      console.log('Transports:', JSON.stringify(transports));
      
      // Render the page with the data
      res.render('index', {
          user: req.session.user,
          countries: countries,
          transports: transports
      });
  })
  .catch(error => {
      console.error('Error in Promise.all:', error);
      res.render('index', {
          user: req.session.user,
          countries: [],
          transports: []
      });
  });
});
// API route for client-side fallback
app.get('/api/dropdown-data', (req, res) => {
  Promise.all([
      new Promise((resolve, reject) => {
          connection.query('SELECT DISTINCT country FROM destinations WHERE country IS NOT NULL AND country != "" ORDER BY country', (error, results) => {
              if (error) {
                  console.error('Error fetching countries:', error);
                  resolve([]);
              } else {
                  resolve(results);
              }
          });
      }),
      new Promise((resolve, reject) => {
          connection.query('SELECT DISTINCT transport FROM destinations WHERE transport IS NOT NULL AND transport != "" ORDER BY transport', (error, results) => {
              if (error) {
                  console.error('Error fetching transports:', error);
                  resolve([]);
              } else {
                  resolve(results);
              }
          });
      })
  ])
  .then(([countries, transports]) => {
      res.json({
          countries: countries,
          transports: transports
      });
  })
  .catch(error => {
      console.error('Error in Promise.all:', error);
      res.status(500).json({ error: error.message });
  });
});

// Add this to your server-side code (app.js or routes file)
app.get('/api/top-destination', async (req, res) => {
  try {
      // Query to find the destination with the most confirmed bookings
      const query = `
          SELECT d.*, COUNT(b.id) as booking_count
          FROM destinations d
          JOIN bookings b ON d.id = b.destination_id
          WHERE b.status = 'confirmed'
          GROUP BY d.id
          ORDER BY booking_count DESC
          LIMIT 1
      `;
      
      connection.query(query, (error, results) => {
          if (error) {
              console.error('Error fetching top destination:', error);
              return res.status(500).json({ success: false, message: 'Database error' });
          }
          
          if (results.length > 0) {
              return res.json({ success: true, destination: results[0] });
          } else {
              return res.json({ success: false, message: 'No destinations found' });
          }
      });
  } catch (error) {
      console.error('Error in top destination route:', error);
      res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/register', (req, res) => {
  res.render('register', {error: null, success: null});
});
app.post('/register', async (req, res) => {
  try {
    const { first_name, last_name, email, password } = req.body;

    // Validate input
    if (!first_name || !last_name || !email || !password) {
      return res.render('register', { 
        error: 'Моля, попълнете всички полета',
        success: null
      });
    }
    
    // Check if password is too short
    if (password.length < 6) {
      return res.render('register', { 
        error: 'Паролата трябва да бъде поне 6 символа',
        success: null
      });
    }

    // Check if email already exists
    const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
    connection.query(checkEmailQuery, [email], async (err, results) => {
      if (err) {
        console.log('Error checking email:', err);
        return res.render('register', { 
          error: 'Възникна грешка при проверката на имейла',
          success: null
        });
      }

      if (results.length > 0) {
        return res.render('register', { 
          error: 'Този имейл вече е регистриран',
          success: null
        });
      }

      // Hash the password
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          console.log('Error hashing password:', err);
          return res.render('register', { 
            error: 'Възникна грешка при обработката на паролата',
            success: null
          });
        }
      
        // Insert user data into the database
        const query = 'INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)';
        connection.query(query, [first_name, last_name, email, hashedPassword], (err, result) => {
          if (err) {
            console.log('Error inserting user into database:', err);
            return res.render('register', { 
              error: 'Възникна грешка при регистрацията',
              success: null
            });
          }
          
          console.log('User registered:', result);
          
          // Show success message on the registration page
          // The JavaScript will handle the redirect after a delay
          return res.render('register', {
            error: null,
            success: 'Регистрацията е успешна! Ще бъдете пренасочени към страницата за вход.'
          });
        });
      });
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.render('register', { 
      error: 'Възникна неочаквана грешка. Моля, опитайте отново.',
      success: null
    });
  }
});

  app.get('/signin', (req, res) => {
    // If user is already logged in, redirect to home
    if (req.session.user) {
      return res.redirect('/');
    }
    
    res.render('signin', { 
      error: null,
      user: null
    });
  });

app.post('/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.render('signin', { 
        error: 'Моля, въведете имейл и парола',
        user: null
      });
    }

    // Convert callback to Promise for cleaner code
    const query = 'SELECT * FROM users WHERE email = ?';
    const [results] = await new Promise((resolve, reject) => {
      connection.query(query, [email], (err, results) => {
        if (err) reject(err);
        else resolve([results]);
      });
    });

    if (results.length === 0) {
      return res.render('signin', { 
        error: 'Потребителят не е намерен',
        user: null
      });
    }

    const user = results[0];
    
    // Convert bcrypt.compare to Promise
    const isMatch = await new Promise((resolve, reject) => {
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) reject(err);
        else resolve(isMatch);
      });
    });

    if (!isMatch) {
      return res.render('signin', { 
        error: 'Невалидни данни за вход',
        user: null
      });
    }

    // Set user session
    req.session.user = {
      id: user.id,
      firstName: user.first_name, // Using the correct column name from your database
      lastName: user.last_name,   // Using the correct column name from your database
      email: user.email,
      role: user.role
    };

    console.log('User signed in:', user);
    res.redirect('/');
    
  } catch (error) {
    console.error('Login error:', error);
    res.render('signin', { 
      error: 'Възникна грешка при входа. Моля, опитайте отново.',
      user: null
    });
  }
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

  // Get any messages or errors from query parameters
  const message = req.query.message;
  const error = req.query.error;

  // Improved query to fetch bookings with destination details
  const bookingsQuery = `
    SELECT 
      b.id, 
      b.booking_date, 
      b.status, 
      d.id AS destination_id,
      d.name AS destination_name, 
      d.description,
      d.country, 
      d.image_url, 
      d.price, 
      d.transport,
      d.duration,
      d.start_date,
      d.type
    FROM bookings b
    LEFT JOIN destinations d ON b.destination_id = d.id
    WHERE b.user_id = ?
    ORDER BY b.booking_date DESC
  `;

  connection.query(bookingsQuery, [userId], (bookingsErr, bookings) => {
    if (bookingsErr) {
      console.error('Error fetching bookings:', bookingsErr);
      return res.status(500).json({ error: 'Error loading profile', details: bookingsErr.message });
    }

    console.log(`Found ${bookings.length} bookings for user ID: ${userId}`);

    // Format the booking data for display
    const formattedBookings = bookings.map(booking => {
      return {
        ...booking,
        booking_date_formatted: new Date(booking.booking_date).toLocaleDateString('bg-BG'),
        start_date_formatted: booking.start_date ? new Date(booking.start_date).toLocaleDateString('bg-BG') : 'Не е посочена',
        price_formatted: booking.price ? (typeof booking.price === 'number' ? booking.price.toFixed(2) : parseFloat(booking.price).toFixed(2)) : '0.00',
        status_text: booking.status === 'confirmed' ? 'Потвърдена' : 
                     booking.status === 'cancelled' ? 'Отказана' : 'В процес',
        status_color: booking.status === 'confirmed' ? 'green' : 
                      booking.status === 'cancelled' ? 'red' : 'yellow'
      };
    });

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
          role: userDetails.role
        },
        bookings: formattedBookings,
        message: message,
        error: error
      });
    });
  });
});

// Add a route to handle booking cancellations
app.post('/cancel-booking', isAuthenticated, (req, res) => {
  const bookingId = req.body.bookingId;
  const userId = req.session.user.id;
  
  console.log(`Attempting to cancel booking ID: ${bookingId} for user ID: ${userId}`);
  
  // Update the booking status to 'cancelled'
  connection.query(
    'UPDATE bookings SET status = ? WHERE id = ? AND user_id = ?',
    ['cancelled', bookingId, userId],
    (error, results) => {
      if (error) {
        console.error('Error cancelling booking:', error);
        return res.redirect('/profile?error=cancel-failed');
      }
      
      if (results.affectedRows === 0) {
        console.log('No booking was updated - might not exist or belong to this user');
        return res.redirect('/profile?error=booking-not-found');
      }
      
      console.log(`Successfully cancelled booking ID: ${bookingId}`);
      // Redirect back to profile with success message
      res.redirect('/profile?message=booking-cancelled');
    }
  );
});

// Add this route to handle password change
app.post('/change-password', (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
      return res.redirect('/signin');
  }
  
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.session.user.id;
  
  // Validate input
  if (!currentPassword || !newPassword || !confirmPassword) {
      return res.render('profile', {
          user: req.session.user,
          bookings: [],
          passwordMessage: 'Всички полета са задължителни',
          passwordError: true
      });
  }
  
  // Check if new passwords match
  if (newPassword !== confirmPassword) {
      return res.render('profile', {
          user: req.session.user,
          bookings: [],
          passwordMessage: 'Новите пароли не съвпадат',
          passwordError: true
      });
  }
  
  // Minimum password length
  if (newPassword.length < 6) {
      return res.render('profile', {
          user: req.session.user,
          bookings: [],
          passwordMessage: 'Новата парола трябва да бъде поне 6 символа',
          passwordError: true
      });
  }
  
  // Get the user's current password from the database
  connection.query('SELECT password FROM users WHERE id = ?', [userId], (error, results) => {
      if (error) {
          console.error('Error fetching user password:', error);
          return res.render('profile', {
              user: req.session.user,
              bookings: [],
              passwordMessage: 'Възникна грешка. Моля, опитайте отново по-късно.',
              passwordError: true
          });
      }
      
      if (results.length === 0) {
          return res.render('profile', {
              user: req.session.user,
              bookings: [],
              passwordMessage: 'Потребителят не е намерен',
              passwordError: true
          });
      }
      
      const hashedPassword = results[0].password;
      
      // Compare the current password with the stored hash
      bcrypt.compare(currentPassword, hashedPassword, (err, isMatch) => {
          if (err) {
              console.error('Error comparing passwords:', err);
              return res.render('profile', {
                  user: req.session.user,
                  bookings: [],
                  passwordMessage: 'Възникна грешка. Моля, опитайте отново по-късно.',
                  passwordError: true
              });
          }
          
          if (!isMatch) {
              return res.render('profile', {
                  user: req.session.user,
                  bookings: [],
                  passwordMessage: 'Текущата парола е неправилна',
                  passwordError: true
              });
          }
          
          // Hash the new password
          bcrypt.hash(newPassword, 10, (err, hashedNewPassword) => {
              if (err) {
                  console.error('Error hashing new password:', err);
                  return res.render('profile', {
                      user: req.session.user,
                      bookings: [],
                      passwordMessage: 'Възникна грешка. Моля, опитайте отново по-късно.',
                      passwordError: true
                  });
              }
              
              // Update the password in the database
              connection.query('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId], (error) => {
                  if (error) {
                      console.error('Error updating password:', error);
                      return res.render('profile', {
                          user: req.session.user,
                          bookings: [],
                          passwordMessage: 'Възникна грешка при обновяването на паролата',
                          passwordError: true
                      });
                  }
                  
                  // Password updated successfully
                  return res.render('profile', {
                      user: req.session.user,
                      bookings: [],
                      passwordMessage: 'Паролата е променена успешно',
                      passwordError: false
                  });
              });
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
          // Redirect with success message as query parameter
          res.redirect('/admin-dashboard?success=add');
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
          res.json({ 
              success: true, 
              message: 'Дестинацията е премахната успешно!' 
          });
      } else {
          res.status(404).json({ success: false, error: 'Destination not found' });
      }
  });
});

app.get('/admin/bookings', isAdmin, (req, res) => {
  const query = `
      SELECT 
          bookings.id, 
          users.first_name AS customer_name, 
          users.email AS customer_email, 
          destinations.name AS destination, 
          bookings.booking_date, 
          bookings.status
      FROM bookings
      JOIN users ON bookings.user_id = users.id
      JOIN destinations ON bookings.destination_id = destinations.id
  `;

  connection.query(query, (error, results) => {
      if (error) {
          console.error('Error fetching bookings:', error);
          return res.status(500).json({ error: 'Internal server error' });
      }
      res.json(results);
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

app.post('/submit-inquiry', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(403).send('Моля, влезте в профила си, за да изпратите запитване.');
    }

    const { name, email, phone, message } = req.body;
    const user = req.session.user;

    // Validate input
    if (!name || !email || !phone || !message) {
      return res.status(400).send('Всички полета са задължителни');
    }

    // Send email to admin
    await sendEmail(
      process.env.ADMIN_EMAIL || 'infowisetravel@gmail.com',
      'Ново запитване от TravelWise',
      `
        Ново запитване от уебсайта на TravelWise:
        
        Име: ${name}
        Имейл: ${email}
        Телефон: ${phone}
        
        Съобщение:
        ${message}
      `,
      `
        <h2>Ново запитване от уебсайта на TravelWise:</h2>
        <p><strong>Име:</strong> ${name}</p>
        <p><strong>Имейл:</strong> ${email}</p>
        <p><strong>Телефон:</strong> ${phone}</p>
        <p><strong>Съобщение:</strong></p>
        <p>${message}</p>
      `,
      email // Pass the user's email as replyTo
    );
    
    // Redirect with success message
    res.redirect('/contact?success=true');

  } catch (error) {
    console.error('Грешка при изпращане на имейл:', error);
    res.redirect('/contact?error=true');
  }
});

// Updated sendEmail function with replyTo parameter
async function sendEmail(to, subject, text, html, replyTo = null) {
  try {
    const msg = {
      to: to,
      from: 'infowisetravel@gmail.com', // Your verified sender
      subject: subject,
      text: text,
      html: html,
    };
    
    // Add replyTo if provided
    if (replyTo) {
      msg.replyTo = replyTo;
    }
    
    const response = await sgMail.send(msg);
    console.log('Email sent successfully');
    return response;
  } catch (error) {
    console.error('Error sending email with SendGrid:', error);
    if (error.response) {
      console.error(error.response.body);
    }
    throw error;
  }
}

app.get('/exotic', async(req, res) => {
  const [destinations] = await connection.promise().query(
         'SELECT * FROM destinations WHERE type = "exotic"'
         );
    
  res.render('types/exotic', {
     user: req.session.user,
    destinations: destinations});
});

app.get('/excursions', async (req, res) => {
  const [destinations] = await connection.promise().query(
    'SELECT * FROM destinations WHERE type = "excursion"'
);

res.render('types/excursions', {
    user: req.session.user,
    destinations: destinations});
});

app.get('/oneDay', async (req, res) => {
  const [destinations] = await connection.promise().query(
    'SELECT * FROM destinations WHERE type = "oneDay"'
);

res.render('types/oneDay', {
    user: req.session.user,
    destinations: destinations});
});

app.get('/admin-dashboard', isAdmin, (req, res) => {
  // Get success message from query parameters
  const successType = req.query.success;
  let successMessage = null;
  
  if (successType === 'add') {
      successMessage = 'Дестинацията е добавена успешно!';
  }
  
  // Fetch destinations
  connection.query('SELECT * FROM destinations', (error, destinations) => {
      if (error) {
          console.error('Error fetching destinations:', error);
          return res.status(500).send('Internal Server Error');
      }
      
      // Fetch users
      connection.query('SELECT * FROM users', (error, users) => {
          if (error) {
              console.error('Error fetching users:', error);
              return res.status(500).send('Internal Server Error');
          }
          
          res.render('adminDashboard', { 
              destinations, 
              users,
              successMessage // Pass success message to template
          });
      });
  });
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

// Delete user
// Delete user with cascade
app.delete('/admin/delete-user/:id', isAdmin, (req, res) => {
  const { id } = req.params;
  
  // Start a transaction to ensure data integrity
  connection.beginTransaction(err => {
    if (err) {
      console.error('Error starting transaction:', err);
      return res.status(500).json({ success: false, error: 'Internal server error' });
    }
    
    // First, check if the user exists
    connection.query('SELECT * FROM users WHERE id = ?', [id], (error, results) => {
      if (error) {
        return connection.rollback(() => {
          console.error('Error checking user:', error);
          res.status(500).json({ success: false, error: 'Internal server error' });
        });
      }
      
      if (results.length === 0) {
        return connection.rollback(() => {
          res.status(404).json({ success: false, error: 'User not found' });
        });
      }
      
      // Delete related records if needed (example: delete user's bookings)
      // connection.query('DELETE FROM bookings WHERE user_id = ?', [id], (error) => { ... });
      
      // Finally, delete the user
      connection.query('DELETE FROM users WHERE id = ?', [id], (error, result) => {
        if (error) {
          return connection.rollback(() => {
            console.error('Error deleting user:', error);
            res.status(500).json({ success: false, error: 'Internal server error', details: error.message });
          });
        }
        
        connection.commit(err => {
          if (err) {
            return connection.rollback(() => {
              console.error('Error committing transaction:', err);
              res.status(500).json({ success: false, error: 'Internal server error' });
            });
          }
          
          res.json({ 
            success: true, 
            message: 'Потребителят е премахнат успешно!' 
          });
        });
      });
    });
  });
});

app.get('/admin/destination/:id', isAdmin, (req, res) => {
  const { id } = req.params;

  connection.query('SELECT * FROM destinations WHERE id = ?', [id], (error, results) => {
      if (error) {
          console.error('Error fetching destination:', error);
          return res.status(500).json({ error: 'Internal server error' });
      }

      if (results.length === 0) {
          return res.status(404).json({ error: 'Destination not found' });
      }

      res.json(results[0]); // Връща само първата дестинация
  });
});

// Update destination
app.put('/admin/update-destination/:id', isAdmin, (req, res) => {
  const { id } = req.params;
  const { name, country, description, image_url, type, price, transport, duration, start_date } = req.body;
  
  console.log('Updating destination:', id);
  console.log('Request body:', req.body);
  
  // Validate the data
  if (!name || !country || !description || !image_url || !type || !price || !transport || !duration || !start_date) {
      console.log('Missing required fields');
      return res.status(400).json({ 
          success: false, 
          message: 'Всички полета са задължителни' 
      });
  }
  
  // Update the destination in the database
  connection.query(
      `UPDATE destinations 
       SET name = ?, country = ?, description = ?, image_url = ?, 
           type = ?, price = ?, transport = ?, duration = ?, start_date = ? 
       WHERE id = ?`,
      [name, country, description, image_url, type, price, transport, duration, start_date, id],
      (error, results) => {
          if (error) {
              console.error('Error updating destination:', error);
              return res.status(500).json({ 
                  success: false, 
                  message: 'Грешка при обновяване на дестинацията',
                  error: error.message
              });
          }
          
          if (results.affectedRows === 0) {
              console.log('No rows affected');
              return res.status(404).json({ 
                  success: false, 
                  message: 'Дестинацията не е намерена' 
              });
          }
          
          console.log('Destination updated successfully');
          res.json({ 
              success: true, 
              message: 'Дестинацията е обновена успешно' 
          });
      }
  );
});

app.get('/destination/:id', async(req, res)=> {
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

app.post('/payment/create-checkout-session', async (req, res) => {
  try {
      const { destinationName, price, destinationId} = req.body;
      const userId = req.session.user ? req.session.user.id : null;
      
      // Log the received data
      console.log('Creating checkout session for:', destinationName, 'Price:', price);
      
      // Convert price to cents (Stripe requires amounts in cents)
      const priceInCents = Math.round(parseFloat(price) * 100);
      
      // Create a checkout session
      const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          line_items: [
              {
                  price_data: {
                      currency: 'bgn',
                      product_data: {
                          name: destinationName,
                          description: 'Резервация за пътуване',
                      },
                      unit_amount: priceInCents,
                  },
                  quantity: 1,
              },
          ],
          mode: 'payment',
          success_url: `${req.protocol}://${req.get('host')}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${req.protocol}://${req.get('host')}/payment-cancel`,
          metadata: {
            destinationId: destinationId.toString(),
            userId: userId ? userId.toString() : null
        }
      });
      
      // Log the created session ID
      console.log('Created session:', session.id);
      
      // Return the session ID to the client
      res.json({ id: session.id });
  } catch (error) {
      console.error('Error creating checkout session:', error);
      res.status(500).json({ error: error.message });
  }
});

// Add success and cancel routes
app.get('/payment-success', async (req, res) => {
  const sessionId = req.query.session_id;
  // Get destination_id and user_id from query parameters as fallback
  const destination_id = req.query.destination_id;
  const user_id = req.query.user_id || (req.session.user ? req.session.user.id : null);
  
  console.log('Payment success with params:', {
      sessionId,
      destination_id,
      user_id
  });
  
  try {
      // Use await with the Stripe API call since it's asynchronous
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      console.log('Retrieved session:', {
          id: session.id,
          metadata: session.metadata
      });
      
      // Get the destination_id and user_id from the metadata or query parameters
      // Note: In your create-checkout-session, you're using destinationId and userId (camelCase)
      // but your database columns are destination_id and user_id (snake_case)
      const final_destination_id = (session.metadata && session.metadata.destinationId) || destination_id;
      const final_user_id = (session.metadata && session.metadata.userId) || user_id;
      
      console.log('Final IDs for booking:', {
          destination_id: final_destination_id,
          user_id: final_user_id
      });
      
      // If we have both user_id and destination_id, create a booking
      if (final_user_id && final_destination_id) {
          // Use pool.query instead of connection.query for consistency
          connection.query(
              'INSERT INTO bookings (user_id, destination_id, status) VALUES (?, ?, ?)',
              [final_user_id, final_destination_id, 'confirmed'],
              (error, results) => {
                  if (error) {
                      console.error('Error creating booking:', error);
                      return res.render('payment-success', {
                          sessionId: sessionId,
                          user: req.session.user,
                          bookingCreated: false,
                          error: error.message
                      });
                  }
                  
                  console.log('Booking created successfully:', results.insertId);
                  
                  // Render the success page
                  res.render('payment-success', {
                      sessionId: sessionId,
                      user: req.session.user,
                      bookingCreated: true,
                      bookingId: results.insertId
                  });
              }
          );
      } else {
          // If we don't have user_id or destination_id, just render the success page
          console.warn('Missing user_id or destination_id for booking');
          res.render('payment-success', {
              sessionId: sessionId,
              user: req.session.user,
              bookingCreated: false,
              error: 'Missing user_id or destination_id for booking'
          });
      }
  } catch (error) {
      console.error('Error retrieving session or creating booking:', error);
      
      // If we have destination_id and user_id from query parameters, try to create booking anyway
      if (destination_id && user_id) {
          console.log('Attempting to create booking from query parameters');
          
          connection.query(
              'INSERT INTO bookings (user_id, destination_id, status) VALUES (?, ?, ?)',
              [user_id, destination_id, 'confirmed'],
              (dbError, results) => {
                  if (dbError) {
                      console.error('Error creating booking from query parameters:', dbError);
                      return res.render('payment-success', {
                          sessionId: sessionId,
                          user: req.session.user,
                          bookingCreated: false,
                          error: `Error retrieving session and creating booking: ${error.message}, DB Error: ${dbError.message}`
                      });
                  }
                  
                  console.log('Booking created successfully from query parameters:', results.insertId);
                  
                  // Render the success page
                  res.render('payment-success', {
                      sessionId: sessionId,
                      user: req.session.user,
                      bookingCreated: true,
                      bookingId: results.insertId,
                      note: 'Created from query parameters due to session retrieval error'
                  });
              }
          );
      } else {
          res.render('payment-success', {
              sessionId: sessionId,
              user: req.session.user,
              bookingCreated: false,
              error: `Error retrieving session: ${error.message}`
          });
      }
  }
});

app.get('/payment-cancel', (req, res) => {
  // Render a cancel page
  res.render('payment-cancel', {
      user: req.session.user
  });
});

app.post('/cancel-booking', (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
      return res.redirect('/signin');
  }
  
  const bookingId = req.body.bookingId;
  const userId = req.session.user.id;
  
  // Update the booking status to 'cancelled'
  connection.query(
      'UPDATE bookings SET status = ? WHERE id = ? AND user_id = ?',
      ['cancelled', bookingId, userId],
      (error, results) => {
          if (error) {
              console.error('Error cancelling booking:', error);
              return res.redirect('/profile?error=cancel-failed');
          }
          
          if (results.affectedRows === 0) {
              // No booking was updated, might be because it doesn't exist or doesn't belong to this user
              return res.redirect('/profile?error=booking-not-found');
          }
          
          // Redirect back to profile with success message
          res.redirect('/profile?message=booking-cancelled');
      }
  );
});

app.listen(port, () => {
  console.log(`TravelWise app listening at http://localhost:${port}`);
});