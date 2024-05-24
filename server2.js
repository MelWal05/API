const express = require("express");
const app = express();
const mysql = require("mysql2/promise");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

async function getDBConnection() {
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "mydb",
  });
}

app.get("/", async(req, res) => {
  res.sendFile(__dirname + "/index.html");
});

app.get("/user/:id", async function (req, res) {
  try {
    const userId = req.params.id;
    const connection = await getDBConnection();
    const [rows, fields] = await connection.execute("SELECT id, username, email FROM users WHERE id = ?", [userId]);
    if (rows.length === 0) {
      res.status(404).json({ error: "User not found" });
    } else {
      res.json(rows[0]);
    }
  } catch (error) {
    console.error("Error fetching user info:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/change-user-info/:id", async function (req, res) {
  try {
    const userId = req.params.id;
    const { username, email, password } = req.body;
    const connection = await getDBConnection();
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    console.table([username, email, hashedPassword, userId])
    const [result] = await connection.execute(
      "UPDATE users SET username = ?, email = ?, password = ? WHERE id = ?",
      [username, email, hashedPassword, userId]
    );
    if (result.affectedRows === 0) {
      res.status(404).json({ error: "User not found" });
    } else {
      res.json({ message: "User updated successfully" });
    }
  } catch (error) {
    console.error("Error updating user info:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/users", async function (req, res) {
  try {
    const connection = await getDBConnection();
    const [rows, fields] = await connection.execute("SELECT id, username FROM users");
    if (rows.length === 0) {
      res.status(404).json({ error: "No users found" });
    } else {
      res.json(rows);
    }
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/create-user", async function (req, res) {
  try {
    const { username, email, password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const connection = await getDBConnection();
    await connection.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, hashedPassword]);
    res.send("User created successfully");
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/login", async function (req, res) {
  try {
    const { email, password } = req.body;
    const connection = await getDBConnection();
    const [rows, fields] = await connection.execute("SELECT id, username, password FROM users WHERE email = ?", [email]);
    if (rows.length === 0) {
      res.status(401).json({ error: "Invalid email or password" });
    } else {
      const user = rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        res.json({ id: user.id, username: user.username, email: user.email });
      } else {
        res.status(401).json({ error: "Invalid email or password" });
      }
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
