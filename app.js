const express = require("express");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const path = require("path");
const bcrypt = require("bcrypt");

const app = express();

const serviceAct = require("./Key.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAct),
});

const db = admin.firestore();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.redirect("/signup");
});

app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

app.post("/signup", async (req, res) => {
  const { username, email, phone, password, confirm_password } = req.body;

  if (password !== confirm_password) {
    return res.render("signup", { error: "Passwords do not match" });
  }

  if (!/^\d{10}$/.test(phone)) {
    return res.render("signup", { error: "Phone number must be exactly 10 digits" });
  }

  try {
    const exist = await db
      .collection("users")
      .where("email", "==", email)
      .get();
    if (!exist.empty) {
      return res.render("signup", { error: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.collection("users").add({
      username,
      email,
      phone,
      password: hashedPassword,
    });

    res.redirect("/login");
  } catch (err) {
    res.status(500).send("Error: " + err.message);
  }
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const exist = await db
      .collection("users")
      .where("email", "==", email)
      .get();
    if (exist.empty) {
      return res.render("login", { error: "Invalid email or password" });
    }
    const user = exist.docs[0].data();
    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      res.render("dashboard", { username: user.username });
    } else {
      return res.render("login", { error: "Invalid email or password" });
    }
  } catch (err) {
    res.status(500).send("Error: " + err.message);
  }
});

app.get("/dashboard", (req, res) => {
  res.render("dashboard", { username: "User" });
});

app.get("/logout", (req, res) => {
  res.redirect("/login");
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
