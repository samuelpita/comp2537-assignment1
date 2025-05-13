//#region Imports

require("dotenv").config();

const bcrypt = require("bcrypt");
const fs = require("fs");
const MongoStore = require("connect-mongo");
const express = require("express");
const session = require("express-session");
const Joi = require("joi");
const { Collection, Document, ObjectId } = require("mongodb");

//#endregion

//#region Environment Variables

const atlasURI = process.env.MONGODB_URI;
const dbName = process.env.MONGODB_DB;

const nodeSessionSecret = process.env.NODE_SESSION_SECRET;
const mongoSessionUrl = process.env.MONGODB_URL;
const mongoSessionSecret = process.env.MONGODB_SESSION_SECRET;

//#endregion

const { database } = require("./dbConnection.js");
const path = require("path");
const userCollection = database.db(dbName).collection("users");

const app = express();
const port = 8000;
const saltRounds = 10;

const userSchema = Joi.object({
    username: Joi.string().alphanum().max(24).required(),
    password: Joi.string().max(24).required(),
});

const mongoStore = MongoStore.create({
    mongoUrl: mongoSessionUrl,
    crypto: {
        secret: mongoSessionSecret,
    },
});

//#region First-Level Functions

function readFile(path) {
    return fs.readFileSync("./" + path, "utf-8");
}

function randomElement(arr) {
    const index = Math.floor(Math.random() * arr.length);
    return arr[index];
}

//#endregion

//#region Middleware Functions

function ensureId(id) {
    if (typeof id == "string") return new ObjectId(id);
    return id;
}

function checkLoggedIn(req, res, next) {
    if (!req.session.authenticated) {
        res.send("src/login.html");
        return;
    }

    next();
}

function checkAdmin(req, res, next) {
    if (!req.session.admin) {
        res.render(readFile("src/error.html"));
        return;
    }

    next();
}

//#endregion

//#region Middleware

app.use(express.urlencoded({ extended: false }));

app.use(
    session({
        secret: nodeSessionSecret,
        store: mongoStore,
        saveUninitialized: false,
        resave: true,
    })
);

app.set("view engine", "ejs");

//#endregion

//#region Static Files

app.use("/icons", express.static("icons"));

//#endregion

//#region API

app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;

    const { error } = userSchema.extract("username").validate(username);
    if (error) {
        console.log(error);
        res.redirect("/login");
        return;
    }

    return await userCollection.findOne({ username }).then((doc) => {
        if (!doc) {
            console.log("User isn't found");
            res.redirect("/login");
        } else if (bcrypt.compareSync(password, doc.password)) {
            req.session.authenticated = true;
            req.session.username = username;
            req.session.admin = doc.admin;
            req.session.cookie.maxAge = 60 * 60 * 24 * 1000;
            if (req.session.admin) res.redirect("/admin");
            else res.redirect("/members");
        } else {
            console.log("Incorrect password!");
            res.redirect("/login");
        }
        return;
    });
});

app.post("/api/register", async (req, res) => {
    const { username, password } = req.body;

    const { error } = userSchema.validate({ username, password });
    if (error) {
        console.log(error);
        res.redirect("/register");
        return;
    }

    const hashedPassword = bcrypt.hashSync(password, saltRounds);

    const userExists = await userCollection.findOne({ username });

    if (!userExists)
        return await userCollection
            .insertOne({ username, password: hashedPassword, admin: false })
            .then((result) => {
                console.log(result.insertedId);
            })
            .finally(() => {
                res.redirect("/login");
            });
    else res.redirect("/register");
});

app.get("/api/members/randomPhoto", (req, res) => {
    if (req.session.authenticated) {
        const imagePath = path.join(
            __dirname,
            "photos",
            randomElement(["DSC_0706.jpg", "DSC_0728.jpg", "DSC_0794.jpg", "DSC_0874.jpg"])
        );
        res.sendFile(imagePath);
        return;
    }

    res.status(400).send("You don't have access!");
});

app.get("/api/members/getUsername", (req, res) => {
    if (req.session.authenticated) {
        res.send(req.session.username);
        return;
    }
    res.status(404).send("You're not logged in!");
});

app.get("/api/logout", checkLoggedIn, (req, res) => {
    req.session.destroy((err) => {
        if (!err) console.log("Successfully logged out!");
        else console.log(err);
    });

    res.redirect("/login");
});

app.get("/api/admin/grantAdmin/:userId", checkLoggedIn, checkAdmin, async (req, res) => {
    const { userId } = req.params;

    await userCollection
        .updateOne({ _id: ensureId(userId) }, { $set: { admin: true } })
        .then((result) => console.log(result))
        .catch((err) => console.log(err));

    res.redirect("/admin?username=");
});

app.get("/api/admin/revokeAdmin/:userId", checkLoggedIn, checkAdmin, async (req, res) => {
    const { userId } = req.params;

    await userCollection
        .updateOne({ _id: ensureId(userId) }, { $set: { admin: false } })
        .then((result) => console.log(`Modified ${result.modifiedCount} documents!`))
        .catch((err) => console.log(err));

    res.redirect("/admin?username=");
});

//#endregion

// Pages

app.get("/admin", checkLoggedIn, checkAdmin, async (req, res) => {
    const { username, limit } = req.query;

    if (username !== undefined) {
        let pipeline = [];

        if (username.length != 0)
            pipeline.push({
                $match: {
                    $text: {
                        $search: username,
                        $caseSensitive: false,
                    },
                },
            });

        if (limit) pipeline.push({ $limit: parseInt(limit) });

        pipeline.push({
            $addFields: {
                _id: { $toString: "$_id" },
            },
        });

        const users = await userCollection.aggregate(pipeline).toArray();

        res.render("admin", { users });
        return;
    }

    res.render("admin", { users: null });
});

app.get("/login", (req, res) => {
    if (req.session.authenticated) {
        res.redirect("/members");
        return;
    }

    res.send(readFile("src/login.html"));
});

app.get("/register", (req, res) => {
    if (req.session.authenticated) {
        res.redirect("/members");
        return;
    }

    res.send(readFile("src/register.html"));
});

app.get("/members", checkLoggedIn, (req, res) => {
    res.send(readFile("src/members.html"));
});

app.get("/", (req, res) => {
    res.send(readFile("src/index.html"));
});

app.use((req, res, next) => {
    res.status(404).send(readFile("src/error.html"));
});

app.listen(port, () => {
    console.log("Running on port " + port);
});
