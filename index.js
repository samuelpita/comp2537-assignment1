const express = require("express");
const fs = require("fs");

const app = express();
const port = 8000;

app.use("/public", express.static("/public"));
app.use("/src", express.static("/src"));

app.listen(port, () => {
    console.log("Running on port " + port);
});
