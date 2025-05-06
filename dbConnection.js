require("dotenv").config();

const { MongoClient } = require("mongodb");
const atlasURI = process.env.ATLAS_URI;
const database = new MongoClient(atlasURI);

module.exports = { database };
