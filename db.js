const { Pool } = require("pg");

const pool = new Pool({
  user: "postgres",
  password: "pern123",
  host: "localhost",
  port: 5432,
  database: "jwttutorial_db",
});

module.exports = pool;
