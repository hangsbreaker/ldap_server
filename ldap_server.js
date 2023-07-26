var ldap = require("ldapjs");
var crypto = require("crypto");
const Pool = require("pg").Pool;
var mysql = require("mysql"),
  server = ldap.createServer(),
  root_user = "root",
  root_pass = "secret",
  ldap_port = 1389,
  basedn = "o=example",
  table_name = "users",
  rev_map = {
    // reverse field mapping, used for building sql query
    mail: "email",
    usr: "username",
    pwd: "password",
    fn: "name",
    sn: "surname",
  };
const db = new Pool({
  host: "localhost",
  user: "postgres",
  database: "postgres",
  password: "",
  port: 5432,
  ssl: false,
});

db.connect();

var sha1 = function (input) {
  return crypto.createHash("sha1").update(input).digest("hex");
};

server.bind(basedn, function (req, res, next) {
  var username = req.dn.toString(),
    password = req.credentials;
  username = username.substring(3, username.indexOf(", " + basedn));
  console.log("bind|" + username + "|" + password);
  // if user is root, just check its password right here
  if (root_user == username && root_pass == password) {
    req.is_root = 1;
    console.log("root");
    res.end();
    return next();
  } else {
    // query the database and validate the user
    // console.log("Get db");
    password = sha1(password);
    db.query(
      "select c.* from " +
        table_name +
        " c where c.username='" +
        username +
        "' and c.password='" +
        password +
        "'",
      function (err, users) {
        if (err) {
          console.log("Error fetching users", err);
          return next(new ldap.LDAPError());
        }
        if (users.length <= 0) {
          console.log("bind invalid credentials");
          return next(new ldap.InvalidCredentialsError());
        } else {
          res.end();
          return next();
        }
      }
    );
  }
});

function prepareQuery(filter) {
  var query = "";
  if (filter.type == "and" || filter.type == "or") {
    query += " ( ";
    for (let i = 0; i < filter.filters.length; i++) {
      if (query.length > 3) query += filter.type;
      query += prepareQuery(filter.filters[i]);
    }
    query += " ) ";
  } else if (filter.type == "substring") {
    query +=
      " c." + rev_map[filter.attribute] + " LIKE '" + filter.initial + "%' ";
  } else if (filter.type == "equal") {
    query += " c." + rev_map[filter.attribute] + " = '" + filter.value + "' ";
  }
  return query;
}

server.search(basedn, function (req, res, next) {
  var binddn = req.connection.ldap.bindDN.toString();
  var username = binddn.substring(3, binddn.indexOf(", " + basedn));
  console.log("search() username=" + username);
  var query = prepareQuery(req.filter).trim();
  if (query != "") {
    query = " where " + query;
  }

  // console.log(req.filter);
  console.log(`query: ${query}`);
  if (username == root_user) {
    db.query(
      "select c.* from " + table_name + " c" + query,
      function (err, users) {
        if (users != undefined) {
          users = users.rows;
          if (err) {
            console.log("Error fetching users", err);
            return next(new ldap.LDAPError());
          }
          
          var user = {
            dn: "cn=" + username + ", " + basedn,
            attributes: users,
          };
          console.log(user);
          res.send(user);
        }
        res.end();
      }
    );
  } else {
    res.end();
  }
});

server.listen(ldap_port, function () {
  console.log("LDAP server started at %s", server.url);
});
