let express = require("express");
let http = require("http");
let bodyParser = require("body-parser");
let cors = require("cors");
let WebSocket = require("ws");
let dotenv = require("dotenv");
let url = require("url");

let authRoute = require("./routes/auth.js");
let dataLoaderRoute = require("./routes/data_loader.js");
let dashboardRoute = require("./routes/dashboard.js");
let fileInteractionRoute = require("./routes/file_interaction.js");

let dbAccess = require("./db_access/db_access.js");
let dbListener = require("./db_access/db_listener.js");
let { get_user_from_jwt_token } = require("./middleware/auth.js");
let {
  on_web_socket_connect_device,
  on_web_socket_last_active,
} = require("./middleware/web_socket_device");

dotenv.config();
const PORT = process.env.PORT || 9000;
const app = express();

//enable routes
app.use(express.json());
app.use(bodyParser.json({ limit: "30mb", extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cors());

app.use("/", authRoute);
app.use("/", dataLoaderRoute);
app.use("/", dashboardRoute);
app.use("/", fileInteractionRoute);

//create server
const server = http.createServer(app);
server.listen(PORT, (err) => {
  if (err) {
    return console.log(`${err} did not connect`);
  } else {
    console.log(`Server Running on Port: http://localhost:${PORT}`);
  }
});

//establish connection with DB
dbListener.listenDB();
/* dbListener.listenDevice() */
dbAccess.connect();

//create web socket server
const wss = new WebSocket.Server({
  server: server,
  verifyClient: function (info, done) {
    console.log("Web socket setup");
    let query = url.parse(info.req.url, true).query;

    if (query.token) {
      const current_user = get_user_from_jwt_token(`Bearer ${query.token}`);
      if (!current_user) {
        return done(false, 403, "Not valid token");
      } else {
        done(true);
      }
    } else if (query.mac) {
      on_web_socket_connect_device(query.mac, query.ip, query.version)
        .then((res) => {
          done(res.status);
        })
        .catch((reason) => {
          done(false);
        });
    } else {
      done(false);
    }
  },
});

wss.on("connection", (socket) => {
  socket.on("message", (msg) => {
    const [client, data] = msg.split("-");
    if (client === "device") {
      on_web_socket_last_active(data);
    }
  });
  console.log(
    `New connection made, current number of clients : ${wss.clients.size}`
  );
  socket.on("close", () => {
    console.log(
      `One connection terminated, current number of clients : ${wss.clients.size}`
    );
  });
});

module.exports = wss;
