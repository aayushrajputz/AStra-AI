function requireAuth(req, res, next) {
  next();
}

function showAdmin(req, res) {
  res.send("admin");
}

function showStatus(req, res) {
  res.send("ok");
}

app.get("/admin", requireAuth, showAdmin);
app.get("/status", showStatus);
