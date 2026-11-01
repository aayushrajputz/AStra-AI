function getStatus(req, res) {
  res.send("ok");
}

app.get("/status", getStatus);
