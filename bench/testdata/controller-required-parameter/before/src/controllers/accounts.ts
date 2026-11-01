function fetchAccount(id: string) {
  return id;
}

function getAccount(req, res) {
  fetchAccount(req.params.id);
}

function getStatus(req, res) {
  res.send("ok");
}

app.get("/accounts/:id", getAccount);
app.get("/status", getStatus);
