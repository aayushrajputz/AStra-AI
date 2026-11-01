function loadItem(id) {
  return database.load(id);
}

function getItem(req, res) {
  loadItem(req.params.id);
}

app.get(`/items/${itemType}`, getItem);

function getHealth(req, res) {
  res.send("ok");
}

app.get("/health", getHealth);
