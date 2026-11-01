function getHealth(req, res) {
  res.json({ ok: true, version: 1 });
}

app.get("/health", getHealth);
