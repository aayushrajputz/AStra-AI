function getHealth(req, res) {
  res.json({ ok: true });
}

app.get("/health", getHealth);
