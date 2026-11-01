import { fetchUser as loadUser } from "@services/users";

function getUser(req, res) {
  return loadUser(req.params.id);
}

app.get("/users/:id", getUser);
